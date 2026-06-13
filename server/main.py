from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Dict, Any
import json
import os
import joblib
import pandas as pd
import numpy as np
import shap
import matplotlib.pyplot as plt
import io
import base64
from contextlib import asynccontextmanager

# Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Global ML objects
ml_models = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load ML artifacts on startup
    print("[*] Loading ML models and SHAP Explainer...")
    model_path = os.path.join(PROJECT_ROOT, "models", "lightgbm_ids_model.pkl")
    le_path = os.path.join(PROJECT_ROOT, "models", "label_encoder.pkl")
    preprocessor_path = os.path.join(PROJECT_ROOT, "models", "preprocessor.pkl")
    features_path = os.path.join(PROJECT_ROOT, "data", "processed", "selected_features.json")
    
    if os.path.exists(model_path) and os.path.exists(le_path) and os.path.exists(features_path) and os.path.exists(preprocessor_path):
        ml_models["model"] = joblib.load(model_path)
        ml_models["le"] = joblib.load(le_path)
        ml_models["preprocessor"] = joblib.load(preprocessor_path)
        with open(features_path, 'r') as f:
            ml_models["selected_features"] = json.load(f)
            
        print("[*] Initializing TreeExplainer...")
        ml_models["explainer"] = shap.TreeExplainer(ml_models["model"])
        print("[+] ML Backend Ready.")
    else:
        print("[!] Warning: ML artifacts not found. Inference will not work.")
        
    yield
    # Clean up
    ml_models.clear()

app = FastAPI(title="HunterIDS Server", version="2.0", lifespan=lifespan)

os.makedirs(os.path.join(BASE_DIR, "static"), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

alerts_db: List[Dict[str, Any]] = []

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        for alert in alerts_db:
            await websocket.send_json(alert)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"Error sending message: {e}")

manager = ConnectionManager()

class AlertInput(BaseModel):
    node_ip: str
    timestamp: str
    features: Dict[str, Any]

@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html")

def generate_shap_waterfall(explanation, sample_class):
    """Generates a SHAP waterfall plot and returns it as a Base64 string."""
    plt.switch_backend('Agg')
    plt.figure(figsize=(9, 6))
    
    # We must plot the waterfall
    shap.waterfall_plot(explanation, show=False)
    plt.title(f"XAI Trace: {sample_class}", color='#00f0ff', pad=20, fontdict={'family':'monospace'})
    
    fig = plt.gcf()
    fig.patch.set_facecolor('#0a1118')
    ax = plt.gca()
    ax.set_facecolor('#0a1118')
    ax.tick_params(colors='#8a9fac')
    ax.xaxis.label.set_color('#8a9fac')
    ax.yaxis.label.set_color('#8a9fac')
    
    # Fix spine colors
    for spine in ax.spines.values():
        spine.set_color('#1a2b3c')
        
    plt.tight_layout()
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', facecolor=fig.get_facecolor(), edgecolor='none', dpi=120)
    plt.close(fig)
    buf.seek(0)
    
    img_str = base64.b64encode(buf.read()).decode('utf-8')
    return f"data:image/png;base64,{img_str}"

@app.post("/api/v1/alerts")
async def receive_alert(alert_input: AlertInput):
    if "model" not in ml_models:
        return {"status": "error", "message": "ML models not loaded"}
        
    model = ml_models["model"]
    le = ml_models["le"]
    explainer = ml_models["explainer"]
    selected_features = ml_models["selected_features"]
    preprocessor = ml_models["preprocessor"]
    
    # 1. Procesamiento Dinámico de características crudas (41 features)
    features_dict = alert_input.features
    df_raw = pd.DataFrame([features_dict])
    
    # Transformar usando el pipeline guardado (MinMax, RobustScaler, OHE)
    X_prep = preprocessor.transform(df_raw)
    
    # Reconstruir nombres de columnas tal como se hizo en entrenamiento
    nominales = ['protocol_type', 'service', 'flag']
    numericas = [col for col in df_raw.columns if col not in nominales]
    cat_feature_names = preprocessor.named_transformers_['cat'].get_feature_names_out(nominales)
    all_feature_names = numericas + list(cat_feature_names)
    
    df_full = pd.DataFrame(X_prep, columns=all_feature_names)
    
    # Filtrar solo las 100 features que el modelo necesita
    for feat in selected_features:
        if feat not in df_full.columns:
            df_full[feat] = 0.0
            
    df = df_full[selected_features]
    
    pred_encoded = model.predict(df)[0]
    pred_class = le.inverse_transform([pred_encoded])[0]
    
    probas = model.predict_proba(df)[0]
    confidence = float(probas[pred_encoded])
    
    # Explicabilidad (SHAP)
    shap_values_raw = explainer.shap_values(df)
    
    if isinstance(shap_values_raw, list):
        shap_vals_for_class = shap_values_raw[pred_encoded][0]
        expected_val = explainer.expected_value[pred_encoded]
    elif len(shap_values_raw.shape) == 3:
        shap_vals_for_class = shap_values_raw[0, :, pred_encoded]
        expected_val = explainer.expected_value[pred_encoded]
    else:
        shap_vals_for_class = shap_values_raw[0]
        expected_val = explainer.expected_value
        if isinstance(expected_val, (list, np.ndarray)):
            expected_val = expected_val[pred_encoded]
            
    feature_impacts = {feat: float(val) for feat, val in zip(selected_features, shap_vals_for_class)}
    top_features = dict(sorted(feature_impacts.items(), key=lambda item: abs(item[1]), reverse=True)[:3])
    
    explanation = shap.Explanation(
        values=shap_vals_for_class, 
        base_values=expected_val, 
        data=df.iloc[0].values, 
        feature_names=selected_features
    )
    
    plot_b64 = generate_shap_waterfall(explanation, pred_class)
    
    alert_dict = {
        "id": os.urandom(4).hex(),
        "node_ip": alert_input.node_ip,
        "timestamp": alert_input.timestamp,
        "prediction": str(pred_class),
        "confidence": confidence,
        "features": top_features,
        "shap_plot_b64": plot_b64
    }
    
    alerts_db.append(alert_dict)
    if len(alerts_db) > 100:
        alerts_db.pop(0)
        
    await manager.broadcast(alert_dict)
    
    return {"status": "success", "prediction": str(pred_class)}
