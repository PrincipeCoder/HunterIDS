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

# Constantes de Mapeo Semántico
ATTACK_MAP_MACRO = {
    'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos', 'smurf': 'dos', 
    'teardrop': 'dos', 'apache2': 'dos', 'mailbomb': 'dos', 'processtable': 'dos', 'udpstorm': 'dos',
    'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 'satan': 'probe', 
    'mscan': 'probe', 'saint': 'probe',
    'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'multihop': 'r2l', 
    'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l', 'warezmaster': 'r2l',
    'sendmail': 'r2l', 'named': 'r2l', 'snmpgetattack': 'r2l', 'snmpguess': 'r2l', 
    'xlock': 'r2l', 'xsnoop': 'r2l', 'worm': 'r2l',
    'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r', 
    'httptunnel': 'u2r', 'ps': 'u2r', 'sqlattack': 'u2r', 'xterm': 'u2r',
    'normal': 'normal'
}

MITRE_MAPPING = {
    'src_bytes': 'T1041 Exfiltration Over C2 Channel',
    'dst_bytes': 'T1041 Exfiltration Over C2 Channel',
    'count': 'T1046 Network Service Scanning',
    'srv_count': 'T1046 Network Service Scanning',
    'flag_S0': 'T1046 Network Service Scanning (SYN Stealth)',
    'flag_REJ': 'T1046 Network Service Scanning',
    'wrong_fragment': 'T1498 Network Denial of Service',
    'dst_host_same_src_port_rate': 'T1046 Network Service Scanning',
    'dst_host_srv_count': 'T1046 Network Service Scanning',
    'num_failed_logins': 'T1110 Brute Force',
    'num_compromised': 'T1068 Exploitation for Privilege Escalation',
    'root_shell': 'T1068 Exploitation for Privilege Escalation'
}

def generate_tactical_explanation(top_features: dict, pred_class: str) -> dict:
    """Generates NLP explanation and MITRE mapping based on top SHAP features."""
    macro_class = ATTACK_MAP_MACRO.get(pred_class, 'unknown')
    
    if macro_class == 'normal':
        return {
            "nlp": "Tráfico con comportamiento estadísticamente normal según línea base.",
            "mitre": ["N/A"]
        }
        
    feat_names = list(top_features.keys())
    
    # NLP Engine
    nlp_parts = []
    if any('bytes' in f for f in feat_names):
        nlp_parts.append("anomalía en volumen de transferencia de datos (posible exfiltración o flood)")
    if any('count' in f or 'rate' in f for f in feat_names):
        nlp_parts.append("alta tasa de conexiones simultáneas (posible escaneo o DoS)")
    if any('flag' in f for f in feat_names):
        nlp_parts.append("manipulación inusual de flags TCP")
    if any('failed_logins' in f or 'compromised' in f or 'root' in f for f in feat_names):
        nlp_parts.append("indicios de compromiso de credenciales o escalado de privilegios")
        
    if not nlp_parts:
        nlp_text = f"Anomalía detectada principalmente por el comportamiento inusual en: {', '.join(feat_names)}."
    else:
        nlp_text = "El sistema detectó " + " y ".join(nlp_parts) + "."
        
    # MITRE Mapping
    mitre_tactics = []
    for f in feat_names:
        for k, v in MITRE_MAPPING.items():
            if k in f:
                mitre_tactics.append(v)
                break
                
    mitre_tactics = list(set(mitre_tactics))
    if not mitre_tactics:
        if macro_class == 'dos': mitre_tactics = ["T1498 Network Denial of Service"]
        elif macro_class == 'probe': mitre_tactics = ["T1046 Network Service Scanning"]
        elif macro_class == 'u2r': mitre_tactics = ["T1068 Exploitation for Privilege Escalation"]
        elif macro_class == 'r2l': mitre_tactics = ["T1110 Brute Force"]
        else: mitre_tactics = ["T1190 Exploit Public-Facing Application (Inferred)"]
        
    return {
        "nlp": nlp_text.capitalize(),
        "mitre": mitre_tactics
    }

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

@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

class AlertInput(BaseModel):
    node_ip: str
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
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
    
    tactical_info = generate_tactical_explanation(top_features, pred_class)
    macro_class = ATTACK_MAP_MACRO.get(pred_class, 'unknown')
    
    alert_dict = {
        "id": os.urandom(4).hex(),
        "node_ip": alert_input.node_ip,
        "src_ip": alert_input.src_ip,
        "dst_ip": alert_input.dst_ip,
        "timestamp": alert_input.timestamp,
        "prediction": str(pred_class),
        "macro_class": macro_class,
        "confidence": confidence,
        "features": top_features,
        "shap_plot_b64": plot_b64,
        "tactical_info": tactical_info
    }
    
    alerts_db.append(alert_dict)
    if len(alerts_db) > 100:
        alerts_db.pop(0)
        
    await manager.broadcast(alert_dict)
    
    return {"status": "success", "prediction": str(pred_class)}

@app.post("/api/v1/alerts/batch")
async def receive_alerts_batch(alerts: List[AlertInput]):
    if "model" not in ml_models:
        return {"status": "error", "message": "ML models not loaded"}
        
    if not alerts:
        return {"status": "success", "results": []}
        
    model = ml_models["model"]
    le = ml_models["le"]
    explainer = ml_models["explainer"]
    selected_features = ml_models["selected_features"]
    preprocessor = ml_models["preprocessor"]
    
    # Extraer todas las features de la lista de alertas
    features_list = [a.features for a in alerts]
    df_raw = pd.DataFrame(features_list)
    
    # Transformar usando el pipeline guardado
    X_prep = preprocessor.transform(df_raw)
    
    # Reconstruir nombres de columnas
    nominales = ['protocol_type', 'service', 'flag']
    numericas = [col for col in df_raw.columns if col not in nominales]
    cat_feature_names = preprocessor.named_transformers_['cat'].get_feature_names_out(nominales)
    all_feature_names = numericas + list(cat_feature_names)
    
    df_full = pd.DataFrame(X_prep, columns=all_feature_names)
    
    for feat in selected_features:
        if feat not in df_full.columns:
            df_full[feat] = 0.0
            
    df = df_full[selected_features]
    
    preds_encoded = model.predict(df)
    preds_classes = le.inverse_transform(preds_encoded)
    probas = model.predict_proba(df)
    
    # Calcular SHAP y notificar por WebSocket solo si es amenaza (o una muestra de normal)
    results = []
    for idx, (pred_encoded, pred_class, proba, alert_input) in enumerate(zip(preds_encoded, preds_classes, probas, alerts)):
        confidence = float(proba[pred_encoded])
        
        is_threat = (str(pred_class).lower() not in ['normal', '0'])
        
        # Para evitar saturar el dashboard, solo enviamos SHAP por WS si es amenaza o 1 normal por lote
        if is_threat or idx == 0:
            df_row = df.iloc[[idx]]
            shap_values_raw = explainer.shap_values(df_row)
            
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
                data=df_row.iloc[0].values, 
                feature_names=selected_features
            )
            
            plot_b64 = generate_shap_waterfall(explanation, pred_class)
            
            tactical_info = generate_tactical_explanation(top_features, pred_class)
            macro_class = ATTACK_MAP_MACRO.get(pred_class, 'unknown')
            
            alert_dict = {
                "id": os.urandom(4).hex(),
                "node_ip": alert_input.node_ip,
                "src_ip": alert_input.src_ip,
                "dst_ip": alert_input.dst_ip,
                "timestamp": alert_input.timestamp,
                "prediction": str(pred_class),
                "macro_class": macro_class,
                "confidence": confidence,
                "features": top_features,
                "shap_plot_b64": plot_b64,
                "tactical_info": tactical_info
            }
            
            alerts_db.append(alert_dict)
            if len(alerts_db) > 100:
                alerts_db.pop(0)
                
            await manager.broadcast(alert_dict)
        
        results.append({
            "src_ip": alert_input.src_ip,
            "dst_ip": alert_input.dst_ip,
            "prediction": str(pred_class)
        })
        
    return {"status": "success", "results": results}
