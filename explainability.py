import os
import json
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import shap

def create_directories():
    """Crea los directorios necesarios para guardar gráficos si no existen."""
    os.makedirs('plots', exist_ok=True)

def load_artifacts():
    """
    Carga el modelo pre-entrenado, el conjunto de prueba con las características exactas
    y el codificador de etiquetas.
    """
    # Cargar las características seleccionadas
    features_path = os.path.join(os.getcwd(), 'data', 'processed', 'selected_features.json')
    with open(features_path, 'r') as f:
        selected_features = json.load(f)
        
    # Cargar el dataset de pruebas procesado
    test_path = os.path.join(os.getcwd(), 'data', 'processed', 'test_processed.csv')
    test_df = pd.read_csv(test_path)
    X_test = test_df[selected_features]
    y_test_real = test_df['label']
    
    # Cargar los artefactos generados en train.py
    model = joblib.load('models/lightgbm_ids_model.pkl')
    le = joblib.load('models/label_encoder.pkl')
    
    return model, X_test, y_test_real, le

def initialize_shap(model, X_test):
    """
    Inicializa SHAP TreeExplainer y calcula los shap_values.
    
    JUSTIFICACIÓN TÉCNICA (TreeSHAP vs KernelSHAP):
    Para el desarrollo de este prototipo IDS orientado al paper, TreeSHAP (usado en TreeExplainer) 
    es matemáticamente superior por tres razones fundamentales:
    1. Exactitud Teórica: TreeSHAP calcula los valores de Shapley exactos aprovechando la topología y 
       divisiones internas de los árboles de LightGBM. KernelSHAP, en cambio, utiliza un modelo lineal 
       sustituto local para aproximar esos valores, induciendo un error de muestreo.
    2. Eficiencia Computacional: TreeSHAP reduce la complejidad asintótica de O(TL2^M) a polinomial O(TLD^2) 
       (donde T=n_árboles, L=hojas y D=profundidad máxima). Esto lo hace órdenes de magnitud más rápido, 
       siendo viable para analizar masivos volúmenes de tráfico de red en ciberseguridad.
    3. Estabilidad Táctica: Al ser puramente analítico y determinista, TreeSHAP asegura que la misma muestra 
       de red siempre genere exactamente la misma explicación, factor crítico para la auditabilidad forense del IDS.
    """
    print("[*] Inicializando TreeExplainer (algoritmo óptimo para LightGBM)...")
    explainer = shap.TreeExplainer(model)
    
    print("[*] Calculando SHAP values sobre el conjunto de pruebas. Esto tomará unos segundos...")
    # Calcula los valores SHAP
    shap_values_raw = explainer.shap_values(X_test)
    
    # SHAP > 0.40 puede devolver un array 3D para multiclass (n_samples, n_features, n_classes).
    # Convertimos a una lista de arrays 2D para mantener compatibilidad con los gráficos.
    if isinstance(shap_values_raw, np.ndarray) and len(shap_values_raw.shape) == 3:
        shap_values = [shap_values_raw[:, :, i] for i in range(shap_values_raw.shape[2])]
    else:
        shap_values = shap_values_raw
        
    return explainer, shap_values

def generate_global_explanations(shap_values, X_test, class_names):
    """
    Genera gráficos de explicabilidad global.
    Permite evaluar la Dimensión 1 (D1) de la Variable Independiente: Tasa de cobertura táctica.
    """
    # 1. SHAP Summary Plot (Bar)
    # Este gráfico de barras apiladas permite operacionalizar la "Tasa de cobertura táctica" 
    # visualizando el impacto absoluto promedio de las 30 características en la toma de decisión 
    # de las 5 diferentes categorías de ataques (DoS, Probe, R2L, U2R) y tráfico Normal.
    # Ayuda a sustentar en el paper qué variables dominan de manera táctica la cobertura del modelo.
    print("[*] Generando SHAP Summary Plot (Bar) - Tasa de cobertura táctica...")
    plt.figure(figsize=(12, 8))
    shap.summary_plot(shap_values, X_test, plot_type="bar", class_names=class_names, show=False)
    plt.title("Tasa de Cobertura Táctica - Impacto Medio Absoluto de las Variables por Clase")
    plt.tight_layout()
    plt.savefig('plots/shap_global_bar.png', dpi=300)
    plt.close()
    
    # 2. SHAP Beeswarm Plot (para la clase 'normal' o la que se desea analizar)
    # Seleccionaremos la primera clase del LabelEncoder (frecuentemente 'dos' o 'normal') 
    # para analizar la direccionalidad (valores altos vs bajos).
    # Este gráfico revela si un valor elevado en métricas como 'src_bytes' inclina 
    # la probabilidad hacia una intrusión o la aleja.
    target_idx = 0 
    target_name = class_names[target_idx]
    
    print(f"[*] Generando SHAP Beeswarm Plot para la clase: {target_name}...")
    plt.figure(figsize=(10, 8))
    # Accedemos a los shap_values específicos de la clase target_idx
    shap.summary_plot(shap_values[target_idx], X_test, show=False)
    plt.title(f"SHAP Beeswarm Plot - Impacto y Dirección para la clase: {target_name}")
    plt.tight_layout()
    plt.savefig('plots/shap_global_beeswarm.png', dpi=300)
    plt.close()

def find_critical_failure(model, X_test, y_test_real, le):
    """
    Módulo de Diagnóstico de Fallos: 
    Busca programáticamente un error de clasificación (Falso Positivo o Falso Negativo) 
    para analizar por qué falló el modelo (especialmente ante ataques Zero-Day o ambigüedad U2R).
    """
    ATTACK_MAP = {
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

    y_pred_encoded = model.predict(X_test)
    y_pred_real = le.inverse_transform(y_pred_encoded)
    
    # 1. Buscar un Falso Positivo crítico (normal clasificado como U2R o ataque)
    for i in range(len(X_test)):
        real = y_test_real.iloc[i]
        pred = y_pred_real[i]
        real_macro = ATTACK_MAP.get(real, 'unknown')
        pred_macro = ATTACK_MAP.get(pred, 'unknown')
        if real_macro == 'normal' and pred_macro != 'normal':
            return i, real, pred
            
    # 2. Buscar un Falso Negativo crítico (Ataque clasificado como normal)
    for i in range(len(X_test)):
        real = y_test_real.iloc[i]
        pred = y_pred_real[i]
        real_macro = ATTACK_MAP.get(real, 'unknown')
        pred_macro = ATTACK_MAP.get(pred, 'unknown')
        if real_macro != 'normal' and pred_macro == 'normal':
            return i, real, pred
            
    # Último recurso (fallback) si no hay errores (poco probable en KDDTest+)
    return 0, y_test_real.iloc[0], y_pred_real[0]

def generate_local_explanations(explainer, shap_values, X_test, sample_idx, sample_class_real, sample_class_pred, le):
    """
    Genera un SHAP Waterfall Plot para un caso de estudio individual de fallo, 
    utilizando los nombres reales de las características.
    Esto representa el escenario donde un analista SOC diagnostica un error.
    """
    print(f"[*] Generando SHAP Waterfall Plot local para Error (Índice: {sample_idx}, Real: {sample_class_real}, Predicción: {sample_class_pred})...")
    
    # Explicamos por qué el modelo tomó la decisión (usamos la clase predicha)
    class_idx = le.transform([sample_class_pred])[0]
    
    # Extraer la muestra y sus características reales
    sample_series = X_test.iloc[sample_idx]
    
    # Preparar el objeto shap.Explanation
    explanation = shap.Explanation(
        values=shap_values[class_idx][sample_idx], 
        base_values=explainer.expected_value[class_idx] if isinstance(explainer.expected_value, list) else explainer.expected_value, 
        data=sample_series.values, 
        feature_names=sample_series.index.tolist()
    )
    
    plt.figure(figsize=(10, 7))
    shap.waterfall_plot(explanation, show=False)
    plt.title(f"Diagnóstico de Fallo - SHAP Waterfall\nReal: {sample_class_real} | Predicho: {sample_class_pred}")
    plt.tight_layout()
    plt.savefig('plots/shap_local_failure.png', dpi=300)
    plt.close()

def main():
    # 0. Asegurar estructura de carpetas
    create_directories()
    
    # 1. Cargar el modelo LightGBM, datos procesados y encoder
    print("[*] 1. Cargando artefactos desde el disco...")
    model, X_test, y_test_real, le = load_artifacts()
    class_names = list(le.classes_)
    
    # 2. Configurar el motor XAI (TreeSHAP)
    print("[*] 2. Configurando Algoritmo SHAP...")
    explainer, shap_values = initialize_shap(model, X_test)
    
    # 3. Explicabilidad Global (Tasa de cobertura táctica)
    print("[*] 3. Procesando gráficos globales (Summary y Beeswarm)...")
    generate_global_explanations(shap_values, X_test, class_names)
    
    # 4. Explicabilidad Local (Diagnóstico de Fallos)
    print("[*] 4. Buscando y explicando un caso crítico de error (FP/FN)...")
    sample_idx, sample_class_real, sample_class_pred = find_critical_failure(model, X_test, y_test_real, le)
    generate_local_explanations(explainer, shap_values, X_test, sample_idx, sample_class_real, sample_class_pred, le)
    
    print("[+] Ejecución completada. Los gráficos de explicabilidad han sido guardados en 'plots/'.")

if __name__ == '__main__':
    main()
