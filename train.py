import os
import json
import time
import joblib
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from lightgbm import LGBMClassifier

def create_directories():
    """Crea los directorios necesarios para guardar modelos y gráficos si no existen."""
    os.makedirs('models', exist_ok=True)
    os.makedirs('plots', exist_ok=True)

def load_and_filter_data():
    """
    Carga los datos preprocesados y filtra las características seleccionadas.
    Retorna X_train, y_train, X_test, y_test.
    """
    # Cargar las características seleccionadas del archivo JSON
    # Esto garantiza el uso exacto del espacio de características dinámico del preprocesamiento
    features_path = os.path.join(os.getcwd(), 'data', 'processed', 'selected_features.json')
    with open(features_path, 'r') as f:
        selected_features = json.load(f)
    
    # Cargar los datasets preprocesados (rutas relativas)
    train_path = os.path.join(os.getcwd(), 'data', 'processed', 'train_processed.csv')
    test_path = os.path.join(os.getcwd(), 'data', 'processed', 'test_processed.csv')
    
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    
    # Separar características (X) y etiquetas (y)
    X_train = train_df[selected_features]
    y_train = train_df['label']
    
    X_test = test_df[selected_features]
    y_test = test_df['label']
    
    return X_train, y_train, X_test, y_test

def encode_labels(y_train):
    """
    Aplica LabelEncoder a las etiquetas.
    Guarda el encoder para mapeo inverso en el módulo XAI.
    """
    le = LabelEncoder()
    # Ajustar y transformar en el conjunto de entrenamiento
    y_train_encoded = le.fit_transform(y_train)
    
    # Guardar el codificador de etiquetas
    joblib.dump(le, 'models/label_encoder.pkl')
    
    return y_train_encoded, le

def train_model(X_train, y_train, le):
    """
    Configura y entrena el clasificador LightGBM.
    Registra el tiempo de entrenamiento para evaluar la Dimensión: Eficiencia Computacional (D2).
    """
    ATTACK_MAP_U2R = ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'httptunnel', 'ps', 'sqlattack', 'xterm']
    
    from sklearn.utils.class_weight import compute_class_weight
    
    # Calculamos primero los pesos balanceados matemáticamente correctos
    balanced_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
    class_weights = dict(zip(np.unique(y_train), balanced_weights))
    
    # Modificación Manual (Cierre de Brecha de Precisión)
    # Penalizaciones personalizadas para reducir Falsos Positivos/Negativos en U2R y R2L
    for i, cls_name in enumerate(le.classes_):
        if cls_name in ATTACK_MAP_U2R:
            # Multiplicador para dar más peso y evitar que se ignore o se confunda (FN/FP)
            class_weights[i] = class_weights[i] * 2.5
        elif cls_name == 'normal':
            # Mantenemos el peso base balanceado para normal, pero lo reforzamos ligeramente 
            # para que el modelo sea más escéptico a predecir U2R erróneamente (reduciendo FP en U2R)
            class_weights[i] = class_weights[i] * 1.5

    # Instanciamos LGBMClassifier con la arquitectura avanzada requerida:
    model = LGBMClassifier(
        objective='multiclass',  # Función de pérdida para clasificación multiclase
        random_state=42,         # Semilla para reproducibilidad
        class_weight=class_weights, # Pesos personalizados
        n_estimators=300,        # Mayor número de iteraciones para un aprendizaje más profundo del error residual.
        learning_rate=0.03,      # Reducción de la tasa para lograr convergencia más suave y exacta en pérdida multiclase.
        num_leaves=63,           # Ajustado a 63: Un balance entre 127 (sobreajuste) y 31 (subajuste)
        max_depth=8,             # Límite de profundidad en 8 para permitir aprender firmas complejas
        min_child_samples=15,    # Regularización relajada ligeramente para permitir hojas más pequeñas en U2R
        subsample=0.8,           # Robustez estadística al muestrear aleatoriamente filas (bagging en cada árbol).
        colsample_bytree=0.8,    # Robustez mediante submuestreo de columnas en cada árbol.
        n_jobs=-1                # Todos los núcleos para máxima eficiencia
    )
    
    # Registrar el tiempo exacto de inicio antes del entrenamiento
    start_time = time.time()
    
    # Entrenar el modelo
    model.fit(X_train, y_train)
    
    # Registrar el tiempo exacto de fin
    end_time = time.time()
    
    # Calcular el tiempo total (Eficiencia computacional del entrenamiento - D2)
    training_time_seconds = end_time - start_time
    
    # Persistir el modelo entrenado en disco
    joblib.dump(model, 'models/lightgbm_ids_model.pkl')
    
    return model, training_time_seconds

def evaluate_model(model, X_test, y_test, le):
    """
    Evalúa el modelo para dimensionar la Efectividad de identificación (D1)
    y la Agilidad de respuesta (D2) en inferencia.
    Genera la Matriz de Confusión.
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

    # Registrar tiempo de inicio de inferencia
    start_inference = time.time()
    
    # Realizar predicciones sobre TODO el conjunto de prueba
    y_pred = model.predict(X_test)
    
    # Registrar tiempo de fin de inferencia
    end_inference = time.time()
    
    # Calcular Agilidad de respuesta: Tiempo de inferencia promedio por muestra (en milisegundos)
    total_inference_time = end_inference - start_inference
    inference_time_per_sample_ms = (total_inference_time / len(X_test)) * 1000
    
    # Mapeo a macro-categorías para el reporte
    y_test_labels = y_test.values
    y_pred_labels = le.inverse_transform(y_pred)
    
    y_test_macro = [ATTACK_MAP.get(l, 'unknown') for l in y_test_labels]
    y_pred_macro = [ATTACK_MAP.get(l, 'unknown') for l in y_pred_labels]
    
    unique_labels = sorted(list(set(y_test_macro) | set(y_pred_macro)))
    
    # Generar classification_report de scikit-learn
    report = classification_report(y_test_macro, y_pred_macro, labels=unique_labels, target_names=unique_labels)
    report_text = "\n" + "="*60 + "\n REPORTE DE CLASIFICACIÓN (Efectividad de Identificación) \n" + "="*60 + "\n" + report
    print(report_text)
    
    # Guardar en archivo
    with open('plots/classification_report.txt', 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    # Generar y guardar la Matriz de Confusión
    cm = confusion_matrix(y_test_macro, y_pred_macro, labels=unique_labels)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=unique_labels, yticklabels=unique_labels)
    plt.title('Matriz de Confusión Macro - Prototipo IDS (LightGBM)')
    plt.xlabel('Clase Predicha')
    plt.ylabel('Clase Real')
    plt.tight_layout()
    plt.savefig('plots/confusion_matrix.png', dpi=300)
    plt.close()
    
    # Calcular métricas macro requeridas para la tabla resumen
    acc = accuracy_score(y_test_macro, y_pred_macro)
    prec = precision_score(y_test_macro, y_pred_macro, average='macro', zero_division=0)
    rec = recall_score(y_test_macro, y_pred_macro, average='macro', zero_division=0)
    f1 = f1_score(y_test_macro, y_pred_macro, average='macro', zero_division=0)
    
    return inference_time_per_sample_ms, acc, prec, rec, f1

def print_consistency_matrix_summary(train_time, inference_ms, acc, prec, rec, f1):
    """
    Imprime una tabla resumen consolidando los resultados de manera explícita 
    para la Matriz de Consistencia.
    """
    summary_text = (
        "\n" + "="*80 + "\n"
        + " TABLA RESUMEN - DIMENSIONES DE LA MATRIZ DE CONSISTENCIA ".center(80) + "\n"
        + "="*80 + "\n\n"
        + "[ 1. VARIABLE INDEPENDIENTE: Prototipo de IDS con IA Explicable (XAI) ]\n"
        + "-" * 80 + "\n"
        + " -> D1: Tasa de cobertura táctica\n"
        + "      (Evaluada mediante explicabilidad en 'explainability.py' con SHAP)\n"
        + f" -> D2: Eficiencia computacional del entrenamiento\n"
        + f"      Tiempo total de entrenamiento: {train_time:.4f} segundos\n\n"
        + "[ 2. VARIABLE DEPENDIENTE: Detección de intrusiones ]\n"
        + "-" * 80 + "\n"
        + " -> D1: Efectividad de identificación (Métricas Macro Multiclase)\n"
        + f"      * Accuracy (Exactitud) : {acc:.4f}\n"
        + f"      * Precision (Precisión): {prec:.4f}\n"
        + f"      * Recall (Exhaustividad) : {rec:.4f}\n"
        + f"      * F1-Score             : {f1:.4f}\n"
        + "      * Matriz de Confusión generada en 'plots/confusion_matrix.png'\n"
        + f" -> D2: Agilidad de respuesta\n"
        + f"      Tiempo promedio de inferencia: {inference_ms:.6f} milisegundos por paquete\n"
        + "\n" + "="*80 + "\n"
    )
    print(summary_text)
    
    # Guardar tabla resumen en archivo
    with open('plots/consistency_matrix_summary.txt', 'w', encoding='utf-8') as f:
        f.write(summary_text)

def main():
    # 0. Asegurar la creación de la estructura de carpetas
    create_directories()
    
    # 1. Conexión de Datos y Trazabilidad
    print("[*] 1. Cargando y filtrando datasets de NSL-KDD...")
    X_train, y_train, X_test, y_test = load_and_filter_data()
    
    print("[*] 2. Aplicando Label Encoding...")
    y_train_enc, le = encode_labels(y_train)
    
    # 2. Configuración y Entrenamiento de LightGBM
    print("[*] 3. Entrenando el clasificador LightGBM...")
    model, training_time = train_model(X_train, y_train_enc, le)
    
    # 3. Evaluación Rigurosa
    print("[*] 4. Evaluando el modelo (métricas y matriz de confusión)...")
    inference_ms, acc, prec, rec, f1 = evaluate_model(model, X_test, y_test, le)
    
    # 4. Imprimir los resultados consolidados de la Matriz de Consistencia
    print_consistency_matrix_summary(training_time, inference_ms, acc, prec, rec, f1)
    print("[+] Ejecución completada exitosamente. Modelo y gráficos guardados en disco.")

if __name__ == '__main__':
    main()
