import os
import json
import time
import joblib
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

def encode_labels(y_train, y_test):
    """
    Aplica LabelEncoder a las etiquetas (normal, dos, probe, r2l, u2r).
    Guarda el encoder para mapeo inverso en el módulo XAI.
    """
    le = LabelEncoder()
    # Ajustar y transformar en el conjunto de entrenamiento
    y_train_encoded = le.fit_transform(y_train)
    # Transformar el conjunto de prueba utilizando el mismo vocabulario
    y_test_encoded = le.transform(y_test)
    
    # Guardar el codificador de etiquetas
    joblib.dump(le, 'models/label_encoder.pkl')
    
    return y_train_encoded, y_test_encoded, le

def train_model(X_train, y_train):
    """
    Configura y entrena el clasificador LightGBM.
    Registra el tiempo de entrenamiento para evaluar la Dimensión: Eficiencia Computacional (D2).
    """
    # Instanciamos LGBMClassifier con la arquitectura avanzada requerida:
    model = LGBMClassifier(
        objective='multiclass',  # Función de pérdida para clasificación multiclase
        num_class=5,             # Dominio de 5 clases (normal + 4 de ataque)
        random_state=42,         # Semilla para reproducibilidad
        class_weight='balanced', # Se reintroduce 'balanced' ya que se eliminó SMOTE, permitiendo que LightGBM maneje nativamente el desbalanceo.
        n_estimators=300,        # Mayor número de iteraciones para un aprendizaje más profundo del error residual.
        learning_rate=0.03,      # Reducción de la tasa para lograr convergencia más suave y exacta en pérdida multiclase.
        num_leaves=127,          # Incremento de hojas para expandir la capacidad del modelo de memorizar complejas reglas de seguridad.
        max_depth=10,            # Límite de profundidad para controlar el sobreajuste ante el aumento de num_leaves.
        min_child_samples=20,    # Regularización para evitar ruido de los datos sintéticos de SMOTE.
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
    # Registrar tiempo de inicio de inferencia
    start_inference = time.time()
    
    # Realizar predicciones sobre TODO el conjunto de prueba
    y_pred = model.predict(X_test)
    
    # Registrar tiempo de fin de inferencia
    end_inference = time.time()
    
    # Calcular Agilidad de respuesta: Tiempo de inferencia promedio por muestra (en milisegundos)
    total_inference_time = end_inference - start_inference
    inference_time_per_sample_ms = (total_inference_time / len(X_test)) * 1000
    
    # Obtener los nombres reales de las clases desde el LabelEncoder
    target_names = le.classes_
    
    # Generar classification_report de scikit-learn
    report = classification_report(y_test, y_pred, target_names=target_names)
    report_text = "\n" + "="*60 + "\n REPORTE DE CLASIFICACIÓN (Efectividad de Identificación) \n" + "="*60 + "\n" + report
    print(report_text)
    
    # Guardar en archivo
    with open('plots/classification_report.txt', 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    # Generar y guardar la Matriz de Confusión
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=target_names, yticklabels=target_names)
    plt.title('Matriz de Confusión - Prototipo IDS (LightGBM)')
    plt.xlabel('Clase Predicha')
    plt.ylabel('Clase Real')
    plt.tight_layout()
    plt.savefig('plots/confusion_matrix.png', dpi=300)
    plt.close()
    
    # Calcular métricas macro requeridas para la tabla resumen
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec = recall_score(y_test, y_pred, average='macro', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
    
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
    y_train_enc, y_test_enc, le = encode_labels(y_train, y_test)
    
    # 2. Configuración y Entrenamiento de LightGBM
    print("[*] 3. Entrenando el clasificador LightGBM...")
    model, training_time = train_model(X_train, y_train_enc)
    
    # 3. Evaluación Rigurosa
    print("[*] 4. Evaluando el modelo (métricas y matriz de confusión)...")
    inference_ms, acc, prec, rec, f1 = evaluate_model(model, X_test, y_test_enc, le)
    
    # 4. Imprimir los resultados consolidados de la Matriz de Consistencia
    print_consistency_matrix_summary(training_time, inference_ms, acc, prec, rec, f1)
    print("[+] Ejecución completada exitosamente. Modelo y gráficos guardados en disco.")

if __name__ == '__main__':
    main()
