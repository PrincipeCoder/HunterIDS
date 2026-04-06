import pandas as pd
import os
import joblib
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report


def load_processed_data(data_dir="../data/processed/"):
    print(f"Cargando datos preprocesados desde {data_dir}...")

    X_train = pd.read_csv(os.path.join(data_dir, "X_train_final.csv"))
    X_test = pd.read_csv(os.path.join(data_dir, "X_test_final.csv"))
    y_train = pd.read_csv(
        os.path.join(data_dir, "y_train.csv")).values.ravel()  # .ravel() aplana el array para scikit-learn
    y_test = pd.read_csv(os.path.join(data_dir, "y_test.csv")).values.ravel()

    return X_train, X_test, y_train, y_test

def train_and_evaluate_models(X_train, X_test, y_train, y_test, models_dir="../models/saved_models/"):
    # Asegurar que la carpeta de modelos exista
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)
        print(f"-> Carpeta creada para guardar modelos: {models_dir}")

    # ¡Indentación corregida! Ahora está al mismo nivel que el 'if'
    # Diccionario con los hiperparámetros EXACTOS extraídos del paper
    models = {
        "Regresion_Logistica": LogisticRegression(
            max_iter=100,  # 100 iteraciones como dice el paper
            random_state=42  # Pesos uniformes y sigmoide son default en sklearn para binaria
        ),
        "KNN": KNeighborsClassifier(
            n_neighbors=5,  # k = 5
            metric='euclidean'  # Distancia Euclidiana
        ),
        "SVM": SVC(
            kernel='linear',  # Kernel Lineal (crucial para no usar redes neuronales profundas)
            C=10.0,  # Parámetro de penalización = 10
            gamma='scale',  # "Valor gamma específico", scale es la mejor práctica
            random_state=42  # Estado aleatorio mencionado
        )
    }

    results = []

    print("\nIniciando entrenamiento y evaluación de modelos de HunterIDS...\n" + "=" * 50)

    for name, model in models.items():
        print(f"Entrenando {name}...")

        # Entrenamiento
        model.fit(X_train, y_train)

        # Predicción sobre el conjunto de prueba
        y_pred = model.predict(X_test)

        # Cálculo de métricas
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)  # También conocido como Tasa de Detección (Detection Rate)
        f1 = f1_score(y_test, y_pred)

        results.append({
            "Modelo": name,
            "Accuracy": round(acc, 4),
            "Precision": round(prec, 4),
            "Recall (DR)": round(rec, 4),
            "F1-Score": round(f1, 4)
        })

        # Guardar el modelo entrenado en disco para la Interfaz Gráfica
        model_path = os.path.join(models_dir, f"{name}.pkl")
        joblib.dump(model, model_path)
        print(f"-> {name} evaluado y guardado en {model_path}\n")

    # Mostrar tabla de resultados comparativos
    results_df = pd.DataFrame(results)
    print("=" * 50 + "\nRESULTADOS FINALES DE EVALUACIÓN (TEST DATASET)\n" + "=" * 50)
    print(results_df.to_string(index=False))
    print("=" * 50)

    # Guardar métricas en un CSV para tu informe técnico
    report_path = os.path.join(models_dir, "metricas_comparativas.csv")
    results_df.to_csv(report_path, index=False)
    print(f"Métricas exportadas a: {report_path}")

if __name__ == "__main__":
    # Rutas relativas basadas en la estructura del proyecto
    data_directory = "../data/processed/"
    models_directory = "../models/saved_models/"

    try:
        X_train, X_test, y_train, y_test = load_processed_data(data_dir=data_directory)
        train_and_evaluate_models(X_train, X_test, y_train, y_test, models_dir=models_directory)
    except FileNotFoundError:
        print("ERROR: No se encontraron los archivos procesados. Ejecuta 'preprocessing.py' primero.")