import pandas as pd
import numpy as np
import os
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import cross_validate, KFold


def run_flawed_cross_validation(data_dir="../data/processed/"):
    print("Cargando datos de entrenamiento para replicar metodología de los autores...")

    # Solo cargamos los datos de entrenamiento (Train) porque aquí es donde
    # los autores aplicaron su 10-Fold CV, causando el sobreajuste.
    X_train = pd.read_csv(os.path.join(data_dir, "X_train_final.csv"))
    y_train = pd.read_csv(os.path.join(data_dir, "y_train.csv")).values.ravel()

    # Los hiperparámetros EXACTOS del paper
    models = {
        "Regresion_Logistica": LogisticRegression(max_iter=100, random_state=42),
        "KNN": KNeighborsClassifier(n_neighbors=5, metric='euclidean'),
        "SVM": SVC(kernel='linear', C=10.0, gamma='scale', random_state=42)
    }

    # Configurar la Validación Cruzada de 10 pliegues (10-Fold CV)
    kf = KFold(n_splits=10, shuffle=True, random_state=42)

    # Métricas que queremos extraer en cada pliegue
    scoring = ['accuracy', 'precision', 'recall', 'f1']
    results = []

    print("\nEjecutando 10-Fold CV (Replicando el error metodológico)...\n" + "=" * 65)
    print("NOTA: El SVM tomará varios minutos ya que entrenará 10 veces.")

    for name, model in models.items():
        print(f"Evaluando {name}...")

        # n_jobs=-1 usa todos los núcleos de tu procesador para acelerar los 10 entrenamientos
        cv_results = cross_validate(model, X_train, y_train, cv=kf, scoring=scoring, n_jobs=-1)

        # Calculamos el promedio de las 10 iteraciones
        acc = np.mean(cv_results['test_accuracy'])
        prec = np.mean(cv_results['test_precision'])
        rec = np.mean(cv_results['test_recall'])
        f1 = np.mean(cv_results['test_f1'])

        results.append({
            "Modelo": name,
            "Accuracy (CV)": round(acc, 4),
            "Precision (CV)": round(prec, 4),
            "Recall (CV)": round(rec, 4),
            "F1-Score (CV)": round(f1, 4)
        })

    # Mostrar tabla de resultados replicados
    results_df = pd.DataFrame(results)
    print("=" * 65 + "\nRESULTADOS REPLICADOS (10-FOLD CV SOBRE KDD-TRAIN)\n" + "=" * 65)
    print(results_df.to_string(index=False))
    print("=" * 65)

    # Guardar métricas en un CSV para tu informe técnico
    out_path = "../models/saved_models/metricas_replicadas_cv.csv"
    results_df.to_csv(out_path, index=False)
    print(f"Métricas de los autores replicadas y exportadas a: {out_path}")


if __name__ == "__main__":
    run_flawed_cross_validation()