import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier


def load_and_preprocess_nslkdd_txt(train_path, test_path, output_dir="../data/processed/"):
    print("Iniciando pipeline HunterIDS con archivos TXT...")

    # Columnas originales del dataset NSL-KDD
    columns = (['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
                'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
                'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
                'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
                'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
                'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
                'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
                'dst_host_srv_rerror_rate', 'label', 'difficulty_level'])

    # 1. CARGA DE DATOS
    df_train = pd.read_csv(train_path, names=columns)
    df_test = pd.read_csv(test_path, names=columns)

    print(f"-> Datos TXT cargados: Train {df_train.shape[0]} filas | Test {df_test.shape[0]} filas.")

    # 2. LIMPIEZA Y TRANSFORMACIÓN
    # Eliminar columna que no aporta a la detección
    df_train.drop(['difficulty_level'], axis=1, inplace=True)
    df_test.drop(['difficulty_level'], axis=1, inplace=True)

    # Binarizar las etiquetas: 'normal' = 0, cualquier ataque = 1 (Anomalía)
    y_train = df_train['label'].apply(lambda x: 0 if x == 'normal' else 1)
    y_test = df_test['label'].apply(lambda x: 0 if x == 'normal' else 1)

    df_train.drop(['label'], axis=1, inplace=True)
    df_test.drop(['label'], axis=1, inplace=True)

    # 3. CODIFICACIÓN (One-Hot Encoding)
    categorical_cols = ['protocol_type', 'service', 'flag']
    df_train_encoded = pd.get_dummies(df_train, columns=categorical_cols)
    df_test_encoded = pd.get_dummies(df_test, columns=categorical_cols)

    # Alinear columnas para asegurar la misma estructura entre entrenamiento y prueba
    df_train_encoded, df_test_encoded = df_train_encoded.align(df_test_encoded, join='left', axis=1, fill_value=0)

    # 4. NORMALIZACIÓN MIN-MAX (0 a 1)
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(df_train_encoded)
    X_test_scaled = scaler.transform(df_test_encoded)

    # 5. SELECCIÓN DE CARACTERÍSTICAS (Top 9)
    print("-> Seleccionando las 9 características más importantes con Random Forest...")
    rf_selector = RandomForestClassifier(n_estimators=300, random_state=100, n_jobs=-1)
    rf_selector.fit(X_train_scaled, y_train)

    importances = rf_selector.feature_importances_

    # Aplicar el umbral constante de 0.05 mencionado por los autores
    indices_umbral = np.where(importances >= 0.05)[0]
    # Si el umbral nos da más de 9 o menos de 9, forzamos los 9 más importantes como dice el texto
    if len(indices_umbral) >= 9:
        # Ordenamos los que pasaron el umbral y tomamos los top 9
        indices_top_9 = indices_umbral[np.argsort(importances[indices_umbral])[-9:]]
    else:
        # Fallback a los top 9 absolutos
        indices_top_9 = np.argsort(importances)[-9:]

    column_names = df_train_encoded.columns
    top_9_features = [column_names[i] for i in indices_top_9]

    # Convertir a DataFrames para facilitar el guardado y lectura posterior
    X_train_final = pd.DataFrame(X_train_scaled[:, indices_top_9], columns=top_9_features)
    X_test_final = pd.DataFrame(X_test_scaled[:, indices_top_9], columns=top_9_features)

    # 6. EXPORTAR DATOS PROCESADOS
    # Crear el directorio si no existe
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"-> Carpeta creada: {output_dir}")

    # Guardar los archivos CSV
    X_train_final.to_csv(os.path.join(output_dir, "X_train_final.csv"), index=False)
    X_test_final.to_csv(os.path.join(output_dir, "X_test_final.csv"), index=False)
    y_train.to_csv(os.path.join(output_dir, "y_train.csv"), index=False)
    y_test.to_csv(os.path.join(output_dir, "y_test.csv"), index=False)

    print(f"-> ¡Éxito! Archivos guardados listos para entrenar en: {os.path.abspath(output_dir)}")
    print("-> Las 9 características finales son:")
    for i, f in enumerate(reversed(top_9_features), 1):
        print(f"   {i}. {f}")

    return X_train_final, X_test_final, y_train, y_test, top_9_features


if __name__ == "__main__":
    # IMPORTANTE: Ejecutar este script estando dentro de la carpeta 'src'
    ruta_train = "../data/raw/KDDTrain+.txt"
    ruta_test = "../data/raw/KDDTest+.txt"
    carpeta_procesados = "../data/processed/"

    # Ejecutar proceso
    load_and_preprocess_nslkdd_txt(ruta_train, ruta_test, output_dir=carpeta_procesados)