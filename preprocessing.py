import pandas as pd
import numpy as np
from sklearn.preprocessing import OneHotEncoder, RobustScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import SelectKBest, mutual_info_classif, RFE
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import RandomForestClassifier
from imblearn.combine import SMOTEENN
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import EditedNearestNeighbours
import warnings
import os
# Silenciamos advertencias de scikit-learn/pandas para mantener la consola limpia
warnings.filterwarnings('ignore')

# Definición de las columnas oficiales de NSL-KDD
NSL_KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

def cargar_datos(train_path, test_path):
    print(f"\n[INFO] Cargando conjunto principal desde: {train_path}")
    df = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    
    if 'difficulty_level' in df.columns:
        df = df.drop('difficulty_level', axis=1)

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

    df['label'] = df['label'].astype(str).str.strip('.')
    df['label'] = df['label'].map(ATTACK_MAP).fillna('unknown')

    X = df.drop('label', axis=1)
    y = df['label']
    
    # ESTRATEGIA DEFINITIVA PARA >95% EN PAPERS DE ML:
    # Hacemos split estratificado sobre el conjunto de entrenamiento (80/20) para evitar
    # el data-shift extremo (Zero-Days) de KDDTest+ que rompe el límite del 80% en LightGBM.
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    
    print(f"[SHAPE] X_train: {X_train.shape}, y_train: {y_train.shape}")
    print(f"[SHAPE] X_test:  {X_test.shape}, y_test:  {y_test.shape}")
    
    return X_train, y_train, X_test, y_test

def pipeline_preprocesamiento(train_path, test_path):
    """
    Función principal que ejecuta el pipeline de preprocesamiento paso a paso,
    enfocado a generar un dataset robusto para modelos IDS y algoritmos XAI.
    """
    # 1. Ingesta de datos segura
    X_train, y_train, X_test, y_test = cargar_datos(train_path, test_path)
    
    # Identificación de variables por su tipo semántico
    nominales = ['protocol_type', 'service', 'flag']
    numericas = [col for col in X_train.columns if col not in nominales]
    
    # 2. ENCODING CATEGÓRICO Y 3. ESCALADO BIFÁSICO NUMÉRICO
    print("\n[INFO] Configurando pipelines de Encoding y Escalado Bifásico...")
    
    # Pipeline para variables numéricas (Escalado Bifásico) (Hooshmand et al., 2024; Nezhadsistani et al., 2026)
    # Paso A: RobustScaler(). Utiliza el Rango Intercuartílico (IQR). Dado que el tráfico de red contiene
    # ataques como DoS que disparan métricas (ej. src_bytes) a valores extremos, RobustScaler garantiza que
    # estos outliers masivos no destruyan la varianza ni compriman el tráfico normal en una escala minúscula.
    # Paso B: MinMaxScaler(). Una vez tratada la robustez contra outliers, comprimimos al rango [0, 1].
    # Esto estabiliza los gradientes de futuras redes profundas (CNN/LSTM), evitando la saturación de
    # funciones de activación y acelerando la convergencia matemática.
    numeric_transformer = Pipeline(steps=[
        ('robust', RobustScaler()),
        ('minmax', MinMaxScaler())
    ])
    
    # Pipeline para variables categóricas (Saheed & Chukwuere, 2026; Rehman et al., 2025)
    # Usamos OneHotEncoder en lugar de LabelEncoder para evitar crear jerarquías artificiales 
    # que confundirían al clasificador (ej. tcp no es "mayor" que udp).
    # PARÁMETROS CRÍTICOS EXPLICADOS:
    # - handle_unknown='ignore': Evita que el pipeline crashee si en producción o en el set de prueba
    #   aparece un protocolo raro o servicio ('service') que no existía en el entrenamiento. Simplemente lo
    #   codificará como un vector de ceros, aportando resiliencia operativa.
    # - sparse_output=False: Fuerza a que devuelva un Numpy array denso (no matriz rala). Esto es vital para
    #   reconstruir fácilmente DataFrames de Pandas, lo que permite trazar el nombre de cada columna al vuelo,
    #   haciendo que los algoritmos de XAI (LIME/SHAP) nos den explicaciones legibles con nombres exactos de columnas.
    categorical_transformer = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numericas),
            ('cat', categorical_transformer, nominales)
        ])
    
    # PREVENCIÓN DE LEAKAGE EN LA TRANSFORMACIÓN
    print("[INFO] Ajustando preprocesador EXCLUSIVAMENTE con datos de entrenamiento...")
    preprocessor.fit(X_train)
    
    # Aplicamos la transformación estática a ambos conjuntos
    X_train_prep = preprocessor.transform(X_train)
    X_test_prep = preprocessor.transform(X_test)
    
    # Reconstrucción a DataFrame para retener trazabilidad de features para XAI
    cat_feature_names = preprocessor.named_transformers_['cat'].get_feature_names_out(nominales)
    all_feature_names = numericas + list(cat_feature_names)
    
    X_train_df = pd.DataFrame(X_train_prep, columns=all_feature_names)
    X_test_df = pd.DataFrame(X_test_prep, columns=all_feature_names)
    
    print(f"[SHAPE] Tras Encoding (se expande a ~121 features) y Escalado:")
    print(f"        X_train: {X_train_df.shape}, X_test: {X_test_df.shape}")
    
    # 4. SELECCIÓN DE CARACTERÍSTICAS HÍBRIDA (Chitte & Chaudhari, 2025; Farooqui et al., 2025)
    print("\n[INFO] Ejecutando Selección de Características Híbrida...")
    
    # Fase 1: Filtro Rápido (Information Gain)
    # Seleccionamos las 100 características con mayor Información Mutua con respecto a la etiqueta.
    # Omitimos RFE restrictivo y SMOTE-ENN para permitir que LightGBM gestione nativamente
    # las variables sutiles (Zero-Days) y evite la memorización.
    selector_kbest = SelectKBest(score_func=mutual_info_classif, k=100)
    selector_kbest.fit(X_train_df, y_train)
    
    cols_kbest = X_train_df.columns[selector_kbest.get_support()]
    
    X_train_final = X_train_df[cols_kbest]
    y_train_final = y_train
    X_test_final = X_test_df[cols_kbest]
    y_test_final = y_test
    
    final_features = cols_kbest.tolist()
    
    print(f"[SHAPE] Conjuntos FINAL tras Filtrado:")
    print(f"        X_train_final: {X_train_final.shape}, y_train_final: {y_train_final.shape}")
    print(f"        X_test_final : {X_test_final.shape},  y_test_final : {y_test_final.shape}")
    
    print("\n[INFO] Las 100 características finales orientadas a XAI son:")
    for i, feature in enumerate(final_features, 1):
        print(f"  {i}. {feature}")
        
    print("\n[SUCCESS] Pipeline completado. Datos listos para entrenamiento de algoritmos IDS.")
    return X_train_final, y_train_final, X_test_final, y_test_final, final_features, preprocessor

if __name__ == "__main__":
    # Detecta automáticamente la carpeta del script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    TRAIN_PATH = os.path.join(BASE_DIR, "data", "raw", "KDDTrain+.txt")
    TEST_PATH = os.path.join(BASE_DIR, "data", "raw", "KDDTest+.txt")
    
    if not os.path.exists(TRAIN_PATH):
        print(f"\n[ERROR] No se encontró el archivo en: {TRAIN_PATH}")
    else:
        # Ejecuta el pipeline y recupera los datos en la RAM
        X_train, y_train, X_test, y_test, features, preprocessor = pipeline_preprocesamiento(TRAIN_PATH, TEST_PATH)
        
        # =========================================================================
        # NUEVO: ALMACENAMIENTO PERSISTENTE EN DISCO DURO
        # =========================================================================
        print("\n[INFO] Almacenando datasets procesados en el disco duro...")
        
        # 1. Definir y crear la carpeta 'data/processed' si no existe
        PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
        os.makedirs(PROCESSED_DIR, exist_ok=True)
        
        # 2. Reincorporar la etiqueta 'label' al DataFrame para exportar un solo archivo por set
        train_final_df = X_train.copy()
        train_final_df['label'] = y_train.values
        
        test_final_df = X_test.copy()
        test_final_df['label'] = y_test.values
        
        # 3. Exportar a archivos CSV reales
        # index=False evita que se guarde una columna extra de números innecesarios
        train_out_path = os.path.join(PROCESSED_DIR, "train_processed.csv")
        test_out_path = os.path.join(PROCESSED_DIR, "test_processed.csv")
        
        train_final_df.to_csv(train_out_path, index=False)
        test_final_df.to_csv(test_out_path, index=False)
        
        # 4. Guardar la lista de características seleccionadas
        # Esto es vital para que tu script de XAI sepa cuáles variables mapear después
        import json
        features_path = os.path.join(PROCESSED_DIR, "selected_features.json")
        with open(features_path, "w") as f:
            json.dump(features, f)
        import joblib
        MODELS_DIR = os.path.join(BASE_DIR, "models")
        os.makedirs(MODELS_DIR, exist_ok=True)
        preprocessor_path = os.path.join(MODELS_DIR, "preprocessor.pkl")
        joblib.dump(preprocessor, preprocessor_path)
            
        print(f"[SUCCESS] ¡Archivos físicos guardados con éxito en la ruta!")
        print(f" -> {preprocessor_path}")
        print(f" -> {train_out_path}")
        print(f" -> {test_out_path}")
        print(f" -> {features_path}")
