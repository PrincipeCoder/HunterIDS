import os
import time
import json
import random
import configparser
import requests
import pandas as pd
from datetime import datetime

# Rutas base
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "agente.conf")

# Columnas oficiales de NSL-KDD crudas (Raw Features)
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

def load_config():
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: No se encontró el archivo de configuración {CONFIG_FILE}")
        exit(1)
    config.read(CONFIG_FILE)
    return config

def main():
    print("[*] Iniciando Agente Raw HunterIDS...")
    config = load_config()
    
    server_host = config.get("SERVER", "host")
    server_port = config.get("SERVER", "port")
    endpoint = config.get("SERVER", "endpoint")
    
    node_ip = config.get("AGENT", "node_ip")
    interval = config.getint("AGENT", "monitoring_interval_seconds")
    
    # Ahora leemos el dataset crudo
    dataset_rel_path = config.get("AGENT", "dataset_path")
    dataset_path = os.path.abspath(os.path.join(BASE_DIR, dataset_rel_path))
    
    if not os.path.exists(dataset_path):
        print(f"Error: No se encontró {dataset_path}")
        exit(1)
    
    print(f"[*] Cargando tráfico crudo de: {dataset_path}")
    df = pd.read_csv(dataset_path, header=None, names=NSL_KDD_COLUMNS)
    
    # Extraer estrictamente las 41 features, sin label ni difficulty_level
    features_columns = NSL_KDD_COLUMNS[:41]
    df_features = df[features_columns]
    
    server_url = f"http://{server_host}:{server_port}{endpoint}"
    print(f"[*] Conectando con servidor en {server_url}")
    print(f"[*] IP de Nodo Asignada: {node_ip}")
    print(f"[*] Intervalo de monitoreo: {interval} segundos\n")
    
    total_samples = len(df_features)
    
    try:
        while True:
            # Seleccionar una fila al azar
            idx = random.randint(0, total_samples - 1)
            row = df_features.iloc[idx]
            
            # Convertir a dict (mezcla de strings como 'tcp' e ints como 0)
            features_dict = row.to_dict()
            
            payload = {
                "node_ip": node_ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "features": features_dict
            }
            
            try:
                print(f"[>] {datetime.now().strftime('%H:%M:%S')} - Enviando 41 Raw Features al servidor...")
                response = requests.post(server_url, json=payload, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    pred = data.get("prediction", "UNKNOWN")
                    print(f"[+] Respuesta recibida. IA Servidor clasificó como: {pred}")
                else:
                    print(f"[!] Error del servidor: {response.status_code} - {response.text}")
            except requests.exceptions.ConnectionError:
                print("[!] Error de conexión: Servidor inalcanzable.")
            except Exception as e:
                print(f"[!] Error inesperado: {e}")
                
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n[*] Agente detenido por el usuario.")

if __name__ == "__main__":
    main()
