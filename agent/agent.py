import os
import time
import json
import configparser
import requests
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Suppress scapy warnings

# Rutas base
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "agente.conf")

# Columnas oficiales KDD
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
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

def get_service(port):
    services = {
        80: 'http', 443: 'http_443', 21: 'ftp', 22: 'ssh', 23: 'telnet',
        25: 'smtp', 53: 'domain_u', 110: 'pop_3', 143: 'imap4', 3306: 'sql_net'
    }
    return services.get(port, 'other')

def get_flag(tcp_flags_seen):
    """Mapea las banderas TCP vistas a las equivalentes KDD"""
    flags_str = "".join(tcp_flags_seen)
    if 'S' in flags_str and 'F' in flags_str:
        return 'SF'  # Conexión establecida y terminada
    elif 'S' in flags_str and 'R' in flags_str:
        return 'REJ' # Conexión rechazada
    elif 'S' in flags_str and not any(f in flags_str for f in ['A', 'F', 'R']):
        return 'S0'  # SYN enviado, sin respuesta
    elif 'R' in flags_str:
        return 'RSTR'
    return 'SF' # Por defecto

def process_flows(packets):
    flows = {}
    for pkt in packets:
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            proto = "other"
            port_src = 0
            port_dst = 0
            tcp_flag = ""
            
            if TCP in pkt:
                proto = "tcp"
                port_src = pkt[TCP].sport
                port_dst = pkt[TCP].dport
                tcp_flag = pkt[TCP].flags
            elif UDP in pkt:
                proto = "udp"
                port_src = pkt[UDP].sport
                port_dst = pkt[UDP].dport
            elif ICMP in pkt:
                proto = "icmp"
                
            # Tupla única independiente de la dirección para agrupar flujos bidireccionales
            flow_key = tuple(sorted([f"{ip_src}:{port_src}", f"{ip_dst}:{port_dst}"]) + [proto])
            
            if flow_key not in flows:
                flows[flow_key] = {
                    "start_time": pkt.time,
                    "end_time": pkt.time,
                    "protocol_type": proto,
                    "service": get_service(port_dst) if proto != "icmp" else "eco_i",
                    "src_bytes": 0,
                    "dst_bytes": 0,
                    "flags_seen": set(),
                    "ip_src": ip_src,
                    "ip_dst": ip_dst
                }
            
            flow = flows[flow_key]
            flow["end_time"] = pkt.time
            
            if pkt[IP].src == flow["ip_src"]:
                flow["src_bytes"] += len(pkt)
                if proto == "tcp":
                    flow["flags_seen"].add(str(tcp_flag))
            else:
                flow["dst_bytes"] += len(pkt)
                if proto == "tcp":
                    flow["flags_seen"].add(str(tcp_flag))
                
    return flows

def main():
    print("[*] Iniciando Sniffer Agent HunterIDS...")
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        print(f"[!] Archivo config no encontrado: {CONFIG_FILE}")
        return
    config.read(CONFIG_FILE)
    
    server_host = config.get("SERVER", "host")
    server_port = config.get("SERVER", "port")
    endpoint = config.get("SERVER", "endpoint")
    node_ip = config.get("AGENT", "node_ip")
    interval = config.getint("AGENT", "monitoring_interval_seconds")
    
    server_url = f"http://{server_host}:{server_port}{endpoint}"
    print(f"[*] Escuchando tráfico real.\n[*] Nodo: {node_ip}\n[*] Servidor IA: {server_url}\n")
    
    try:
        while True:
            # Sniff intercepta paquetes de red durante el intervalo configurado
            packets = sniff(timeout=interval)
            
            if len(packets) > 0:
                flows = process_flows(packets)
                
                # Limitamos para no saturar el websocket (por ser prototipo)
                flow_list = list(flows.values())[:15]
                
                for flow in flow_list:
                    duration = max(0.0, float(flow["end_time"] - flow["start_time"]))
                    flag = get_flag(flow["flags_seen"]) if flow["protocol_type"] == "tcp" else "SF"
                    
                    # Generar las 41 features con base 0.0
                    features = {col: 0.0 for col in NSL_KDD_COLUMNS}
                    
                    # Rellenar las features extraídas dinámicamente
                    features["duration"] = duration
                    features["protocol_type"] = flow["protocol_type"]
                    features["service"] = flow["service"]
                    features["flag"] = flag
                    features["src_bytes"] = float(flow["src_bytes"])
                    features["dst_bytes"] = float(flow["dst_bytes"])
                    features["land"] = 1.0 if flow["ip_src"] == flow["ip_dst"] else 0.0
                    
                    payload = {
                        "node_ip": node_ip,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "features": features
                    }
                    
                    try:
                        res = requests.post(server_url, json=payload, timeout=2)
                        if res.status_code == 200:
                            pred = res.json().get("prediction", "UNKNOWN")
                            print(f"[>] {flow['protocol_type']} {flow['service']} | {flow['src_bytes']}b -> IA: {pred}")
                    except Exception as e:
                        pass # Ignorar si no hay conexión
                        
    except KeyboardInterrupt:
        print("\n[*] Agente detenido.")
    except PermissionError:
        print("\n[!] ERROR FATAL: Debes ejecutar este script como root/Administrador (sudo python agent.py) para interceptar paquetes de red.")

if __name__ == "__main__":
    main()
