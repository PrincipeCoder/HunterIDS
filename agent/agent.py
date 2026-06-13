import os
import time
import json
import configparser
import requests
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
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
                    "ip_dst": ip_dst,
                    "num_failed_logins": 0,
                    "is_guest_login": 0
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
            
            # Deep Packet Inspection (DPI)
            if Raw in pkt:
                try:
                    payload_data = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                    if "530 login incorrect" in payload_data or "401 unauthorized" in payload_data or "authentication failure" in payload_data:
                        flow["num_failed_logins"] += 1
                    if "user anonymous" in payload_data or "guest login" in payload_data:
                        flow["is_guest_login"] = 1
                except:
                    pass
                
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
                
                flow_list = list(flows.values())
                
                # Calcular características de ventana de tiempo (Time-Window features)
                for flow in flow_list:
                    flag = get_flag(flow["flags_seen"]) if flow["protocol_type"] == "tcp" else "SF"
                    flow["computed_flag"] = flag
                    
                for flow in flow_list:
                    same_dst = [f for f in flow_list if f["ip_dst"] == flow["ip_dst"]]
                    same_srv = [f for f in same_dst if f["service"] == flow["service"]]
                    
                    flow["count"] = len(same_dst)
                    flow["srv_count"] = len(same_srv)
                    
                    s0_count = sum(1 for f in same_dst if f.get("computed_flag") == "S0")
                    rej_count = sum(1 for f in same_dst if f.get("computed_flag") == "REJ")
                    
                    flow["serror_rate"] = s0_count / max(1, len(same_dst))
                    flow["rerror_rate"] = rej_count / max(1, len(same_dst))
                    flow["same_srv_rate"] = len(same_srv) / max(1, len(same_dst))
                
                # Ya no truncamos a 15, preparamos un lote (batch) completo
                batch_payload = []
                
                for flow in flow_list:
                    duration = max(0.0, float(flow["end_time"] - flow["start_time"]))
                    
                    # Generar las 41 features con base 0.0
                    features = {col: 0.0 for col in NSL_KDD_COLUMNS}
                    
                    # Rellenar las features extraídas dinámicamente
                    features["duration"] = duration
                    features["protocol_type"] = flow["protocol_type"]
                    features["service"] = flow["service"]
                    features["flag"] = flow["computed_flag"]
                    features["src_bytes"] = float(flow["src_bytes"])
                    features["dst_bytes"] = float(flow["dst_bytes"])
                    features["land"] = 1.0 if flow["ip_src"] == flow["ip_dst"] else 0.0
                    
                    features["count"] = float(flow["count"])
                    features["srv_count"] = float(flow["srv_count"])
                    features["serror_rate"] = float(flow["serror_rate"])
                    features["rerror_rate"] = float(flow["rerror_rate"])
                    features["same_srv_rate"] = float(flow["same_srv_rate"])
                    
                    # DPI Features
                    features["num_failed_logins"] = float(flow["num_failed_logins"])
                    features["is_guest_login"] = float(flow["is_guest_login"])
                    
                    payload = {
                        "node_ip": node_ip,
                        "src_ip": flow["ip_src"],
                        "dst_ip": flow["ip_dst"],
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "features": features
                    }
                    batch_payload.append(payload)
                    
                if batch_payload:
                    try:
                        batch_url = f"http://{server_host}:{server_port}/api/v1/alerts/batch"
                        res = requests.post(batch_url, json=batch_payload, timeout=5)
                        if res.status_code == 200:
                            results = res.json().get("results", [])
                            print(f"[+] Lote enviado: {len(batch_payload)} flujos. Analizados con éxito.")
                            
                            # Imprimir amenazas o flujos destacables
                            for r in results:
                                if r["prediction"] != "normal" and r["prediction"] != "0":
                                    print(f"  [!] ALERTA: {r['src_ip']} -> {r['dst_ip']} | IA: {r['prediction']}")
                    except Exception as e:
                        pass # Ignorar si no hay conexión
                        
    except KeyboardInterrupt:
        print("\n[*] Agente detenido.")
    except PermissionError:
        print("\n[!] ERROR FATAL: Debes ejecutar este script como root/Administrador (sudo python agent.py) para interceptar paquetes de red.")

if __name__ == "__main__":
    main()
