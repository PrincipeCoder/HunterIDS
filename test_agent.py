import requests
import time
import json
import random
from datetime import datetime

SERVER_URL = "http://localhost:8000/api/v1/alerts"

def send_alert():
    features = {
        "Src_Port": random.uniform(1024, 65535),
        "Dst_Port": 80,
        "Flow_Duration": random.uniform(10, 10000),
        "Total_Fwd_Packets": random.randint(1, 100),
        "Total_Backward_Packets": random.randint(1, 100),
    }
    
    # Sort features by value to simulate top features
    sorted_features = dict(sorted(features.items(), key=lambda item: item[1], reverse=True)[:3])
    
    is_malicious = random.random() > 0.5
    
    alert = {
        "node_ip": f"192.168.1.{random.randint(10, 50)}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "prediction": "Malicious" if is_malicious else "Normal",
        "confidence": random.uniform(0.7, 0.99) if is_malicious else random.uniform(0.5, 0.9),
        "features": sorted_features,
        "shap_values": {k: random.uniform(0.1, 0.5) for k in sorted_features.keys()}
    }
    
    try:
        response = requests.post(SERVER_URL, json=alert)
        print(f"Sent alert: {alert['prediction']} - {alert['confidence']:.2f}")
        print(f"Server response: {response.json()}")
    except Exception as e:
        print(f"Error sending alert: {e}")

if __name__ == "__main__":
    print("Starting agent simulation...")
    for i in range(5):
        send_alert()
        time.sleep(1)
