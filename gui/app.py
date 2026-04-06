import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd
import joblib
import os
import random


class HunterIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HunterIDS - Network Anomaly Detector")
        self.root.geometry("850x550")
        self.root.configure(bg="#0d1117")  # Fondo oscuro tipo GitHub Dark
        self.root.resizable(False, False)

        # Rutas relativas asumiendo que se ejecuta desde main.py en la raíz
        self.models_dir = os.path.join("models", "saved_models")
        self.data_dir = os.path.join("data", "processed")

        self.models = {}
        self.current_packet = None
        self.actual_label = None
        self.features_names = []

        self.load_models_and_data()
        self.setup_ui()

    def load_models_and_data(self):
        """Carga los archivos .pkl y el dataset de prueba para la simulación"""
        try:
            # Cargar modelos
            for model_name in ["Regresion_Logistica", "KNN", "SVM"]:
                path = os.path.join(self.models_dir, f"{model_name}.pkl")
                if os.path.exists(path):
                    self.models[model_name] = joblib.load(path)

            # Cargar datos para simulación
            self.X_test = pd.read_csv(os.path.join(self.data_dir, "X_test_final.csv"))
            self.y_test = pd.read_csv(os.path.join(self.data_dir, "y_test.csv")).values.ravel()
            self.features_names = self.X_test.columns.tolist()

        except Exception as e:
            messagebox.showerror("Error de Carga",
                                 f"Faltan archivos del modelo o datos.\nAsegúrate de haber ejecutado preprocessing.py y trainer.py.\nDetalle: {e}")

    def setup_ui(self):
        # --- ESTILOS ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background="#0d1117")
        style.configure("TLabel", background="#0d1117", foreground="#c9d1d9", font=("Consolas", 11))
        style.configure("Header.TLabel", foreground="#58a6ff", font=("Consolas", 18, "bold"))
        style.configure("TButton", font=("Consolas", 11, "bold"), background="#21262d", foreground="#c9d1d9")
        style.map("TButton", background=[("active", "#30363d")])

        # --- HEADER ---
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, pady=20)
        ttk.Label(header_frame, text="🛡️ HunterIDS | Security Operations Center", style="Header.TLabel").pack()

        # --- MAIN CONTENT ---
        content_frame = ttk.Frame(self.root)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20)

        # Panel Izquierdo (Controles)
        left_panel = ttk.Frame(content_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))

        ttk.Label(left_panel, text="Control de Análisis", font=("Consolas", 13, "bold"), foreground="#7ee787").pack(
            pady=(0, 15))

        self.btn_intercept = tk.Button(left_panel, text="📡 Interceptar Paquete", command=self.intercept_packet,
                                       bg="#238636", fg="white", font=("Consolas", 11, "bold"), relief="flat", padx=10,
                                       pady=5)
        self.btn_intercept.pack(fill=tk.X, pady=10)

        ttk.Label(left_panel, text="Seleccionar Motor IA:").pack(pady=(15, 5))
        self.model_var = tk.StringVar(value="Regresion_Logistica")
        self.model_combo = ttk.Combobox(left_panel, textvariable=self.model_var, values=list(self.models.keys()),
                                        state="readonly", font=("Consolas", 11))
        self.model_combo.pack(fill=tk.X, pady=5)

        self.btn_analyze = tk.Button(left_panel, text="🔍 Analizar Tráfico", command=self.analyze_traffic,
                                     bg="#1f6feb", fg="white", font=("Consolas", 11, "bold"), relief="flat", padx=10,
                                     pady=5, state=tk.DISABLED)
        self.btn_analyze.pack(fill=tk.X, pady=20)

        # Panel Derecho (Datos del Paquete)
        right_panel = ttk.Frame(content_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        ttk.Label(right_panel, text="Firma del Paquete de Red (Top 9 Features)", font=("Consolas", 12, "bold"),
                  foreground="#8b949e").pack(anchor=tk.W)

        # Caja de texto para mostrar las variables
        self.data_display = tk.Text(right_panel, height=12, bg="#161b22", fg="#79c0ff", font=("Consolas", 11),
                                    relief="flat", padx=10, pady=10)
        self.data_display.pack(fill=tk.X, pady=10)
        self.data_display.insert(tk.END, "Esperando intercepción de red...\n")
        self.data_display.config(state=tk.DISABLED)

        # --- PANEL DE RESULTADOS ---
        result_frame = ttk.Frame(self.root)
        result_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=20, padx=20)

        self.lbl_status = tk.Label(result_frame, text="ESTADO: EN ESPERA", bg="#0d1117", fg="#8b949e",
                                   font=("Consolas", 16, "bold"))
        self.lbl_status.pack()

    def intercept_packet(self):
        """Simula la captura de un paquete tomando una fila aleatoria del set de pruebas"""
        if not hasattr(self, 'X_test'):
            return

        # Elegir un índice aleatorio
        idx = random.randint(0, len(self.X_test) - 1)
        self.current_packet = self.X_test.iloc[[idx]]
        self.actual_label = self.y_test[idx]  # 0 Normal, 1 Anomalía

        # Mostrar en pantalla
        self.data_display.config(state=tk.NORMAL)
        self.data_display.delete(1.0, tk.END)
        for col in self.features_names:
            val = self.current_packet[col].values[0]
            self.data_display.insert(tk.END, f"{col.ljust(25)}: {val:.6f}\n")
        self.data_display.config(state=tk.DISABLED)

        self.lbl_status.config(text="PAQUETE CAPTURADO - LISTO PARA ANÁLISIS", fg="#f2cc60")
        self.btn_analyze.config(state=tk.NORMAL)

    def analyze_traffic(self):
        """Pasa el paquete por el modelo .pkl seleccionado"""
        selected_model = self.model_var.get()
        if selected_model not in self.models or self.current_packet is None:
            return

        model = self.models[selected_model]

        # Inferencia matemática
        prediction = model.predict(self.current_packet)[0]

        # Mostrar Resultado
        if prediction == 1:
            self.lbl_status.config(text="🚨 ALERTA CRÍTICA: TRÁFICO ANÓMALO DETECTADO 🚨", fg="#ff7b72")
        else:
            self.lbl_status.config(text="✅ TRÁFICO NORMAL: SIN AMENAZAS DETECTADAS ✅", fg="#3fb950")


def main():
    root = tk.Tk()
    app = HunterIDSApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()