# 🛡️ HunterIDS:Sistema Híbrido de Detección de Intrusiones en Red
HunterIDS es una herramienta de ciberseguridad basada en Inteligencia Artificial diseñada para interceptar y clasificar tráfico de red anómalo en tiempo real. Este proyecto nace como una reproducción experimental y mejora crítica del artículo científico "Towards Detection of Network Anomalies using Machine Learning Algorithms on the NSL-KDD Benchmark Datasets".

DOI: https://doi.org/10.1016/j.procs.2024.03.285
## 🔬 Contexto Académico y Mejora Metodológica
El sistema ha sido entrenado y evaluado estrictamente separando los datos de conocimiento previo (KDDTrain+) del tráfico con amenazas de día cero (KDDTest+), ofreciendo métricas de detección reales y fiables para un entorno de producción.

## ⚙️ Arquitectura Técnica
El "motor" de HunterIDS se basa en un pipeline de Machine Learning de dos fases, optimizado para ser computacionalmente ligero y de respuesta instantánea:

Selección de Características (Feature Engineering): Utiliza un ensamble de Random Forest (300 estimadores) para reducir el ruido computacional, extrayendo dinámicamente las 9 firmas de red más críticas (de un total de 41 atributos originales).

Clasificación Binaria: Implementa clasificadores estadísticos pre-entrenados y serializados (Support Vector Machine con Kernel Lineal, Regresión Logística y K-Nearest Neighbors) para evaluar las 9 variables y emitir veredictos de "Tráfico Normal" o "Anomalía" en milisegundos.

## 🎯 Enfoque Operativo para SOCs
Concebido para su integración en Centros de Operaciones de Seguridad, HunterIDS incluye una Interfaz Gráfica de Usuario (GUI) que simula la intercepción de paquetes de red. Su arquitectura modular permite a los analistas de seguridad realizar inferencias casi instantáneas sin depender de clústeres masivos de GPU, facilitando la identificación ágil de amenazas y sirviendo como una base sólida para futuras integraciones de Inteligencia Artificial Explicable (XAI).
