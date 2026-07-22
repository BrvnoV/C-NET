# C2-Hunter 🛡️

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![API](https://img.shields.io/badge/API-AbuseIPDB-orange.svg)](https://www.abuseipdb.com/)
[![Security](https://img.shields.io/badge/Security-Threat%20Intelligence-red.svg)](#)

**C2-Hunter-Engine** es una plataforma interactiva de **Threat Intelligence y Auditoría de Red** desarrollada en Python y Flask. Su objetivo es automatizar la detección de infraestructuras maliciosas, identificar patrones de Comando y Control (C2) y exponer técnicas de evasión como el **Cloud Masking** en entornos SOC y Blue Team.

---

## 🚀 Capacidades Principales

* **Análisis de Reputación IP en Tiempo Real:** Evalúa direcciones IP públicas mediante la integración estricta de la API v2 de AbuseIPDB, calculando niveles de confianza y reportes en una ventana de 90 días.
* **Detección de Cloud Masking:** Identifica si un actor malicioso intenta ocultar servidores C2 detrás de proveedores de nube legítimos (AWS, DigitalOcean, Linode, Hetzner, etc.) mediante correlación de ISPs y reportes activos.
* **Exclusión Automática de Redes Internas:** Filtra y segmenta rangos de IP privadas (RFC 1918) e inválidas para optimizar las consultas a APIs externas.
* **Interfaz Web Intuitiva:** Dashboard limpio y responsivo para el análisis masivo de direcciones IP mediante un motor de decisiones categorizado por colores e indicadores de criticidad.

---

## 📊 Matriz de Clasificación de Amenazas

El motor analiza las respuestas y clasifica cada IP según los siguientes criterios de seguridad:

| Nivel | Estado | Criterio de Análisis | Acción Sugerida |
| :---: | :---: | :--- | :--- |
| **CRÍTICO** | 🔴 `BLOQUEAR` | Detección de ISP sospechoso/Nube con reportes activos de abuso. | Bloqueo inmediato en Firewall / Drop de tráfico. |
| **ALTO** | 🟠 `REVISAR` | Índice de confianza de abuso mayor o igual al 25%. | Aislar para análisis forense / Monitoreo en SIEM. |
| **BAJO** | 🟢 `ALLOW` | Sin reportes significativos de abuso registrados. | Permitir tráfico / Tráfico legítimo. |
| **EXCLUIDO**| ⚪ `ALLOW` | Dirección IP perteneciente a rangos privados (RFC 1918). | Excluir de análisis externo. |

---

## 🛠️ Requisitos Previos e Instalación

### 1. Clonar el repositorio
git clone https://github.com/BrvnoV/C2-Hunter-Engine.git
cd C2-Hunter-Engine

### 2. Crear un entorno virtual e instalar dependencias
python3 -m venv .venv
source .venv/bin/activate  # En Linux/macOS
# .venv\Scripts\activate   # En Windows

pip install -r requirements.txt

### 3. Configuración de Variables de Entorno (Seguridad)
Para proteger tus credenciales, crea un archivo .env en la raíz del proyecto (asegúrate de que este archivo esté incluido en el .gitignore):

C2_HUNTER_KEY=tu_api_key_de_abuseipdb_aqui

---

## 💻 Uso de la Aplicación

Ejecuta el servidor web local con el siguiente comando:

python abuseip/abuseip.py

Abre tu navegador e ingresa a http://127.0.0.1:5000 para acceder a la consola interactiva de análisis.

---

## 🔒 Buenas Prácticas de Seguridad Implementadas

* **Gestión Segura de Credenciales:** Uso de `python-dotenv` para evitar el *hardcoding* de API Keys en el control de versiones.
* **Manejo Estricto de Excepciones:** Control de *timeouts* e interrupciones en peticiones HTTP para prevenir fallos en cascada en el servidor web.

---

## 📜 Licencia y Descargo de Responsabilidad

Este proyecto ha sido desarrollado exclusivamente con fines educativos, de investigación y para el fortalecimiento de la postura de seguridad en entornos autorizados.
