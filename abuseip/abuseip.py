import ipaddress
import os
from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# --- [ CONFIGURACIÓN C2-HUNTER ] ---
# Se utiliza variable de entorno para evitar exponer credenciales en Git
C2_HUNTER_KEY = os.getenv(
    'C2_HUNTER_KEY', 'TU_API_KEY_AQUI'
)  # Reemplaza con tu llave o variable de entorno
SUSPICIOUS_ISPS = {
    'Datacamp Limited',
    'DataPacket',
    'DigitalOcean',
    'Linode',
    'Hetzner',
    'M247',
    'Contabo',
}
PRIVATE_RANGES = [
    ipaddress.ip_network(r)
    for r in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
]


def analyze_ip(ip_str):
  ip_str = ip_str.strip()
  try:
    ip_obj = ipaddress.ip_address(ip_str)
    if any(ip_obj in net for net in PRIVATE_RANGES):
      return {
          'ip': ip_str,
          'nivel': 'EXCLUIDO',
          'isp': 'RED INTERNA',
          'accion': 'ALLOW',
          'class': 'table-secondary',
      }
  except:
    return {
        'ip': ip_str,
        'nivel': 'ERROR',
        'isp': 'FORMATO INVÁLIDO',
        'accion': 'ERROR',
        'class': 'table-warning',
    }

  # Consulta Motor C2-Hunter
  url = 'https://api.abuseipdb.com/api/v2/check'
  headers = {'Accept': 'application/json', 'Key': C2_HUNTER_KEY}
  params = {'ipAddress': ip_str, 'maxAgeInDays': '90'}

  try:
    res = requests.get(url, headers=headers, params=params, timeout=5).json()[
        'data'
    ]
    score = res.get('abuseConfidenceScore', 0)
    isp = res.get('isp', 'N/A')
    reports = res.get('totalReports', 0)
    is_dc = any(s.lower() in isp.lower() for s in SUSPICIOUS_ISPS)

    # Lógica Senior C2-Hunter
    if is_dc and reports > 0:
      return {
          'ip': ip_str,
          'nivel': 'CRÍTICO',
          'isp': isp,
          'accion': 'BLOQUEAR',
          'class': 'table-danger',
      }
    elif score >= 25:
      return {
          'ip': ip_str,
          'nivel': 'ALTO',
          'isp': isp,
          'accion': 'REVISAR',
          'class': 'table-warning',
      }
    else:
      return {
          'ip': ip_str,
          'nivel': 'BAJO',
          'isp': isp,
          'accion': 'ALLOW',
          'class': 'table-success',
      }
  except:
    return {
        'ip': ip_str,
        'nivel': 'DOWN',
        'isp': 'API ERROR',
        'accion': 'REINTENTAR',
        'class': '',
    }


@app.route('/', methods=['GET', 'POST'])
def index():
  results = []
  if request.method == 'POST':
    raw_ips = request.form.get('ips', '').splitlines()
    unique_ips = list(set([ip.strip() for ip in raw_ips if ip.strip()]))
    results = [analyze_ip(ip) for ip in unique_ips]
  return render_template('index.html', results=results)


if __name__ == '__main__':
  app.run(debug=True, port=5000)

#http://127.0.0.1:5000