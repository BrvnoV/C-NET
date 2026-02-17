import requests
import pandas as pd
import time
import os
import ipaddress
import socket
from datetime import datetime

# --- [ SENIOR SECURITY CONFIG ] ---
API_KEY = os.getenv('ABUSEIPDB_KEY')

# Lista de Dominios C2 e IOCs Críticos (Basado en Intel de hoy 17/Feb)
# Incluye dominios de SmartLoader, ClickFix y malware macOS
MALICIOUS_DOMAINS = {
    'raxelpak.com', 'azwsappdev.com', 'testdomain123123.shop', 
    'mcp-market.com', 'oura-mcp-server.xyz', 'lumma-c2-portal.net'
}

class IPThreatAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
            'Accept': 'application/json',
            'Key': self.api_key,
            'User-Agent': 'Security-C2-Hunter/3.5'
        }

    def get_reverse_dns(self, ip):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname.lower()
        except:
            return "no-rdns-record"

    def evaluate_threat(self, ip):
        sanitized_ip = self._sanitize_ip(ip)
        if not sanitized_ip: return None

        rdns_name = self.get_reverse_dns(sanitized_ip)
        
        # --- [ NUEVA CAPA: C2 DOMAIN MATCH ] ---
        # Si el hostname del rDNS coincide con un dominio malicioso conocido
        c2_match = any(domain in rdns_name for domain in MALICIOUS_DOMAINS)

        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': sanitized_ip, 'maxAgeInDays': '90'}
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=12)
            data = response.json()['data']
            conf = data.get('abuseConfidenceScore', 0)
            
            # --- [ LÓGICA DE SCORE ESTRICA ] ---
            base_score = conf
            
            # Si hay coincidencia con dominio C2, el score es 100 automático (BLOQUEO)
            if c2_match:
                base_score = 100
                level, action = "💀 C2 CONFIRMADO", "🔴 BLOQUEO INMEDIATO / AISLAR"
            elif base_score >= 80:
                level, action = "CRÍTICO", "🔴 BLOQUEAR / DROP"
            elif base_score >= 45:
                level, action = "ALTO", "🟠 INVESTIGAR"
            else:
                level, action = "BAJO", "🟢 ALLOW"

            return {
                "IP": sanitized_ip,
                "Hostname": rdns_name,
                "Nivel": level,
                "Score_Reputacion": base_score,
                "C2_Match": "SÍ" if c2_match else "NO",
                "Acción": action,
                "ISP": data.get('isp', 'N/A'),
                "Analyst_Note": f"ALERT: Dominio C2 detectado!" if c2_match else "Análisis estándar"
            }
        except Exception:
            return None

    def _sanitize_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(str(ip).strip())
            return None if ip_obj.is_private else str(ip_obj)
        except: return None

def run_security_scan(ip_list):
    analyzer = IPThreatAnalyzer(API_KEY)
    results = [analyzer.evaluate_threat(ip) for ip in set(ip_list) if analyzer.evaluate_threat(ip)]
    
    if results:
        df = pd.DataFrame(results).sort_values(by="Score_Reputacion", ascending=False)
        df.to_excel(f"SOC_C2_Report_{datetime.now().strftime('%Y%m%d')}.xlsx", index=False)
        print("\n🏆 RESULTADOS CRÍTICOS:")
        print(df[df['Score_Reputacion'] >= 80][['IP', 'Hostname', 'Acción']])

if __name__ == "__main__":
    # Agrega aquí tus IPs capturadas hoy
    ips_de_hoy = [] 
    run_security_scan(ips_de_hoy)