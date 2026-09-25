import argparse
import random
import socket
import sys
import time
import requests

# Desactivar advertencias de SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Dejamos tus rutas originales y agregamos la raíz "/"
COMMON_PATHS = [
    "/",
    "/flmngr",
    "/sites/default/files/flmngr",
    "/admin/config/content/n1ed"
]

def network_recon(domain_or_ip):
    print("\n========================================")
    print("      MÓDULO DE RECONOCIMIENTO (RECON)   ")
    print("========================================")
    clean_target = domain_or_ip.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        print(f"[*] Resolviendo dirección IP para: {clean_target}")
        ip_address = socket.gethostbyname(clean_target)
        print(f"    [+] Dirección IP principal: {ip_address}")
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            print(f"    [+] Hostname asociado (Lookup inverso): {hostname}")
        except socket.herror:
            print("    [-] Lookup inverso no disponible.")
    except socket.gaierror as e:
        print(f"    [-] Error DNS/IP: {e}")
    print("-" * 50)

def evasive_request(url, method, headers, payload=None):
    headers["User-Agent"] = random.choice(USER_AGENTS)
    time.sleep(random.uniform(0.3, 1.0))
    try:
        if method == "OPTIONS":
            return requests.options(url, headers=headers, timeout=5, verify=False)
        elif method == "GET":
            return requests.get(url, headers=headers, timeout=5, verify=False)
        elif method == "POST":
            return requests.post(url, headers=headers, json=payload, timeout=5, verify=False)
    except requests.exceptions.RequestException:
        return None

def audit_security_headers(headers, url):
    """Módulo nuevo: Analiza la seguridad de las cabeceras HTTP"""
    print(f"\n    [+] Auditando cabeceras de seguridad para: {url}")
    security_headers = {
        "Strict-Transport-Security": "Fuerza HTTPS",
        "X-Frame-Options": "Protege contra Clickjacking",
        "X-Content-Type-Options": "Evita MIME-sniffing",
        "Content-Security-Policy": "Previene XSS",
    }
    headers_lower = {k.lower(): v for k, v in headers.items()}
    score = 0
    for header, description in security_headers.items():
        if header.lower() in headers_lower:
            print(f"        [V] {header}: PRESENTE")
            score += 1
        else:
            print(f"        [X] {header}: AUSENTE - {description}")
    print(f"        [*] Puntuación: {score}/{len(security_headers)}")

def comprehensive_scan(base_url, api_key=None):
    headers = {
        "Referer": base_url,
        "Origin": base_url,
        "Content-Type": "application/json",
        "X-Forwarded-For": "192.168.1.100",
    }
    payload = {"key": api_key} if api_key else None
    base_url = base_url.rstrip("/")

    print("\n========================================")
    print("    ESCÁNER DE VULNERABILIDADES Y FUZZER  ")
    print("========================================")
    print(f"[*] Objetivo base: {base_url}")
    print("=" * 50)

    for path in COMMON_PATHS:
        target_url = f"{base_url}{path}"
        print(f"\n[->] Analizando ruta: {target_url}")

        # OPTIONS
        res_opt = evasive_request(target_url, "OPTIONS", headers)
        if res_opt is not None:
            allowed = res_opt.headers.get("Allow", "No especificado")
            print(f"    [i] OPTIONS Status: {res_opt.status_code} | Métodos: {allowed}")

        # GET (Con el bug de Python arreglado)
        res_get = evasive_request(target_url, "GET", headers)
        if res_get is not None:
            print(f"    [i] GET Status: {res_get.status_code}")
            if res_get.status_code == 200:
                print(f"        [!] Endpoint accesible por GET: {target_url}")
                audit_security_headers(res_get.headers, target_url)

        # POST (Con el bug de Python arreglado)
        res_post = evasive_request(target_url, "POST", headers, payload)
        if res_post is not None:
            print(f"    [i] POST Status: {res_post.status_code}")

        print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description="ApiSecurityScanner Suite Pro v5.3")
    parser.add_argument("-u", "--url", required=True, help="URL objetivo")
    parser.add_argument("-k", "--key", required=False, default=None, help="API Key")
    parser.add_argument("--recon", action="store_true", help="Reconocimiento de red")
    args = parser.parse_args()

    print("==================================================")
    print("    API SECURITY SCANNER SUITE - EDG v5.3       ")
    print("==================================================")

    if args.recon:
        network_recon(args.url)

    comprehensive_scan(args.url, args.key)

if __name__ == "__main__":
    main()