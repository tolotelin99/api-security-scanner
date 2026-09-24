import urllib.request
import urllib.error
from urllib.parse import urlparse
import ssl
import argparse
import sys

# --- CONFIGURACIÓN DE ARGUMENTOS DE CONSOLA ---
parser = argparse.ArgumentParser(description="API Security Scanner - Herramienta de Reconocimiento")
parser.add_argument("-u", "--url", help="URL objetivo a escanear (ej. https://ejemplo.com)", required=True)

# Mostrar menú de ayuda si el usuario no ingresa parámetros
if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

args = parser.parse_args()
objetivo = args.url
contexto_ssl = ssl._create_unverified_context()

print(f"[*] Iniciando auditoría en: {objetivo}\n")

# --- FASE 1: ESCANEO DE HEADERS ---
print("[*] FASE 1: Extracción de Headers...")
try:
    respuesta = urllib.request.urlopen(objetivo, context=contexto_ssl)
    for header, valor in respuesta.headers.items():
        print(f"   - {header}: {valor}")
except Exception as e:
    print(f"   [!] Error al obtener headers: {e}")

# --- FASE 2: DETECCIÓN DE MÉTODOS HTTP ---
print("\n[*] FASE 2: Probando métodos HTTP...")
metodos = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]

for metodo in metodos:
    try:
        peticion = urllib.request.Request(objetivo, method=metodo)
        respuesta = urllib.request.urlopen(peticion, context=contexto_ssl)
        print(f"   [+] {metodo}: ABIERTO (Código {respuesta.getcode()})")
    except urllib.error.HTTPError as error_http:
        if error_http.code == 405:
            print(f"   [-] {metodo}: BLOQUEADO (405 Not Allowed)")
        else:
            print(f"   [?] {metodo}: ESTADO {error_http.code}")
    except Exception as e:
        print(f"   [!] {metodo}: ERROR DE CONEXIÓN")

# --- FASE 3: BÚSQUEDA DE RUTAS SENSIBLES (FUZZING) ---
print("\n[*] FASE 3: Buscando rutas sensibles...")

parsed_url = urlparse(objetivo)
base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

rutas_comunes = [
    "/admin",
    "/api/v1",
    "/.env",
    "/swagger.json",
    "/robots.txt",
    "/backup.zip",
    "/config.php"
]

for ruta in rutas_comunes:
    url_prueba = base_url + ruta
    try:
        req = urllib.request.Request(url_prueba, method="GET")
        resp = urllib.request.urlopen(req, context=contexto_ssl)
        print(f"   [!] ALERTA CRÍTICA: Ruta expuesta -> {url_prueba} (Código 200)")
    except urllib.error.HTTPError as e:
        if e.code in [401, 403]:
            print(f"   [+] Ruta protegida detectada: {url_prueba} (Código {e.code})")
        elif e.code == 404:
            pass
        else:
            print(f"   [?] Estado {e.code}: {url_prueba}")
    except Exception:
        pass