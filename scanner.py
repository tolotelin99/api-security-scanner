import urllib.request
import urllib.error
import ssl

objetivo = "https://httpbin.org/get"
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
        # Construimos una petición forzando un método específico
        peticion = urllib.request.Request(objetivo, method=metodo)
        respuesta = urllib.request.urlopen(peticion, context=contexto_ssl)
        print(f"   [+] {metodo}: ABIERTO (Código {respuesta.getcode()})")
    except urllib.error.HTTPError as error_http:
        # El código 405 significa "Method Not Allowed" (Método bloqueado correctamente)
        if error_http.code == 405:
            print(f"   [-] {metodo}: BLOQUEADO (405 Not Allowed)")
        else:
            # Otros códigos (como 401, 403, 500) podrían indicar que el método existe
            print(f"   [?] {metodo}: ESTADO {error_http.code}")
    except Exception as e:
        print(f"   [!] {metodo}: ERROR DE CONEXIÓN")