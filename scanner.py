import urllib.request
import ssl

# Definimos la URL a escanear
objetivo = "https://httpbin.org/get"

print(f"[*] Iniciando escaneo de Headers en: {objetivo}")

# Ignoramos la validación del certificado (útil en ciberseguridad)
contexto_ssl = ssl._create_unverified_context()

# Hacemos la petición
respuesta = urllib.request.urlopen(objetivo, context=contexto_ssl)

print("[+] Headers detectados:")
# Extraemos y mostramos los headers
for header, valor in respuesta.headers.items():
    print(f"   - {header}: {valor}")