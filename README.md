# API-Security-Scanner

Escáner automatizado desarrollado en Python, orientado a la fase de reconocimiento (Recon) y enumeración en auditorías de seguridad de APIs y aplicaciones web.

La herramienta proporciona a los analistas una evaluación rápida de la superficie de ataque mediante tres fases de sondeo activo.

## Características Principales

* Fase 1 | Análisis de Headers HTTP: Extracción de cabeceras de respuesta para identificar el software subyacente y auditar configuraciones de seguridad (CORS, Information Disclosure).
* Fase 2 | Sondeo Activo de Métodos: Evaluación automatizada de métodos HTTP (GET, POST, PUT, DELETE, OPTIONS, PATCH) mediante el análisis de códigos de estado para detectar vectores de interacción expuestos.
* Fase 3 | Fuzzing de Rutas Sensibles: Búsqueda activa de directorios críticos y archivos de configuración (ej. `/.env`, `/admin`, `/robots.txt`) utilizando diccionarios predefinidos.

## Especificaciones Técnicas

* Lenguaje: Python 3.x
* Dependencias: Librería estándar de Python (`urllib`, `ssl`). Arquitectura "Zero-Dependencies", no requiere instalación de paquetes de terceros mediante `pip`.

## Instalación y Despliegue

Clonar el repositorio en el entorno local y ejecutar el script principal desde la terminal:

```bash
# 1. Clonar el repositorio
git clone [https://github.com/tolotelin99/api-security-scanner.git](https://github.com/tolotelin99/api-security-scanner.git)

# 2. Acceder al directorio
cd api-security-scanner

# 3. Ejecutar la herramienta
python scanner.py -u https://httpbin.org/get