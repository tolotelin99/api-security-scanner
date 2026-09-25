# API-Security-Scanner (v5.3)

Escáner automatizado desarrollado en Python, orientado a las fases de reconocimiento (Recon) y enumeración en auditorías de seguridad de APIs y aplicaciones web.

La herramienta proporciona a los analistas una evaluación detallada de la superficie de ataque mediante técnicas de sondeo activo y evasión de firewalls.

## Características Principales

* **Análisis de Reconocimiento de Red (Recon):** Resolución DNS para descubrir la IP real detrás de un dominio y búsquedas de lookup inverso.
* **Motor de Evasión (Anti-IDS/WAF):** Rotación dinámica de User-Agents y retrasos (jitter) aleatorios para evadir bloqueos temporales por firewalls de aplicaciones web.
* **Auditoría de Cabeceras Defensivas:** Análisis de la respuesta del servidor en busca de configuraciones críticas de seguridad (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) y asignación de un puntaje de seguridad basado en estándares de OWASP.
* **Sondeo Activo de Métodos:** Evaluación automatizada de los métodos HTTP permitidos (OPTIONS) y pruebas de interacción mediante peticiones GET y POST.
* **Fuzzing de Rutas Estratégicas:** Búsqueda activa de directorios críticos, paneles de administración y componentes expuestos mediante rutas integradas.

## Especificaciones Técnicas

* **Lenguaje:** Python 3.x
* **Dependencias Externas:** `requests`, `urllib3`

## Instalación y Despliegue

Clonar el repositorio en el entorno local e instalar las dependencias de red necesarias:

```bash
# 1. Clonar el repositorio
git clone [https://github.com/tolotelin99/api-security-scanner.git](https://github.com/tolotelin99/api-security-scanner.git)

# 2. Acceder al directorio
cd api-security-scanner

# 3. Instalar dependencias
pip install requests urllib3