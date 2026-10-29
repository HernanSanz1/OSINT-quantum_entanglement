# SENTINEL — OSINT Framework v2

Aplicación de escritorio para investigaciones OSINT de un SOC: reúne fuentes abiertas, perfila a figuras públicas, cruza cada caso con la inteligencia de amenazas (CTI) y genera fichas, informes y boletines legibles para personas no técnicas.

- **Plataforma:** Windows 10/11 (probado en Windows 11). Linux y Mac aún no están soportados del todo.
- **Lenguaje:** Python 3.12+ con interfaz PySide6 (Qt).
- **Licencia:** MIT (ver [LICENSE](LICENSE)).

## Qué hace

La ventana tiene siete pestañas:

| Pestaña | Para qué sirve |
|---|---|
| **Casos** | Crear, abrir y organizar investigaciones. Todo lo demás se guarda en el caso abierto. |
| **Datos** | Añadir los datos del objetivo (dominio, IP, correo, usuario, nombre…). El tipo se detecta solo y se valida. |
| **Herramientas** | Lanzar cada herramienta OSINT sobre los datos del caso, ver su estado y su guía de instalación, y guardar claves de API. |
| **Perfilamiento** | Buscar a una persona pública con varias herramientas a la vez, revisar candidatos (confirmar o descartar), separar homónimos y generar la ficha en HTML o PDF. |
| **Correlación** | Relacionar los datos del caso entre sí y con otros casos, y cruzarlos con el CTI: víctima de ransomware, noticias que lo citan, IP en avisos y tecnologías con vulnerabilidades (con EPSS). |
| **CTI** | Recoger noticias y vulnerabilidades (CISA KEV, Microsoft, EcuCERT, CSIRT Telconet…) y generar el boletín semanal, general o para un cliente. |
| **Reportes** | Leer el resultado de cada herramienta en lenguaje claro (o el JSON técnico). |

### Herramientas incluidas

- **Sin instalar nada:** búsqueda web multibuscador, Google Dorks, Wikidata (ficha y cuentas oficiales de personas públicas), GitHub, variantes de usuario, crt.sh (subdominios desde 4 fuentes públicas), Domain WHOIS, DNS, IP/ASN, IP Reputation, Wayback Machine, Mail Health (SPF, DMARC), Tech Detect, Link Shield, metadatos de archivos y análisis de teléfonos.
- **Paquetes de Python** (se instalan con `requirements.txt` o aparte): Sherlock, Maigret, Holehe e Instaloader.
- **Con clave de API:** Hunter.io, CENSYS y token de GitHub (opcional, sube el límite de consultas).
- **Externas** (cada una con su guía en la pestaña Herramientas): Subfinder, OWASP Amass, TheHarvester, SpiderFoot y Recon-ng.
- **Plataformas de CTI con servidor** (MISP, OpenCTI, IntelOwl, Cortex, IntelMQ): todavía en desarrollo.

Para ver qué está listo en tu equipo:

```powershell
env\Scripts\python.exe -m osint_app.main --check-tools
```

## Instalación (Windows)

Necesitas [Python 3.12](https://www.python.org/downloads/) y [Git](https://git-scm.com/download/win). En PowerShell:

```powershell
# 1. Descargar el código
git clone https://github.com/HernanSanz1/OSINT-quantum_entanglement.git
cd OSINT-quantum_entanglement

# 2. Crear el entorno de Python del proyecto
py -3.12 -m venv env

# 3. Instalar las dependencias
env\Scripts\python.exe -m pip install -r osint_app\requirements.txt

# 4. Abrir SENTINEL
env\Scripts\python.exe -m osint_app.main
```

Se usa siempre `env\Scripts\python.exe` (sin "activar" el entorno). Así funciona también con el Control inteligente de aplicaciones (Smart App Control) de Windows 11, que bloquea los `.exe` sin firma que crean algunos paquetes.

### Claves de API

Las claves **nunca** se escriben en el código, en archivos de texto ni en los commits. Cada persona guarda las suyas:

- **Desde la ventana:** pestaña Herramientas → elige la herramienta → «Verificar Estado» → «🔑 Guardar clave».
- **Desde la consola** (la pide sin mostrarla):

```powershell
env\Scripts\python.exe -m osint_app.main --set-key Hunter.io
env\Scripts\python.exe -m osint_app.main --keys
```

`--keys` muestra qué claves están configuradas, nunca su valor. Se guardan cifradas con DPAPI de Windows: solo tu usuario, en tu equipo, puede leerlas.

### Buscador propio (opcional): SearXNG en Docker

Los buscadores públicos bloquean las búsquedas automáticas a menudo. Con un SearXNG propio la búsqueda web es más completa y rápida (medido: 94 resultados relevantes en 21 s frente a 74 en 49 s).

1. Instala [Docker Desktop](https://www.docker.com/products/docker-desktop/) y espera a que diga «Engine running».
2. Ejecuta:

```powershell
env\Scripts\python.exe scripts\searxng_local.py start
```

El contenedor `sentinel-searxng` escucha solo en `127.0.0.1:8888`. También existen `status` y `stop`. Sin Docker, SENTINEL sigue funcionando con los buscadores de respaldo y avisa de que SearXNG no responde.

Si un perfil termina con la búsqueda web **incompleta** (bloqueos), el botón «🔁 Reintentar búsquedas fallidas» repite solo las consultas que fallaron.

## Dónde se guardan las cosas

Nada de lo que produces se guarda dentro del proyecto:

| Qué | Dónde |
|---|---|
| Casos (base SQLite `osint_v2.db`) | `%LOCALAPPDATA%\SENTINEL\` |
| Fichas, PDF y exportaciones | `%LOCALAPPDATA%\SENTINEL\informes\` (carpeta solo para tu usuario). Se abre desde Perfilamiento → Generar Ficha → Abrir la carpeta de informes. |
| Noticias CTI, dossiers y boletines | `%LOCALAPPDATA%\SENTINEL\cti\` |
| Configuración de SearXNG | `%LOCALAPPDATA%\SENTINEL\searxng\` |
| Programas externos (`subfinder.exe`, `amass.exe`) | `%LOCALAPPDATA%\SENTINEL\bin\` |
| Herramientas descargadas con su código (TheHarvester, SpiderFoot, Recon-ng) | `%LOCALAPPDATA%\SENTINEL\herramientas\` |
| Claves de API | Baúl cifrado en tu carpeta personal |

La carpeta de datos se puede cambiar con la variable de entorno `SENTINEL_DATA_DIR`.

## Para desarrolladores

```powershell
# Tests (sin red; unos 1.070)
env\Scripts\python.exe -m pytest osint_app/tests -q -p no:cacheprovider

# Pruebas con objetivos reales (usa internet)
env\Scripts\python.exe scripts\auditoria_real.py
```

GitHub Actions ejecuta los tests en Windows y Ubuntu con Python 3.12 y 3.14, y revisa el Markdown modificado.

```text
OSINT-quantum_entanglement/
├── osint_app/              Aplicación
│   ├── gui/                Ventana y pestañas (PySide6)
│   ├── tools/              Herramientas OSINT (una clase por herramienta)
│   ├── reports/            Ficha de persona, informes y vista legible
│   ├── db/                 Base SQLite (casos, informes, veredictos)
│   ├── utils/              Búsqueda web, homónimos, rutas de datos, baúl de claves…
│   ├── tests/              Tests (pytest)
│   ├── profiler_engine.py  Motor de perfilamiento
│   ├── correlation_engine.py
│   └── cti_link.py, cti_match.py   Cruce de casos con el CTI
├── sentinel_unified/modules/cti/   Recolección CTI, dossier y boletín
├── scripts/                SearXNG local, auditoría real, métricas CTI
├── deploy/searxng/         Plantilla de configuración de SearXNG
└── docs/                   Manuales y guía de cada herramienta (docs/tools/)
```

Más documentación:

- [Manual de usuario](docs/MANUAL_USUARIO.md) y [manual de desarrollador](docs/MANUAL_DESARROLLADOR.md).
- [Guía de cada herramienta](docs/tools/README.md).
- [Arquitectura](ARCHITECTURE.md) y [cómo contribuir](CONTRIBUTING.md).
- [Traspaso del proyecto](PARA_PAUL_Y_SU_CLAUDE.md): decisiones, historial y pendientes.

## Uso responsable y seguridad

- SENTINEL está pensado para investigaciones autorizadas con fuentes abiertas.
- Si encuentras una vulnerabilidad en SENTINEL, sigue la [política de reporte de fallos](POLICIE.md) y no la publiques antes de que se corrija.
