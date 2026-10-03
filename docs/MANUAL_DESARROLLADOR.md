# 🛠 Manual del Desarrollador — OSINT Framework v2

> Guía de arquitectura, seguridad, convenciones y extensión del sistema.

---

## 1. Estructura del proyecto

```
OSINT-quantum_entanglement/
├── conftest.py                 # pytest: carpeta de datos TEMPORAL (los tests nunca tocan los casos reales)
├── osint_app/
│   ├── main.py                 # entrada: GUI, --check-tools, --keys, --set-key
│   ├── framework.py            # OSINTFramework — ejecuta una herramienta sobre un caso
│   ├── profiler_engine.py      # ★ Perfilamiento de personas: semilla, rondas, candidatos, confirmar/refinar
│   ├── correlation_engine.py   # ★ Entidades y relaciones entre los datos de un caso
│   ├── cti_link.py             # Cruce de lo hallado con el CTI
│   ├── case_manager.py         # CRUD de casos
│   ├── core/
│   │   ├── models.py           # Case, TargetData, ToolReport, SearchResult, QueryParameters…
│   │   └── base_tool.py        # OSINTTool — interfaz de todas las herramientas
│   ├── db/
│   │   └── feedback_db.py      # SQLite: cases, target_data, tool_reports, data_extracts
│   ├── tools/                  # una herramienta por archivo (ver docs/tools/)
│   │   ├── web_search.py       # WebSearch, GitHubOSINT, UsernameVariants
│   │   ├── google_dorks.py, hunter.py, social_tools.py, network_tools.py, heavy_tools.py, threat_intel.py
│   │   ├── crtsh.py, domain_whois.py, mail_health.py, tech_detect.py, wayback.py
│   │   ├── file_metadata.py    # EXIF / PDF / Office
│   │   └── link_shield.py      # riesgo de URLs
│   ├── utils/
│   │   ├── sanitizer.py        # ★ sanitización de entradas, SSRF, texto
│   │   ├── secret_vault.py     # ★ claves de API (cifradas con DPAPI en Windows)  +  key_cli.py, dpapi.py
│   │   ├── data_paths.py       # ★ dónde van los datos y la migración segura de la base
│   │   ├── identity.py         # perfiles sociales, nombres y su relación con usuarios y correos
│   │   ├── person_match.py     # comparar nombres, teléfonos, usuarios y URLs (sin tildes ni orden)
│   │   ├── homonyms.py, geo_data.py  # señales de posible homónimo
│   │   ├── directories.py      # listados de personas que no son candidatos
│   │   ├── entity_filters.py, entity_extractor.py, tlds.txt  # extracción de entidades sin ruido
│   │   └── compatibility.py, cache.py, rate_limiter.py, resource_monitor.py, tool_checker.py
│   ├── gui/                    # PySide6: app.py, tab_cases/data/tools/profiling/correlation/cti/reports.py, style.qss
│   ├── reports/html_report.py
│   └── tests/                  # pytest, sin red ni base real
├── sentinel_unified/modules/cti/   # módulos CTI (recolección, dossiers)
├── docs/                       # manuales, fichas de herramientas (docs/tools/) y REVISION_PROYECTO.md
└── osint_app/requirements.txt
```

★ = piezas centrales. La carpeta `osint_app/ai/` y `smart_profiler.py` se eliminaron: la IA ya no forma parte del
proyecto y su lógica útil se rescató en `UsernameVariants`, `identity.py` y `person_match.py`.

---

## 2. Agregar una nueva herramienta

### Paso 1 — Crear la clase

```python
# osint_app/tools/mi_nueva_tool.py
from ..core.base_tool import OSINTTool
from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..utils.sanitizer import sanitize_shell_arg, sanitize_snippet, validate_domain
from typing import List

class MiNuevaTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "MiTool", "Descripción corta",
            ToolRequirements(
                mandatory=["domain"],    # datos REQUERIDOS del caso
                optional=["email"],      # datos opcionales que mejoran los resultados
                produces=["ip", "url"],  # qué extrae esta tool
                hint="Necesita un dominio.",
            )
        )
        self.requires_api_key = True   # si necesita API key
        self.is_heavy = False          # True = binario externo

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        # ★ SIEMPRE sanitizar inputs
        domain = sanitize_shell_arg(query_params.domain or "")
        if not domain or not validate_domain(domain):
            return []
        
        # ... lógica de la herramienta ...
        
        return [SearchResult(
            title="Resultado",
            url="https://...",
            snippet=sanitize_snippet("..."),
            source_tool=self.name,
            category="Network",
            relevance_score=70,
        )]
```

### Paso 2 — Registrar en el registry

```python
# osint_app/tools/__init__.py
from .mi_nueva_tool import MiNuevaTool

TOOL_REGISTRY = {
    ...
    "MiTool": MiNuevaTool,
}
```

---

## 3. Reglas de seguridad (OBLIGATORIAS)

### 3.1 Sanitización de inputs

```python
# ✅ CORRECTO — siempre sanitizar antes de subprocess o network
from ..utils.sanitizer import sanitize_shell_arg, validate_domain

domain = sanitize_shell_arg(query_params.domain)
if not validate_domain(domain):
    return []
subprocess.run(["mi-tool", "-d", domain], ...)   # list, no shell=True

# ❌ INCORRECTO — nunca esto
subprocess.run(f"mi-tool -d {query_params.domain}", shell=True)  # INYECCIÓN
```

### 3.2 API Keys

Las claves se guardan con `python -m osint_app.main --set-key NOMBRE` (la pide oculta; nunca como argumento) y, en Windows, cifradas con DPAPI.

```python
# ✅ CORRECTO — usar SecretVault
from ..utils.secret_vault import vault
api_key = vault.get("MiServicio")

# ❌ INCORRECTO — nunca hardcodear ni guardar en el projeto
api_key = "sk-abc123..."           # HARDCODED = CRÍTICO
config = json.loads("osint_config.json")["api_key"]  # plaintext en repo
```

### 3.3 Subprocess

```python
# ✅ CORRECTO
subprocess.run(["cmd", arg1, arg2], capture_output=True, timeout=300)

# ❌ NUNCA
subprocess.run("cmd " + user_input, shell=True)   # INYECCIÓN DE COMANDOS
os.system("cmd " + user_input)                     # INYECCIÓN DE COMANDOS
```

### 3.4 Límites de output

```python
# ✅ SIEMPRE limitar el output de subprocesses
MAX_OUTPUT_BYTES = 2_000_000
out = proc.stdout[:MAX_OUTPUT_BYTES]

# ✅ SIEMPRE limitar resultados
MAX_RESULTS = 200
for line in out.splitlines()[:MAX_RESULTS]:
    ...
```

### 3.5 HTTP / SSRF

```python
# ✅ CORRECTO — validar URLs antes de llamadas HTTP
from ..utils.sanitizer import validate_ssrf
if not validate_ssrf(url):
    return []
requests.get(url, timeout=20)

# ✅ SIEMPRE usar HTTPS
requests.get("https://...", timeout=20)   # no http://

# ❌ INCORRECTO
requests.get(user_url)                    # SSRF sin validación
requests.get("http://...")                # sin TLS
```

---

## 4. Interfaz gráfica (GUI)

La interfaz es **PySide6 (Qt)**. Los estilos están en `osint_app/gui/style.qss`; `gui/sentinel_theme.py` solo conserva
funciones vacías por compatibilidad. Cada pestaña es un `QWidget` en `osint_app/gui/tab_*.py` y se registra en
`OSINTGUI.pages` (`gui/app.py`).

Las pruebas que abren Qt solo corren en Windows o con `SENTINEL_GUI_TESTS=1` (abrir Qt en un servidor Linux sin
librerías gráficas puede abortar todo el proceso de pytest).

---

## 5. Base de datos (SQLite)

La DB se guarda **fuera del proyecto**: en Windows `%LOCALAPPDATA%\SENTINEL\osint_v2.db` (o `SENTINEL_DATA_DIR`). Ver `utils/data_paths.py`: la versión anterior la guardaba en `osint_app/data/` y se migra por copia sin borrar el original.

```python
from ..db.feedback_db import db   # singleton global

# Crear caso
case_id = db.create_case(Case(name="Caso1", ...))

# Guardar reporte
report_id = db.save_report(ToolReport(case_id=case_id, ...))

# Leer reportes del caso
reports = db.get_reports(case_id)
```

**Reglas:**
- Siempre usar queries parametrizadas (`?`) — nunca f-strings en SQL
- Truncar texto con `sanitize_db_text(text)` antes de `raw_json`
- Evitar writes sin transacción en loops grandes

---

## 6. Tests

```bash
# Sintaxis
python3 -c "import ast, os; [ast.parse(open(os.path.join(r,f)).read()) for r,_,fs in os.walk('osint_app') for f in fs if f.endswith('.py')]"

# Imports
python3 -m pytest osint_app/ -x --timeout=10

# Security scan
python3 -m bandit -r osint_app/ -ll
```

---

## 7. Puertos abiertos / exposición de red

**Estado actual:** ✅ **Sin puertos abiertos**

La aplicación **no levanta ningún servidor**. Todas las conexiones son **salientes**, hacia fuentes públicas
(buscadores, GitHub, registros RDAP, DNS, crt.sh, Wayback…) y hacia los servicios que tengan clave (Hunter.io, CENSYS…).
`Link Shield` y `File Metadata` bloquean destinos locales y privados y validan cada redirección.

Para verificar en tiempo real:
```bash
lsof -i -P | grep LISTEN
```

Si en el futuro se agrega un endpoint HTTP (Flask/FastAPI):
- Usar HTTPS obligatoriamente
- Agregar autenticación (JWT o API key con Bearer)
- Documentarlo aquí con el port y scope
