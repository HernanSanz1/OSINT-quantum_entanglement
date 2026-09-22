# 🛠 Manual del Desarrollador — OSINT Framework v2

> Guía de arquitectura, seguridad, convenciones y extensión del sistema.

---

## 1. Estructura del proyecto

```
IAprototipe/
├── osint_app/
│   ├── core/
│   │   ├── models.py          # Dataclasses: Case, ToolReport, TargetData, AICorrelation…
│   │   └── base_tool.py       # OSINTTool — interfaz abstracta para todas las tools
│   ├── utils/
│   │   ├── sanitizer.py       # ★ Sanitización: shell, SSRF, DB, snippets
│   │   ├── secret_vault.py    # ★ API keys seguro en ~/.osint_v2_keys (chmod 600)
│   │   ├── tool_checker.py    # Verificación e instalación de dependencias
│   │   ├── compatibility.py   # DataCompatibilityEngine — score de compatibilidad tool↔case
│   │   ├── entity_extractor.py # Regex extractor de entidades (emails, IPs, dominios…)
│   │   ├── resource_monitor.py # CPU/RAM monitor
│   │   └── cache.py / rate_limiter.py
│   ├── db/
│   │   └── feedback_db.py     # SQLite: cases, target_data, tool_reports, ai_correlations
│   ├── tools/
│   │   ├── google_dorks.py    # Google Dorks (requests)
│   │   ├── hunter.py          # Hunter.io API
│   │   ├── social_tools.py    # Sherlock, Holehe, GHunt, snscrape
│   │   ├── network_tools.py   # ★ dnspython, ipwhois, CENSYS, TheHarvester, Wayback, phone
│   │   ├── heavy_tools.py     # ★ Subfinder, AMASS, SpiderFoot, Recon-ng, sn0int, Maigret
│   │   ├── threat_intel.py    # IntelOwl, OpenCTI, MISP, Cortex, IntelMQ
│   │   └── __init__.py        # TOOL_REGISTRY — instancia cualquier tool por nombre
│   ├── gui/
│   │   ├── app.py             # ★ Shell principal — Sentinel palette + Tool Checker popup
│   │   ├── tab_cases.py       # Tab casos — CRUD
│   │   ├── tab_data.py        # Tab datos objetivos
│   │   ├── tab_tools.py       # Tab herramientas — cards con indicadores compatibilidad
│   │   ├── tab_reports.py     # Tab reportes — export JSON/HTML
│   │   └── tab_ai.py          # Tab IA — Triple-Brain view + chat
│   ├── llm_brains.py          # ★ OllamaBrain, OpenAIBrain, VeniceBrain
│   ├── ai_engine.py           # ★ MultiLLMEngine — análisis paralelo + consenso
│   ├── framework.py           # OSINTFramework — ejecución secuencial de tools
│   ├── case_manager.py        # CaseManager — CRUD de casos
│   └── reports/
│       └── html_report.py     # Generador HTML dark
├── docs/
│   ├── MANUAL_USUARIO.md
│   └── MANUAL_DESARROLLADOR.md
├── .gitignore                 # ★ Protege DB, keys, cache de git
└── requirements.txt
```

★ = Archivos modificados en la v2 Sentinel Edition

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

## 4. Paleta Sentinel (GUI)

```python
# osint_app/gui/app.py — importar SP
from .app import SP   # dict con todos los colores

SP = {
    "bg":       "#0d1117",   # fondo principal
    "surface":  "#161b22",   # superficies/cards
    "elevated": "#21262d",   # inputs, botones
    "border":   "#30363d",   # bordes
    "text":     "#e6edf3",   # texto principal
    "muted":    "#8b949e",   # texto secundario
    "accent":   "#58a6ff",   # azul Sentinel — acciones primarias
    "success":  "#3fb950",   # verde
    "warning":  "#d29922",   # ámbar
    "danger":   "#f85149",   # rojo
    "purple":   "#bc8cff",   # cerebro Venice
}
```

Para usar en widgets:
```python
tk.Label(parent, bg=SP["surface"], fg=SP["accent"], text="Título")
ttk.Button(parent, style="Accent.TButton", text="Acción primaria")
ttk.Button(parent, style="Danger.TButton",  text="Eliminar")
ttk.Button(parent, style="Success.TButton", text="Guardar")
```

---

## 5. Base de datos (SQLite)

La DB se guarda en `osint_app/data/osint_v2.db` (ignorada por `.gitignore`).

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

La aplicación **no levanta ningún servidor**. Todas las conexiones son **salientes**:
- Ollama: `http://localhost:11434` — solo accesible localmente
- VeniceBrain: `https://api.venice.ai` — saliente, autenticado con Bearer token
- OpenAIBrain: `https://api.openai.com` — saliente, autenticado con Bearer token

Para verificar en tiempo real:
```bash
lsof -i -P | grep LISTEN
```

Si en el futuro se agrega un endpoint HTTP (Flask/FastAPI):
- Usar HTTPS obligatoriamente
- Agregar autenticación (JWT o API key con Bearer)
- Documentarlo aquí con el port y scope
