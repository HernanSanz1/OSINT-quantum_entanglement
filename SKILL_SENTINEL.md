# Skill: SENTINEL OSINT + CTI

Plataforma unificada de inteligencia: perfilamiento de personas, reconocimiento de infraestructura (EAMS), y Cyber Threat Intelligence.

## Perfilamiento Inteligente (SmartProfiler)

El SmartProfiler hace correlación automática: solo guarda datos que coincidan con el objetivo.

```python
from osint_app.smart_profiler import smart_profile

# Buscar persona con contexto
result = smart_profile(
    name='Juan Riofrio',
    context='UDLA Ecuador nacido 2006',  # El año ayuda a generar variantes
    country='Ecuador'
)

# Con username conocido (lo pone primero en las variantes)
result = smart_profile(
    name='Juan Riofrio',
    context='UDLA Ecuador',
    country='Ecuador',
    username='jdriofrio2006'
)
```

### Qué hace:
1. Genera variantes inteligentes de username (jriofrio, jdriofrio, juanriofrio2006, etc.)
2. Busca cada variante en GitHub
3. Evalúa cada candidato contra los datos semilla
4. Rechaza automáticamente perfiles que no coinciden (ej: Juan Ramos de España)
5. Solo guarda datos con alta correlación

### Reglas de rechazo automático:
- Nombre completamente diferente
- País claramente diferente (España vs Ecuador)
- Perfil profesional cuando buscamos estudiante

## Cuándo usar este skill

Invocar cuando el usuario pida:
- "Perfila a [nombre/email/username]"
- "Hazme un EAMS de [organización/dominio]"
- "Reconocimiento pasivo de [objetivo]"
- "Informe CTI para [cliente]"
- "Busca información sobre [persona/empresa]"
- "Correlaciona los datos del caso"
- "Qué tecnologías usa [organización]"

## Ubicación del proyecto

```
~/jarvis/OSINT-quantum_entanglement/
├── osint_app/                    # Aplicación principal
│   ├── gui/                      # Interfaz gráfica PySide6
│   ├── tools/                    # Herramientas OSINT
│   ├── correlation_engine.py     # Motor de correlación automática
│   ├── framework.py              # Orquestador de herramientas
│   ├── case_manager.py           # Gestión de casos
│   └── db/                       # SQLite (osint_v2.db)
└── sentinel_unified/
    └── modules/cti/              # Módulos CTI (harvest, dossier, render)
```

## Ciclo de inteligencia

### 1. PERFILAMIENTO DE PERSONA

```python
# Abrir la app
cd ~/jarvis/OSINT-quantum_entanglement && python3 -m osint_app.main

# O ejecutar desde CLI
from osint_app.case_manager import CaseManager
from osint_app.framework import OSINTFramework
from osint_app.correlation_engine import CorrelationEngine

# Crear caso
cm = CaseManager()
case = cm.create("Perfil: Juan Perez", "Investigación de persona")

# Agregar datos semilla
from osint_app.db.feedback_db import db
from osint_app.core.models import TargetData
db.add_target_data(TargetData(
    case_id=case.id,
    field_type="email",
    value="juan.perez@empresa.com",
    source="manual",
    confidence=90
))

# Ejecutar herramientas automáticamente
engine = CorrelationEngine(case.id)
suggestions = engine.suggest_tools()  # ["Holehe", "Hunter.io", "Google Dorks"]

# El motor extrae entidades y correlaciona automáticamente
```

### 2. EAMS (External Attack Surface Management)

Reconocimiento pasivo de infraestructura:

1. **Enumerar subdominios**: Subfinder, Amass
2. **Recolectar emails/hosts**: TheHarvester
3. **Histórico web**: Wayback Machine
4. **Certificados**: Censys
5. **Tecnologías**: Correlacionar con feeds CTI

```bash
# Herramientas disponibles para EAMS
subfinder -d empresa.com -o subdominios.txt
amass enum -passive -d empresa.com
theHarvester -d empresa.com -b all
```

### 3. CTI (Cyber Threat Intelligence)

```bash
# Ubicación de scripts CTI
cd ~/jarvis/OSINT-quantum_entanglement/sentinel_unified/modules/cti

# Recolectar feeds
python3 harvest.py --dry-run

# Generar dossier por cliente
python3 dossier.py --cliente CER --resumen
python3 dossier.py --cliente MAVESA --resumen

# Render HTML
python3 render.py store/dossier-YYYY-MM-DD.json
```

Clientes configurados: CER, MAVESA, XTRIM, SERVIANDINA

### 4. CORRELACIÓN AUTOMÁTICA

El motor de correlación:
- Extrae entidades de resultados (emails, dominios, IPs, usernames)
- Busca patrones: email@dominio, username=prefijo_email
- Correlación cruzada entre casos
- Sugiere herramientas según datos disponibles

```python
from osint_app.correlation_engine import CorrelationEngine, CrossCaseCorrelator

# Analizar un caso
engine = CorrelationEngine(case_id)
summary = engine.get_profile_summary()
# {
#   "total_entities": 15,
#   "total_correlations": 8,
#   "entities_by_type": {"email": [...], "domain": [...]},
#   "top_correlations": [...]
# }

# Correlación entre casos
correlator = CrossCaseCorrelator()
correlator.load_case(1)
correlator.load_case(2)
shared = correlator.find_cross_correlations()
```

## Herramientas disponibles

### PROFILE (Personas)
| Herramienta | Estado | Uso |
|-------------|--------|-----|
| Google Dorks | ✅ | Búsqueda avanzada DuckDuckGo |
| Hunter.io | ✅ | Emails corporativos (requiere API key) |
| Holehe | ❌ | Email en servicios (pip install holehe) |
| Sherlock | ❌ | Username en +300 sitios (pip install sherlock-project) |
| Maigret | ✅ | Username profundo |
| GHunt | ❌ | Cuenta Google (pip install ghunt) |

### RECON (Infraestructura)
| Herramienta | Estado | Uso |
|-------------|--------|-----|
| Subfinder | ✅ | Subdominios pasivos |
| Amass | ✅ | Enumeración completa |
| TheHarvester | ❌ | Emails y hosts (pip install theHarvester) |
| Censys | ✅ | Certificados e IPs |
| Wayback | ✅ | Histórico web |
| dnspython | ✅ | Registros DNS |
| phonenumbers | ✅ | Análisis de teléfonos |
| SpiderFoot | ✅ | OSINT automatizado |

### CTI (Threat Intelligence)
| Módulo | Descripción |
|--------|-------------|
| harvest.py | Recolector de feeds (CISA KEV, ransomware.live, etc.) |
| fuentes.py | Registro de fuentes CTI |
| dossier.py | Generador de dossiers por cliente |
| clientes.py | Inventarios y pesos por cliente |
| render.py | Plantilla HTML Altel |

## Flujo completo: Investigación de organización

```
1. CREAR CASO
   Tipo: mixed (OSINT + CTI)
   
2. AGREGAR SEMILLAS
   - Dominio principal: empresa.com
   - Nombre de contacto: Juan Perez
   
3. EJECUTAR EAMS
   - Subfinder → subdominios
   - Amass → más subdominios, ASNs
   - TheHarvester → emails, hosts
   - Censys → certificados, puertos
   
4. CORRELACIONAR
   - Motor extrae entidades automáticamente
   - Encuentra relaciones: email@subdominio
   - Detecta tecnologías: WordPress, Nginx, etc.
   
5. ENRIQUECER CON CTI
   - harvest.py → feeds actuales
   - Correlacionar CVEs con tecnologías encontradas
   - Priorizar por cliente
   
6. GENERAR REPORTE
   - Superficie de ataque mapeada
   - Tecnologías expuestas
   - CVEs aplicables
   - Recomendaciones de mitigación
```

## Reportes

### Perfil de persona
- Datos confirmados (emails, usernames, redes)
- Fuentes de cada dato
- Nivel de confianza
- Correlaciones encontradas

### EAMS de organización
- Subdominios activos
- IPs y ASNs
- Tecnologías detectadas
- Certificados
- Puertos abiertos

### Informe CTI
- Amenazas relevantes para el sector
- CVEs aplicables a tecnologías del cliente
- IOCs para bloquear
- Recomendaciones

## Base de datos

SQLite en: `osint_app/data/osint_v2.db`

Tablas:
- `cases`: Casos de investigación
- `target_data`: Datos del objetivo
- `tool_reports`: Resultados de herramientas
- `data_extracts`: Entidades extraídas

## Comandos rápidos

```bash
# Lanzar GUI
cd ~/jarvis/OSINT-quantum_entanglement && python3 -m osint_app.main

# Verificar herramientas
python3 -m osint_app.main --check-tools

# Modo CLI
python3 -m osint_app.main --cli
```

## Comportamiento esperado de la IA

Cuando el usuario pida investigar:

1. **Entender el objetivo**: persona, organización, o mixto
2. **Crear caso** en la app o usar la BD directamente
3. **Ejecutar herramientas** según el tipo de objetivo
4. **Correlacionar** datos automáticamente
5. **Enriquecer con CTI** si aplica
6. **Reportar** hallazgos de forma estructurada

La IA debe:
- Usar las herramientas disponibles (✅)
- Sugerir instalación de las faltantes (❌)
- Correlacionar automáticamente
- Priorizar por confianza
- Generar reportes accionables
