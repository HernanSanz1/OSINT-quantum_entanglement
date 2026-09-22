# SENTINEL UNIFIED - Arquitectura

## Tres Modulos Principales

```
┌─────────────────────────────────────────────────────────────────┐
│                      SENTINEL UNIFIED                           │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   PROFILE       │   RECON         │   CTI                       │
│   (Personas)    │   (Infra)       │   (Threat Intel)            │
├─────────────────┼─────────────────┼─────────────────────────────┤
│ - Sherlock      │ - Subfinder     │ - Feeds (harvest.py)        │
│ - Holehe        │ - Amass         │ - EPSS enrichment           │
│ - Maigret       │ - SpiderFoot    │ - KEV/CVE correlation       │
│ - GHunt         │ - Censys        │ - Dossier por cliente       │
│ - Hunter.io     │ - TheHarvester  │ - Render HTML               │
│ - Google Dorks  │ - Wayback       │ - Mail Graph                │
│ - Instagram     │ - DNS tools     │ - Vision One connector      │
│ - Snscrape      │ - IP Whois      │                             │
└─────────────────┴─────────────────┴─────────────────────────────┘
                           │
                           ▼
              ┌───────────────────────┐
              │   CASE DATABASE       │
              │   (SQLite unificado)  │
              │                       │
              │ - cases               │
              │ - targets (personas)  │
              │ - assets (infra)      │
              │ - iocs (threat intel) │
              │ - tool_reports        │
              │ - correlations        │
              └───────────────────────┘
                           │
                           ▼
              ┌───────────────────────┐
              │   GRAPH ENGINE        │
              │                       │
              │ persona ──► email     │
              │    │          │       │
              │    ▼          ▼       │
              │ username ◄── domain   │
              │    │          │       │
              │    ▼          ▼       │
              │  social     IP/ASN    │
              │              │        │
              │              ▼        │
              │           CVE/IOC     │
              └───────────────────────┘
```

## Estructura de Carpetas

```
sentinel_unified/
├── core/
│   ├── models.py          # Case, Target, Asset, IOC, Correlation
│   ├── database.py        # SQLite unificado
│   └── graph.py           # Motor de grafos (relaciones)
│
├── modules/
│   ├── profile/           # Perfilamiento de personas
│   │   ├── sherlock.py
│   │   ├── holehe.py
│   │   ├── maigret.py
│   │   ├── ghunt.py
│   │   ├── hunter.py
│   │   └── social.py
│   │
│   ├── recon/             # Reconocimiento de infra
│   │   ├── subfinder.py
│   │   ├── amass.py
│   │   ├── spiderfoot.py
│   │   ├── censys.py
│   │   ├── theharvester.py
│   │   ├── wayback.py
│   │   └── dns.py
│   │
│   └── cti/               # Threat Intelligence
│       ├── harvest.py     # Recolector de feeds
│       ├── fuentes.py     # Registro de fuentes
│       ├── dossier.py     # Generador de dossiers
│       ├── clientes.py    # Inventarios por cliente
│       ├── render.py      # HTML generator
│       └── enrichment.py  # EPSS, PoC-in-GitHub
│
├── reports/
│   ├── profile_report.py  # Reporte de persona
│   ├── recon_report.py    # Reporte de infra
│   ├── cti_report.py      # Boletin CTI (Altel format)
│   └── unified_report.py  # Reporte combinado (actor de amenaza)
│
├── gui/
│   ├── app.py             # Main window
│   ├── style.qss          # Dark theme
│   ├── tab_cases.py       # Gestion de casos
│   ├── tab_profile.py     # Perfilamiento
│   ├── tab_recon.py       # Reconocimiento
│   ├── tab_cti.py         # Threat Intel
│   ├── tab_graph.py       # Visualizacion de grafos
│   └── components.py      # Widgets reutilizables
│
├── store/                 # Datos persistentes
│   ├── sentinel.db        # SQLite principal
│   ├── items.jsonl        # Items CTI raw
│   └── cache/             # Cache de herramientas
│
└── main.py
```

## Modelo de Datos Unificado

### Case (Caso)
- id, name, description, type (profile|recon|cti|mixed), status, created_at

### Target (Persona)
- case_id, name, email, phone, username, photo_url, location, company, notes

### Asset (Infraestructura)
- case_id, type (domain|subdomain|ip|asn|url), value, source_tool, first_seen

### IOC (Indicador de Compromiso)
- case_id, type (ip|domain|hash|cve), value, source, confidence, tags

### Correlation (Relacion en grafo)
- source_type, source_id, target_type, target_id, relation_type, confidence

## Flujo de Trabajo

1. **Crear caso** → elegir tipo (persona, infra, CTI, mixto)
2. **Agregar semilla** → nombre, email, dominio, IP, etc.
3. **Ejecutar herramientas** → segun el tipo de caso
4. **Ver grafo** → relaciones descubiertas
5. **Enriquecer con CTI** → correlacionar con IOCs conocidos
6. **Generar reporte** → formato segun el tipo

## Integracion CTI ↔ OSINT

- Si perfilo a "Juan Perez" y encuentro su email juan@empresa.com
- Puedo correlacionar empresa.com con IOCs de CTI
- Si empresa.com aparece en un feed de phishing → alerta
- Si Juan es admin de un servidor comprometido → vincular actor

## GUI Tabs

1. **CASES** - Lista de casos, crear nuevo, abrir
2. **PROFILE** - Herramientas de perfilamiento, resultados, foto
3. **RECON** - Herramientas de infra, subdominios, IPs
4. **CTI** - Feeds, dossiers, boletines, clientes
5. **GRAPH** - Visualizacion de relaciones
6. **REPORTS** - Generacion de informes
