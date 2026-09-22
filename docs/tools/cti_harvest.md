# CTI Harvest

Recolector de feeds de inteligencia de amenazas.

## Descripción

harvest.py recolecta IOCs y vulnerabilidades de múltiples fuentes de threat intelligence: CISA KEV, ransomware.live, abuse.ch, GreyNoise, y más. Normaliza los datos y los prepara para generar dossiers.

## Ubicación

```
~/jarvis/OSINT-quantum_entanglement/sentinel_unified/modules/cti/harvest.py
```

## Uso

```bash
cd ~/jarvis/OSINT-quantum_entanglement/sentinel_unified/modules/cti

# Dry run (ver qué haría)
python3 harvest.py --dry-run

# Ejecutar recolección
python3 harvest.py

# Solo fuentes específicas
python3 harvest.py --sources kev,ransomware

# Verbose
python3 harvest.py -v
```

## Fuentes configuradas

| Fuente | Tipo | Frecuencia |
|--------|------|------------|
| CISA KEV | CVEs explotados | Diario |
| ransomware.live | Grupos ransomware | Diario |
| abuse.ch URLhaus | URLs maliciosas | Diario |
| abuse.ch MalwareBazaar | Hashes de malware | Diario |
| abuse.ch ThreatFox | IOCs variados | Diario |
| GreyNoise | IPs escaneando | Continuo |
| AlienVault OTX | Pulsos de amenazas | Diario |

## Estructura de salida

```json
{
  "timestamp": "2026-09-22T10:00:00Z",
  "sources": {
    "kev": {
      "items": 1200,
      "last_updated": "2026-09-22"
    }
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2026-1234",
      "vendor": "Microsoft",
      "product": "Exchange",
      "epss": 0.95,
      "kev": true,
      "ransomware": ["LockBit"]
    }
  ],
  "iocs": {
    "ips": [...],
    "domains": [...],
    "urls": [...],
    "hashes": [...]
  }
}
```

## Archivos generados

```
store/
  raw/                    # Datos crudos de cada fuente
    kev-YYYY-MM-DD.json
    ransomware-YYYY-MM-DD.json
  normalized/             # Datos normalizados
    harvest-YYYY-MM-DD.json
```

## Integración con SENTINEL

```python
from sentinel_unified.modules.cti.harvest import Harvester

h = Harvester()
h.run()
# Datos disponibles en:
# - h.vulnerabilities: CVEs con EPSS y contexto
# - h.iocs: IOCs por tipo
# - h.store_path: Ruta a archivo JSON
```

## Parámetros de configuración

En `fuentes.py`:
```python
SOURCES = {
    "kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "enabled": True,
        "parser": "parse_kev"
    },
    # ...
}
```

## Tips

1. KEV es la fuente más importante: CVEs confirmados en explotación
2. EPSS prioriza: mayor score = mayor probabilidad de explotación
3. El campo "ransomware" indica grupos que usan esa vuln
4. Ejecuta diariamente para tener datos frescos
5. --dry-run para debugging sin escribir archivos
