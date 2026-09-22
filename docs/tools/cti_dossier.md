# CTI Dossier

Generador de informes de inteligencia de amenazas por cliente.

## Descripción

dossier.py toma los datos recolectados por harvest.py y genera informes personalizados para cada cliente, priorizando vulnerabilidades según su stack tecnológico.

## Ubicación

```
~/jarvis/OSINT-quantum_entanglement/sentinel_unified/modules/cti/dossier.py
```

## Uso

```bash
cd ~/jarvis/OSINT-quantum_entanglement/sentinel_unified/modules/cti

# Generar dossier para un cliente
python3 dossier.py --cliente CER

# Solo resumen
python3 dossier.py --cliente MAVESA --resumen

# Todos los clientes
python3 dossier.py --all

# Rango de fechas
python3 dossier.py --cliente XTRIM --desde 2026-09-01 --hasta 2026-09-22

# Output JSON
python3 dossier.py --cliente CER --json
```

## Clientes configurados

| Cliente | Sectores | Tecnologías clave |
|---------|----------|-------------------|
| CER | Energía, SCADA | Siemens, Schneider, Fortinet |
| MAVESA | Retail, POS | Windows, VMware, Cisco |
| XTRIM | Telecom | Linux, Juniper, AWS |
| SERVIANDINA | Finanzas | Oracle, SAP, Azure |

## Estructura del dossier

```json
{
  "cliente": "CER",
  "generado": "2026-09-22T10:00:00Z",
  "periodo": "2026-09-15 a 2026-09-22",
  "resumen": {
    "vulns_criticas": 5,
    "vulns_altas": 12,
    "iocs_nuevos": 234,
    "grupos_activos": ["LockBit", "BlackCat"]
  },
  "vulnerabilidades": [
    {
      "cve": "CVE-2026-1234",
      "cvss": 9.8,
      "epss": 0.95,
      "producto": "FortiOS",
      "relevancia": "ALTA",
      "motivo_relevancia": "Cliente usa Fortinet",
      "mitigacion": "Actualizar a FortiOS 7.4.3"
    }
  ],
  "amenazas": [
    {
      "grupo": "LockBit",
      "sector": "Energía",
      "actividad_reciente": "15 víctimas en Latam esta semana"
    }
  ],
  "iocs_prioritarios": {
    "ips": ["1.2.3.4"],
    "dominios": ["evil.com"],
    "hashes": ["abc123..."]
  },
  "recomendaciones": [...]
}
```

## Archivos generados

```
store/
  dossiers/
    CER-YYYY-MM-DD.json
    MAVESA-YYYY-MM-DD.json
```

## Configuración de clientes

En `clientes.py`:
```python
CLIENTES = {
    "CER": {
        "nombre_completo": "Corporación Eléctrica Regional",
        "sectores": ["energy", "utilities"],
        "tecnologias": ["fortinet", "siemens", "schneider"],
        "pesos": {
            "kev": 1.5,        # Prioriza CVEs explotados
            "ransomware": 1.3  # Prioriza si hay ransomware usando
        }
    }
}
```

## Integración con SENTINEL

```python
from sentinel_unified.modules.cti.dossier import DossierGenerator

gen = DossierGenerator(cliente="CER")
dossier = gen.generate()
# dossier contiene todo el informe estructurado
# gen.save() guarda a archivo
```

## Priorización de vulnerabilidades

El score de relevancia considera:
1. **EPSS**: Probabilidad de explotación
2. **KEV**: Si está en lista CISA
3. **Ransomware**: Si hay grupos usándola
4. **Match tecnología**: Si el cliente usa el producto afectado
5. **Match sector**: Si el sector del cliente es objetivo

## Tips

1. Revisa clientes.py para ajustar tecnologías de cada cliente
2. --resumen es útil para briefings rápidos
3. El JSON es consumible por otros sistemas (SOAR, SIEM)
4. Ejecuta después de harvest.py para datos frescos
5. Los pesos en clientes.py ajustan la priorización
