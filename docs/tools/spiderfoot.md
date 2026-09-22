# SpiderFoot

Framework de OSINT automatizado con más de 200 módulos.

## Descripción

SpiderFoot es una herramienta de automatización OSINT que corre múltiples módulos para recolectar información sobre IPs, dominios, emails, nombres, y más. Tiene GUI web y CLI.

## Instalación

```bash
# Clonar
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot

# Instalar dependencias
pip install -r requirements.txt

# Iniciar GUI web
python sf.py -l 127.0.0.1:5001
```

## Modos de uso

### GUI Web

```bash
python sf.py -l 127.0.0.1:5001
# Abrir http://127.0.0.1:5001
```

### CLI

```bash
# Escaneo básico
python sf.py -s ejemplo.com -m all

# Módulos específicos
python sf.py -s ejemplo.com -m sfp_dnsresolve,sfp_shodan

# Output JSON
python sf.py -s ejemplo.com -o json -q

# Listar módulos
python sf.py -M
```

## Parámetros CLI

| Parámetro | Descripción |
|-----------|-------------|
| `-s` | Target (dominio, IP, email, etc) |
| `-m` | Módulos (all o lista) |
| `-t` | Tipos de datos a buscar |
| `-o` | Formato output (csv, json, etc) |
| `-q` | Quiet mode |
| `-M` | Listar módulos |
| `-T` | Listar tipos de datos |
| `-l` | Iniciar GUI en host:port |

## Módulos importantes

| Módulo | Descripción |
|--------|-------------|
| `sfp_dnsresolve` | Resolución DNS |
| `sfp_shodan` | Búsqueda en Shodan |
| `sfp_censys` | Búsqueda en Censys |
| `sfp_virustotal` | VirusTotal lookup |
| `sfp_have_i_been_pwned` | Verificar breaches |
| `sfp_hunter` | Hunter.io emails |
| `sfp_whois` | Información WHOIS |
| `sfp_sslcert` | Certificados SSL |
| `sfp_webframework` | Detectar frameworks |

## Tipos de datos

```
DOMAIN_NAME, IP_ADDRESS, EMAILADDR, PHONE_NUMBER
HUMAN_NAME, USERNAME, BITCOIN_ADDRESS, CREDIT_CARD
SOFTWARE_USED, AFFILIATE, WEBSERVER_TECHNOLOGY
VULNERABILITY, DARKNET_MENTION, LEAKED_CREDENTIAL
```

## Configuración de API keys

En la GUI: Settings > API Keys

O editar `spiderfoot.cfg`:
```
[module:sfp_shodan]
api_key = xxx

[module:sfp_virustotal]
api_key = xxx
```

## Integración con SENTINEL

```python
from osint_app.tools.spiderfoot import SpiderFootTool

tool = SpiderFootTool(sf_path="~/spiderfoot")
results = tool.run(
    target="ejemplo.com",
    modules=["sfp_dnsresolve", "sfp_sslcert", "sfp_webframework"]
)
# Parsea output JSON y extrae entidades
```

## Ventajas

1. +200 módulos integrados
2. Correlación automática de datos
3. GUI web para análisis visual
4. Soporte para múltiples tipos de target
5. Integración con muchas APIs

## Tips

1. Configura API keys para mejores resultados
2. Usa `-t` para enfocar en tipos de datos específicos
3. La GUI web tiene visualización de grafos
4. Exporta a CSV/JSON para análisis posterior
5. Crea "use cases" predefinidos para diferentes tipos de investigación
