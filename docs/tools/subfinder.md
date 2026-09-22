# Subfinder

Herramienta de descubrimiento pasivo de subdominios.

## Descripción

Subfinder es una herramienta que usa múltiples fuentes pasivas (motores de búsqueda, DNS, certificados) para encontrar subdominios sin generar tráfico directo hacia el objetivo.

## Instalación

```bash
# macOS
brew install subfinder

# Linux
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Uso básico

```bash
# Dominio único
subfinder -d ejemplo.com

# Guardar en archivo
subfinder -d ejemplo.com -o subdominios.txt

# Silencioso (solo resultados)
subfinder -d ejemplo.com -silent

# Múltiples dominios
subfinder -dL dominios.txt -o resultados.txt
```

## Parámetros principales

| Parámetro | Descripción |
|-----------|-------------|
| `-d` | Dominio objetivo |
| `-dL` | Archivo con lista de dominios |
| `-o` | Archivo de salida |
| `-oJ` | Salida en JSON |
| `-silent` | Solo imprime subdominios |
| `-v` | Modo verbose |
| `-t` | Threads (default: 10) |
| `-timeout` | Timeout en segundos |
| `-all` | Usar todas las fuentes |
| `-config` | Archivo de configuración |

## Configuración de API keys

Crear `~/.config/subfinder/provider-config.yaml`:

```yaml
securitytrails:
  - API_KEY_AQUI
chaos:
  - API_KEY_AQUI
shodan:
  - API_KEY_AQUI
virustotal:
  - API_KEY_AQUI
censys:
  - API_KEY_AQUI:SECRET_AQUI
```

## Fuentes pasivas

Sin API keys: crt.sh, Alienvault, Wayback, hackertarget, dnsdumpster, anubis, riddler, bufferover

Con API keys: SecurityTrails, Shodan, VirusTotal, Censys, Chaos, PassiveTotal, Fofa

## Ejemplo de salida

```
mail.ejemplo.com
www.ejemplo.com
api.ejemplo.com
dev.ejemplo.com
staging.ejemplo.com
```

## Integración con SENTINEL

```python
from osint_app.tools.subfinder import SubfinderTool

tool = SubfinderTool()
results = tool.run(domain="ejemplo.com")
# Resultados se guardan automáticamente en tool_reports
# Subdominios se extraen a data_extracts como type="subdomain"
```

## Tips

1. Siempre usa `-all` para máxima cobertura
2. Configura API keys para mejores resultados
3. Combina con Amass para cobertura completa
4. Los resultados son pasivos: no alertan al objetivo
