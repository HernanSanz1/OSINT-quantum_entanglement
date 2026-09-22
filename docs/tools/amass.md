# Amass

Framework avanzado de enumeración de infraestructura y subdominios.

## Descripción

Amass es la herramienta más completa para mapear la superficie de ataque externa. Combina técnicas pasivas y activas con grafo de relaciones.

## Instalación

```bash
# macOS
brew install amass

# Linux
go install -v github.com/owasp-amass/amass/v4/...@master

# Snap
sudo snap install amass
```

## Modos de operación

### Pasivo (recomendado para OSINT)

```bash
# Enumeración pasiva
amass enum -passive -d ejemplo.com

# Con salida a archivo
amass enum -passive -d ejemplo.com -o pasivo.txt
```

### Activo (genera tráfico)

```bash
# Enumeración activa
amass enum -active -d ejemplo.com

# Con brute force
amass enum -active -brute -d ejemplo.com
```

## Parámetros principales

| Parámetro | Descripción |
|-----------|-------------|
| `-d` | Dominio objetivo |
| `-passive` | Solo fuentes pasivas |
| `-active` | Incluir DNS activo |
| `-brute` | Brute force de subdominios |
| `-o` | Archivo de salida |
| `-oA` | Salida en todos los formatos |
| `-json` | Salida JSON |
| `-config` | Archivo de configuración |
| `-timeout` | Timeout en minutos |
| `-v` | Verbose |
| `-asn` | Listar ASNs relacionados |
| `-ip` | Resolver IPs |

## Comandos útiles

```bash
# Ver ASNs de una organización
amass intel -org "Empresa SA"

# Subdominios + IPs
amass enum -passive -d ejemplo.com -ip

# Historial de enumeraciones
amass db -show

# Exportar grafo
amass viz -d ejemplo.com -o grafo.html
```

## Configuración de API keys

Crear `~/.config/amass/config.ini`:

```ini
[data_sources]
minimum_ttl = 1440

[data_sources.SecurityTrails]
apikey = API_KEY_AQUI

[data_sources.Shodan]
apikey = API_KEY_AQUI

[data_sources.VirusTotal]
apikey = API_KEY_AQUI

[data_sources.Censys]
apikey = API_KEY_AQUI
secret = SECRET_AQUI
```

## Fuentes de datos

Amass usa +50 fuentes: crt.sh, SecurityTrails, Shodan, VirusTotal, Censys, PassiveTotal, RiskIQ, Spyse, URLScan, Wayback, y más.

## Salida de ejemplo

```
www.ejemplo.com
mail.ejemplo.com (192.168.1.10)
api.ejemplo.com (192.168.1.20)
dev.ejemplo.com (192.168.1.30)
[ASN] 12345 - Ejemplo Hosting
```

## Integración con SENTINEL

```python
from osint_app.tools.amass import AmassTool

tool = AmassTool()
results = tool.run(domain="ejemplo.com", passive=True)
# Extrae: subdominios, IPs, ASNs
# Todo se guarda en tool_reports y data_extracts
```

## Tips

1. Usa `-passive` para OSINT sin alertar
2. Combina con Subfinder: Amass es más profundo pero más lento
3. `-active` puede tomar horas en dominios grandes
4. El grafo (`amass viz`) es útil para presentaciones
