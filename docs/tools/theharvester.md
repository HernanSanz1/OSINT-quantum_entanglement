# TheHarvester

Herramienta de recolección de emails, nombres, subdominios e IPs.

## Descripción

TheHarvester recopila información de fuentes públicas: emails, nombres de empleados, subdominios, IPs y banners. Ideal para la fase de reconocimiento.

## Instalación

```bash
# pip
pip install theHarvester

# Desde source
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip install -r requirements.txt
```

## Uso básico

```bash
# Búsqueda completa
theHarvester -d ejemplo.com -b all

# Fuentes específicas
theHarvester -d ejemplo.com -b google,bing,linkedin

# Guardar resultados
theHarvester -d ejemplo.com -b all -f resultados

# Limitar resultados
theHarvester -d ejemplo.com -b all -l 500
```

## Parámetros principales

| Parámetro | Descripción |
|-----------|-------------|
| `-d` | Dominio objetivo |
| `-b` | Fuentes de datos (all o lista) |
| `-l` | Límite de resultados |
| `-S` | Start desde resultado N |
| `-f` | Archivo de salida (sin extensión) |
| `-n` | DNS lookup de hosts |
| `-c` | DNS brute force |
| `-t` | DNS TLD expansion |
| `-e` | DNS server a usar |
| `-v` | Verificar host con DNS |
| `-r` | Usar resolvers custom |

## Fuentes disponibles

Gratuitas: google, bing, duckduckgo, yahoo, baidu, crtsh, dnsdumpster, hackertarget, rapiddns, sublist3r, threatcrowd, urlscan, virustotal

Con API: hunter, securityTrails, shodan, spyse, intelx, pentesttools

## Ejemplo de salida

```
[*] Hosts encontrados: 15
  api.ejemplo.com: 192.168.1.10
  mail.ejemplo.com: 192.168.1.11
  www.ejemplo.com: 192.168.1.12
  
[*] Emails encontrados: 8
  admin@ejemplo.com
  contacto@ejemplo.com
  rrhh@ejemplo.com
  
[*] Empleados:
  Juan Perez - IT Manager
  Maria Garcia - CFO
```

## Configuración de API keys

Editar `/etc/theHarvester/api-keys.yaml` o crear `~/.theHarvester/api-keys.yaml`:

```yaml
apikeys:
  hunter: API_KEY_AQUI
  securityTrails: API_KEY_AQUI
  shodan: API_KEY_AQUI
  intelx: API_KEY_AQUI
```

## Integración con SENTINEL

```python
from osint_app.tools.theharvester import TheHarvesterTool

tool = TheHarvesterTool()
results = tool.run(domain="ejemplo.com", sources=["google", "bing", "crtsh"])
# Extrae automáticamente:
# - emails → data_extracts type="email"
# - hosts → data_extracts type="subdomain"  
# - IPs → data_extracts type="ip"
```

## Tips

1. `-b all` puede ser lento; usa fuentes específicas para velocidad
2. Combina con Hunter.io para emails verificados
3. Los nombres de empleados son útiles para spear phishing awareness
4. Verifica emails con Holehe para confirmar cuentas activas
