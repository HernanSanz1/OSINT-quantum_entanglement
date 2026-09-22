# Censys

Motor de búsqueda de dispositivos y certificados en Internet.

## Descripción

Censys escanea toda la Internet y indexa información de hosts, certificados SSL, y servicios. Ideal para descubrir infraestructura y certificados de una organización.

## Requisitos

- Cuenta gratuita: 250 queries/mes
- API ID y Secret: https://search.censys.io/account/api

## Uso web

```
# Buscar hosts de un dominio
services.http.response.html_title: "ejemplo"

# Certificados de dominio
parsed.names: ejemplo.com

# IPs de una organización
autonomous_system.name: "Empresa SA"

# Servicios específicos
services.port: 443 AND services.http.response.html_title: "admin"
```

## Uso desde API (Python)

```python
from censys.search import CensysHosts, CensysCerts

# Hosts
h = CensysHosts()
for host in h.search("services.http.response.html_title: ejemplo"):
    print(host["ip"], host["services"])

# Certificados
c = CensysCerts()
for cert in c.search("parsed.names: ejemplo.com"):
    print(cert["parsed"]["subject"]["common_name"])
```

## Operadores de búsqueda

| Operador | Descripción | Ejemplo |
|----------|-------------|---------|
| `:` | Igualdad | `ip: 1.2.3.4` |
| `AND` | Y lógico | `port: 443 AND asn: 12345` |
| `OR` | O lógico | `port: 80 OR port: 443` |
| `NOT` | Negación | `NOT port: 22` |
| `*` | Wildcard | `services.http.response.html_title: *admin*` |

## Campos útiles para hosts

```
ip
autonomous_system.asn
autonomous_system.name  
services.port
services.service_name
services.http.response.html_title
services.http.response.headers.server
services.tls.certificates.leaf_data.subject.common_name
location.country
```

## Campos para certificados

```
parsed.names
parsed.subject.common_name
parsed.subject.organization
parsed.issuer.common_name
parsed.validity.start
parsed.validity.end
parsed.fingerprint_sha256
```

## Integración con SENTINEL

```python
from osint_app.tools.censys import CensysTool

tool = CensysTool(api_id="ID", api_secret="SECRET")
results = tool.run(domain="ejemplo.com")
# Busca certificados y hosts
# Extrae: subdominios de SANs, IPs, puertos, tecnologías
```

## Configuración

```bash
# Variables de entorno
export CENSYS_API_ID=xxx
export CENSYS_API_SECRET=xxx

# O archivo ~/.censys.cfg
[DEFAULT]
api_id = xxx
api_secret = xxx
```

## Casos de uso

1. **Descubrir subdominios** via certificados (SANs)
2. **Mapear infraestructura** de una organización
3. **Identificar tecnologías** por banners HTTP
4. **Encontrar paneles expuestos** (admin, phpmyadmin)
5. **Detectar certificados expirados** o mal configurados

## Tips

1. Los certificados revelan subdominios en Subject Alternative Names
2. Combina con Shodan para cobertura completa
3. Busca por ASN para encontrar toda la infraestructura
4. Los certificados históricos muestran cambios de infraestructura
5. Usa la búsqueda de certificados para encontrar dominios relacionados
