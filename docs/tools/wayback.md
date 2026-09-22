# Wayback Machine

Archivo histórico de páginas web.

## Descripción

Wayback Machine de Internet Archive guarda snapshots históricos de páginas web. Útil para encontrar información eliminada, URLs antiguas, y ver cómo evolucionó un sitio.

## Uso web

```
https://web.archive.org/web/*/ejemplo.com
```

## API CDX (búsqueda)

```bash
# Todas las URLs archivadas
curl "https://web.archive.org/cdx/search/cdx?url=ejemplo.com/*&output=json&fl=timestamp,original,statuscode"

# Solo páginas exitosas
curl "https://web.archive.org/cdx/search/cdx?url=ejemplo.com/*&filter=statuscode:200"

# Rango de fechas
curl "https://web.archive.org/cdx/search/cdx?url=ejemplo.com&from=2020&to=2023"

# Limitar resultados
curl "https://web.archive.org/cdx/search/cdx?url=ejemplo.com/*&limit=1000"
```

## Parámetros CDX

| Parámetro | Descripción |
|-----------|-------------|
| `url` | URL a buscar (acepta wildcards) |
| `matchType` | exact, prefix, host, domain |
| `from` | Fecha inicio (YYYYMMDD) |
| `to` | Fecha fin |
| `filter` | Filtros (statuscode:200) |
| `collapse` | Agrupar duplicados |
| `limit` | Máximo de resultados |
| `output` | json, text |
| `fl` | Campos a retornar |

## Campos disponibles

```
urlkey       - URL normalizada
timestamp    - Fecha del snapshot (YYYYMMDDHHMMSS)
original     - URL original
mimetype     - Tipo de contenido
statuscode   - Código HTTP
digest       - Hash del contenido
length       - Tamaño
```

## Ver snapshot específico

```
https://web.archive.org/web/20230115120000/https://ejemplo.com/
                             ^timestamp^         ^URL^
```

## Herramienta waybackurls

```bash
# Instalar
go install github.com/tomnomnom/waybackurls@latest

# Usar
echo ejemplo.com | waybackurls > urls.txt

# Con timestamps
echo ejemplo.com | waybackurls -dates
```

## Integración con SENTINEL

```python
from osint_app.tools.wayback import WaybackTool

tool = WaybackTool()
results = tool.run(domain="ejemplo.com", years_back=5)
# Retorna:
# - URLs únicas encontradas
# - Timestamps de capturas
# - Cambios detectados en páginas clave
```

## Casos de uso OSINT

1. **URLs eliminadas**: Páginas que ya no existen
2. **Subdominios antiguos**: APIs, dev, staging que fueron retirados
3. **Documentos expuestos**: PDFs, configs que fueron removidos
4. **Evolución de tecnología**: Cambios en headers, frameworks
5. **Información de contacto**: Emails, teléfonos antiguos
6. **Estructura organizacional**: Organigramas, directorios eliminados

## Tips

1. Usa `/*` al final para buscar todo el sitio
2. `collapse=urlkey` elimina duplicados
3. Combina con Google Dorks para encontrar archivos específicos
4. Los robots.txt archivados revelan directorios ocultos
5. Compara versiones para detectar cambios de seguridad
