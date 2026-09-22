# Google Dorks

Búsqueda avanzada con operadores especiales para encontrar información expuesta.

## Descripción

Google Dorks son consultas avanzadas que usan operadores de búsqueda para encontrar información específica: archivos expuestos, paneles de admin, errores de configuración, etc.

## Operadores principales

| Operador | Descripción | Ejemplo |
|----------|-------------|---------|
| `site:` | Limitar a dominio | `site:ejemplo.com` |
| `filetype:` | Tipo de archivo | `filetype:pdf` |
| `inurl:` | Texto en URL | `inurl:admin` |
| `intitle:` | Texto en título | `intitle:"index of"` |
| `intext:` | Texto en página | `intext:password` |
| `ext:` | Extensión | `ext:sql` |
| `cache:` | Versión cacheada | `cache:ejemplo.com` |
| `-` | Excluir | `-site:www.ejemplo.com` |
| `""` | Frase exacta | `"error de conexión"` |
| `OR` | Alternativa | `admin OR login` |
| `*` | Wildcard | `admin*.ejemplo.com` |

## Dorks útiles para OSINT

### Documentos expuestos

```
site:ejemplo.com filetype:pdf
site:ejemplo.com filetype:doc OR filetype:docx
site:ejemplo.com filetype:xls OR filetype:xlsx
site:ejemplo.com filetype:sql
site:ejemplo.com filetype:log
```

### Paneles de administración

```
site:ejemplo.com inurl:admin
site:ejemplo.com inurl:login
site:ejemplo.com intitle:"dashboard"
site:ejemplo.com inurl:wp-admin
site:ejemplo.com inurl:phpmyadmin
```

### Errores y configuración

```
site:ejemplo.com "error" OR "warning" OR "exception"
site:ejemplo.com "index of /"
site:ejemplo.com intitle:"Apache Status"
site:ejemplo.com ext:env OR ext:config
site:ejemplo.com "DB_PASSWORD" OR "API_KEY"
```

### Información sensible

```
site:ejemplo.com "confidencial" OR "interno"
site:ejemplo.com "@ejemplo.com"
site:ejemplo.com filetype:csv email
site:ejemplo.com "password" filetype:txt
```

### Subdominios y URLs

```
site:*.ejemplo.com -www
site:ejemplo.com inurl:dev OR inurl:test OR inurl:staging
site:ejemplo.com inurl:api
```

## Integración con SENTINEL

```python
from osint_app.tools.google_dorks import GoogleDorksTool

tool = GoogleDorksTool()
results = tool.run(
    domain="ejemplo.com",
    dork_categories=["files", "admin", "sensitive"]
)
# Usa DuckDuckGo para evitar captchas de Google
# Extrae URLs encontradas y las clasifica
```

## Implementación en SENTINEL

SENTINEL usa DuckDuckGo en lugar de Google para evitar bloqueos. La herramienta:

1. Genera dorks automáticamente según el dominio
2. Ejecuta búsquedas con delays para evitar rate limiting
3. Parsea resultados y extrae URLs únicas
4. Clasifica por categoría (docs, admin, config, etc.)

## Tips

1. Usa comillas para frases exactas
2. Combina operadores: `site:ejemplo.com filetype:pdf intext:confidencial`
3. Excluye subdominios conocidos: `-site:www.ejemplo.com`
4. Revisa resultados cacheados si la página ya no existe
5. Google indexa menos que antes; combina con Wayback
