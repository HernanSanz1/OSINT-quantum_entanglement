# Maigret

Búsqueda profunda de usernames en más de 2500 sitios web.

## Descripción

Maigret es un fork mejorado de Sherlock que busca un username en miles de sitios, extrae información adicional del perfil, y genera reportes detallados.

## Instalación

```bash
# pip
pip install maigret

# Desde source
git clone https://github.com/soxoj/maigret.git
cd maigret
pip install -r requirements.txt
```

## Uso básico

```bash
# Username único
maigret username

# Con reporte HTML
maigret username -H

# Múltiples usernames
maigret user1 user2 user3

# Guardar JSON
maigret username --json report.json

# Sitios específicos
maigret username --site twitter --site instagram
```

## Parámetros principales

| Parámetro | Descripción |
|-----------|-------------|
| `-a` `--all-sites` | Buscar en TODOS los sitios |
| `-H` `--html` | Generar reporte HTML |
| `--json` | Guardar resultados en JSON |
| `--csv` | Guardar en CSV |
| `--pdf` | Generar PDF |
| `-t` | Timeout por request |
| `--site` | Sitio específico |
| `--tags` | Filtrar por tags (social, gaming, etc) |
| `-x` | Proxy SOCKS |
| `--tor` | Usar Tor |
| `-v` | Verbose |
| `--no-color` | Sin colores en output |
| `--retries` | Reintentos por sitio |

## Tags disponibles

```bash
# Filtrar por categoría
maigret username --tags social
maigret username --tags gaming
maigret username --tags dating
maigret username --tags coding
```

Tags: social, gaming, dating, coding, news, finance, art, music, video, photo, forum, blog, travel

## Ejemplo de salida

```
[*] Checking username: johndoe
[+] Twitter: https://twitter.com/johndoe
    Full name: John Doe
    Bio: Developer
    Location: NYC
    Followers: 1234
    
[+] GitHub: https://github.com/johndoe
    Name: John Doe
    Company: Acme Corp
    Repos: 42
    
[+] Instagram: https://instagram.com/johndoe
    Posts: 156
    Followers: 2000
```

## Integración con SENTINEL

```python
from osint_app.tools.maigret import MaigretTool

tool = MaigretTool()
results = tool.run(username="johndoe", tags=["social", "coding"])
# Extrae:
# - URLs de perfiles encontrados
# - Nombres, bios, ubicaciones
# - Metadata de cada plataforma
```

## Diferencias con Sherlock

| Feature | Sherlock | Maigret |
|---------|----------|---------|
| Sitios | ~300 | ~2500 |
| Extracción de datos | No | Sí |
| Reportes | Básico | HTML/PDF/JSON |
| Filtrado por tags | No | Sí |
| Parsing de perfiles | No | Sí |

## Tips

1. Usa `--all-sites` para búsqueda exhaustiva (toma tiempo)
2. `-H` genera reportes HTML visualmente útiles
3. Combina tags para enfocar la búsqueda
4. El username puede tener variaciones: prueba john_doe, johndoe, john.doe
5. Los sitios con captcha pueden dar falsos negativos
