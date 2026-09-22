# Sherlock

Busca un username en más de 300 redes sociales y sitios web.

## Instalación

```bash
pip install sherlock-project
```

## Uso básico

```bash
# Buscar un username
sherlock johndoe

# Buscar múltiples usernames
sherlock johndoe janedoe admin

# Guardar en archivo
sherlock johndoe --output results.txt

# Formato CSV
sherlock johndoe --csv

# Solo mostrar encontrados
sherlock johndoe --print-found
```

## Parámetros importantes

| Parámetro | Descripción |
|-----------|-------------|
| `--timeout` | Timeout por sitio (default: 60s) |
| `--print-found` | Solo muestra donde existe |
| `--no-color` | Sin colores (para logs) |
| `--browse` | Abre resultados en navegador |
| `--local` | Usa solo sitios locales |
| `--csv` | Exporta a CSV |
| `--xlsx` | Exporta a Excel |
| `--json` | Salida JSON |

## Integración con SENTINEL

En SENTINEL, Sherlock se ejecuta automáticamente cuando:
1. Se agrega un username al caso
2. El motor de correlación sugiere búsqueda de redes sociales

Los resultados se parsean y las URLs encontradas se agregan como entidades tipo "social" con alta confianza.

## Ejemplo de salida

```
[*] Checking username johndoe on:
[+] GitHub: https://github.com/johndoe
[+] Twitter: https://twitter.com/johndoe
[+] Instagram: https://instagram.com/johndoe
[-] Facebook: Not Found
[+] LinkedIn: https://linkedin.com/in/johndoe
```

## Limitaciones

- Algunos sitios tienen rate limiting
- Puede dar falsos positivos en sitios con usernames comunes
- No verifica si la cuenta está activa
