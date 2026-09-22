# Holehe

Verifica en qué servicios está registrado un email sin enviar notificaciones.

## Instalación

```bash
pip install holehe
```

## Uso básico

```bash
# Verificar un email
holehe test@gmail.com

# Salida solo positivos
holehe test@gmail.com --only-used

# Formato CSV
holehe test@gmail.com --csv output.csv

# Sin banner
holehe test@gmail.com --no-banner
```

## Parámetros importantes

| Parámetro | Descripción |
|-----------|-------------|
| `--only-used` | Solo servicios donde existe |
| `--csv` | Exporta a CSV |
| `--no-color` | Sin colores |
| `--no-banner` | Sin banner inicial |
| `-T, --timeout` | Timeout en segundos |

## Servicios verificados

Holehe verifica más de 120 servicios incluyendo:
- Amazon, Apple, Adobe
- Discord, Dropbox, Docker
- Facebook, GitHub, Google
- Instagram, LinkedIn, Microsoft
- Netflix, PayPal, Spotify
- Twitter, Uber, Yahoo
- Y muchos más...

## Integración con SENTINEL

En SENTINEL, Holehe se ejecuta cuando:
1. Se agrega un email al caso
2. Se quiere verificar si un email está en uso

El resultado indica en qué servicios está registrado, lo que ayuda a:
- Confirmar que el email está activo
- Encontrar más perfiles sociales
- Expandir la investigación

## Ejemplo de salida

```
[+] Email used: test@gmail.com
[+] Amazon: Registered
[+] Discord: Registered  
[+] GitHub: Registered
[-] Twitter: Not Registered
[+] LinkedIn: Registered
```

## Consideraciones

- No envía correos ni notificaciones al objetivo
- Usa las funciones de "olvidé contraseña" de cada servicio
- Algunos servicios pueden bloquear por rate limiting
- Resultados pueden variar según la región
