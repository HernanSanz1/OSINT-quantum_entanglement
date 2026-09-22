# Hunter.io

Plataforma de búsqueda y verificación de emails corporativos.

## Descripción

Hunter.io encuentra emails asociados a un dominio, verifica si son válidos, y proporciona información sobre el formato de email de una empresa.

## Requisitos

- API Key gratuita: 25 búsquedas/mes
- API Key de pago: desde $49/mes

Obtener key: https://hunter.io/api_keys

## Uso desde API

### Domain Search

```bash
curl "https://api.hunter.io/v2/domain-search?domain=ejemplo.com&api_key=KEY"
```

Respuesta:
```json
{
  "data": {
    "domain": "ejemplo.com",
    "pattern": "{first}.{last}",
    "emails": [
      {
        "value": "juan.perez@ejemplo.com",
        "type": "personal",
        "confidence": 95,
        "first_name": "Juan",
        "last_name": "Perez",
        "position": "IT Manager"
      }
    ]
  }
}
```

### Email Finder

```bash
curl "https://api.hunter.io/v2/email-finder?domain=ejemplo.com&first_name=Juan&last_name=Perez&api_key=KEY"
```

### Email Verifier

```bash
curl "https://api.hunter.io/v2/email-verifier?email=juan.perez@ejemplo.com&api_key=KEY"
```

Estados: valid, invalid, accept_all, unknown

## Campos de respuesta

| Campo | Descripción |
|-------|-------------|
| `value` | Email encontrado |
| `type` | personal o generic (info@, admin@) |
| `confidence` | Porcentaje de confianza |
| `first_name` | Nombre |
| `last_name` | Apellido |
| `position` | Cargo |
| `department` | Departamento |
| `sources` | URLs donde se encontró |

## Integración con SENTINEL

```python
from osint_app.tools.hunter import HunterTool

tool = HunterTool(api_key="tu_key")
results = tool.run(domain="ejemplo.com")
# Retorna emails con metadatos
# Se guardan en data_extracts con confidence score
```

## Límites de la API gratuita

- 25 búsquedas de dominio/mes
- 50 verificaciones/mes
- 10 búsquedas de email/mes

## Tips

1. Usa Domain Search primero para ver el patrón de email
2. Verifica emails importantes antes de usarlos
3. Combina con Holehe para ver en qué servicios están registrados
4. Los emails de tipo "generic" son menos útiles para OSINT de personas
5. El campo `sources` te dice dónde está expuesto el email
