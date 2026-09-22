# CTI Render

Generador de boletines HTML con plantilla corporativa Altel.

## Descripción

render.py toma un dossier JSON y genera un boletín HTML listo para enviar por email. Usa la plantilla corporativa de Altel con branding consistente.

## Ubicación

```
~/jarvis/OSINT-quantum_entanglement/sentinel_unified/modules/cti/render.py
```

## Uso

```bash
cd ~/jarvis/OSINT-quantum_entanglement/sentinel_unified/modules/cti

# Renderizar dossier a HTML
python3 render.py store/dossiers/CER-2026-09-22.json

# Output específico
python3 render.py store/dossiers/CER-2026-09-22.json -o boletin_cer.html

# Preview en navegador
python3 render.py store/dossiers/CER-2026-09-22.json --preview

# Todos los dossiers del día
python3 render.py --all-today
```

## Estructura del boletín

```
+------------------------------------------+
|  [Logo Altel]    BOLETÍN DE SEGURIDAD    |
|               Septiembre 2026 - Semana 38 |
+------------------------------------------+
|  RESUMEN EJECUTIVO                        |
|  - 5 vulnerabilidades críticas            |
|  - 234 nuevos IOCs                        |
|  - LockBit activo en el sector            |
+------------------------------------------+
|  VULNERABILIDADES CRÍTICAS                |
|  +--------------------------------------+ |
|  | CVE-2026-1234 | FortiOS | CVSS 9.8  | |
|  | EPSS: 95% | KEV: Sí | Ransomware: Sí| |
|  +--------------------------------------+ |
+------------------------------------------+
|  AMENAZAS ACTIVAS                         |
|  - LockBit: 15 víctimas Latam            |
+------------------------------------------+
|  IOCs PARA BLOQUEO                        |
|  IPs: 1.2.3.4, 5.6.7.8                   |
|  Dominios: evil.com, bad.net             |
+------------------------------------------+
|  RECOMENDACIONES                          |
|  1. Actualizar FortiOS                   |
|  2. Bloquear IOCs en perimetral          |
+------------------------------------------+
|  [Pie: Altel SOC | soc@altel.com.ec]     |
+------------------------------------------+
```

## Archivos generados

```
output/
  boletines/
    boletin-CER-2026-09-22.html
    boletin-MAVESA-2026-09-22.html
```

## Personalización de plantilla

En `render.py`:
```python
TEMPLATE_CONFIG = {
    "logo_url": "https://altel.com.ec/logo.png",
    "header_color": "#003366",
    "accent_color": "#0066cc",
    "font_family": "Arial, sans-serif",
    "footer_text": "Altel SOC - Centro de Operaciones de Seguridad"
}
```

## Integración con SENTINEL

```python
from sentinel_unified.modules.cti.render import BoletinRenderer

renderer = BoletinRenderer()
html = renderer.render("store/dossiers/CER-2026-09-22.json")
# html contiene el boletín completo
# renderer.save("output/boletin.html")
# renderer.preview() abre en navegador
```

## Envío por email

El boletín se puede enviar via Microsoft Graph (skill m365):
```python
# Después de generar el HTML
from sentinel_unified.modules.cti.render import BoletinRenderer

renderer = BoletinRenderer()
html = renderer.render("store/dossiers/CER-2026-09-22.json")

# Enviar via skill m365
# El HTML es inline, no attachment
```

## Secciones del boletín

1. **Resumen ejecutivo**: Métricas clave del periodo
2. **Vulnerabilidades críticas**: CVEs priorizados para el cliente
3. **Amenazas activas**: Grupos de ransomware y APTs relevantes
4. **IOCs para bloqueo**: Listas listas para importar a firewall/SIEM
5. **Recomendaciones**: Acciones específicas priorizadas

## Tips

1. --preview es útil para revisar antes de enviar
2. El HTML es responsive para lectura en móvil
3. Los IOCs están formateados para copy/paste directo
4. Mantén el branding consistente editando TEMPLATE_CONFIG
5. Genera PDFs con wkhtmltopdf si necesitas adjuntos
