# Documentación de Herramientas SENTINEL

Este directorio contiene la documentación detallada de cada herramienta integrada en SENTINEL.

Cada archivo incluye: descripción, instalación, parámetros, ejemplos de uso, e integración con SENTINEL.

## Índice

### Perfilamiento (PROFILE)
- [Google Dorks](google_dorks.md) - Búsqueda avanzada con operadores
- [Hunter.io](hunter.md) - Emails corporativos verificados
- [Holehe](holehe.md) - Email en servicios web
- [Sherlock](sherlock.md) - Username en +300 sitios
- [Maigret](maigret.md) - Username profundo en +2500 sitios
- [GHunt](ghunt.md) - OSINT de cuentas Google

### Reconocimiento (RECON)
- [Subfinder](subfinder.md) - Subdominios pasivos
- [Amass](amass.md) - Enumeración completa de infraestructura
- [TheHarvester](theharvester.md) - Emails, hosts y empleados
- [Censys](censys.md) - Certificados, IPs y servicios
- [Wayback](wayback.md) - Histórico de páginas web
- [SpiderFoot](spiderfoot.md) - OSINT automatizado +200 módulos

### Threat Intelligence (CTI)
- [Harvest](cti_harvest.md) - Recolector de feeds (KEV, ransomware, abuse.ch)
- [Dossier](cti_dossier.md) - Generador de informes por cliente
- [Render](cti_render.md) - Boletines HTML con plantilla corporativa

## Estado de herramientas

| Herramienta | Instalada | Requiere API | Comando |
|-------------|-----------|--------------|---------|
| Google Dorks | ✅ | No | Interno (DuckDuckGo) |
| Hunter.io | ✅ | Sí (25/mes gratis) | Interno |
| Holehe | ❌ | No | `pip install holehe` |
| Sherlock | ❌ | No | `pip install sherlock-project` |
| Maigret | ✅ | No | `maigret` |
| GHunt | ❌ | No | `pip install ghunt` |
| Subfinder | ✅ | Opcional | `subfinder` |
| Amass | ✅ | Opcional | `amass` |
| TheHarvester | ❌ | Opcional | `pip install theHarvester` |
| Censys | ✅ | Sí (250/mes gratis) | Interno |
| Wayback | ✅ | No | Interno |
| SpiderFoot | ✅ | Opcional | `python3 sf.py -l 127.0.0.1:5001` |

## Uso rápido

```bash
# Lanzar GUI SENTINEL
cd ~/jarvis/OSINT-quantum_entanglement && python3 -m osint_app.main

# Verificar herramientas instaladas
python3 -m osint_app.main --check-tools
```

## Agregar nueva herramienta

1. Crear wrapper en `osint_app/tools/nombre_tool.py`
2. Implementar método `run()` que retorne resultados estructurados
3. Registrar en `osint_app/tools/__init__.py`
4. Crear documentación en `docs/tools/nombre_tool.md`
5. Agregar a esta tabla de estado
