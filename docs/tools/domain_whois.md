# Domain WHOIS (RDAP)

Registro público de un dominio: quién lo gestiona, desde cuándo existe, cuándo
vence y qué servidores lo resuelven.

## Descripción

Usa **RDAP**, el sucesor moderno de WHOIS. La consulta va a `rdap.org`, que
redirige al registro oficial de cada extensión (Verisign para `.com`, NIC.ec para
`.ec`, PIR para `.org`, …). Funciona también con dominios de Ecuador.

**No necesita clave de API ni instalación adicional** (solo `requests`). Es
pasivo: consulta un servicio público, no toca al objetivo.

Ya existía `ipwhois` (WHOIS de **IPs**); esta herramienta cubre los **dominios**.

## Requisitos

- **Entrada obligatoria:** un dominio (ej: `empresa.com`). Si das un subdominio
  (`mail.empresa.com`), sube automáticamente al dominio registrable
  (`empresa.com`).
- **Produce:** dominio, empresa, correo (contactos no censurados).

## Uso en SENTINEL

1. Crea un caso y añade un dato de tipo **Domain**.
2. En **Herramientas**, selecciona **Domain WHOIS** y pulsa **▶ Ejecutar Tool**.
3. En **Reportes** verás un resultado principal y, si aplica, alertas y contactos.
   También corre solo en **Perfilamiento** cuando el caso tiene un dominio.

## Qué devuelve

| Resultado | Categoría | Contenido |
|---|---|---|
| `WHOIS: dominio` | Network | Registrador, fecha de alta, vencimiento, servidores de nombres, DNSSEC (y estado, edad en días, etc. en `raw_data`) |
| `⚠️ dominio: …` | Alerta | Dominio **registrado hace menos de 30 días** (señal típica de phishing), **vence en menos de 30 días** o **ya vencido** |
| `Contacto … de dominio` | Contacto | Nombre / organización / correo de registrante, administrativo o técnico, **solo si no están censurados** |

## Privacidad (LOPDP / RGPD)

La mayoría de registros censuran los datos personales (`REDACTED FOR PRIVACY`).
La herramienta **descarta esos campos y no intenta eludir la censura**. Lo que
sí aparece es lo que el propio registro publica. Úsala solo en investigaciones
autorizadas y con un propósito legítimo.

## Detalles técnicos

- Consulta: `https://rdap.org/domain/<dominio>` (cabecera `Accept: application/rdap+json`).
- Reintentos ante `429/502/503/504` (2 intentos) y caché de 1 hora.
- Si el registro responde `400/404` **o un cascarón sin datos** (algunos
  registros, como `.ec`, lo hacen para nombres no registrables), prueba con el
  dominio padre.

## Limitaciones

- Depende de que el registro de la extensión ofrezca RDAP (casi todos lo hacen).
- Los contactos suelen venir censurados; sin ellos, el valor está en registrador,
  fechas y servidores de nombres.
- Un dominio con fecha de alta reciente no es malicioso por sí solo: es una
  **señal** que hay que cruzar con otras.
