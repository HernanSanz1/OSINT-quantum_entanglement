# Mail Health (salud del correo)

Revisa cómo está configurado el correo de un dominio y si se puede **suplantar**
(enviar correo falso "desde" `gerencia@empresa.com`).

## Descripción

Consulta solo **DNS público** (pasivo: no toca ni escanea al objetivo). No
necesita clave de API; usa `dnspython`, que ya es dependencia del proyecto.

Analiza cuatro cosas:

- **MX:** qué servidor recibe el correo. Detecta proveedores comunes (Google
  Workspace, Microsoft 365, Zoho, Proofpoint, Mimecast…).
- **SPF:** qué servidores pueden enviar por el dominio. Valora el `all` final,
  cuenta las consultas DNS (límite RFC: 10) y lista los servicios que autoriza
  (`include:`), lo que revela proveedores que usa la organización.
- **DMARC:** qué hacer con los correos falsos (`none` / `quarantine` /
  `reject`). Si un subdominio no tiene DMARC propio, se informa el heredado del
  dominio padre.
- **DKIM:** prueba los selectores más comunes (`google`, `selector1`, `k1`…).

## Requisitos

- **Entrada obligatoria:** un dominio (ej: `empresa.com`).
- **Produce:** dominio.

## Uso en SENTINEL

1. Crea un caso y añade un dato de tipo **Domain**.
2. En **Herramientas**, selecciona **Mail Health** y pulsa **▶ Ejecutar Tool**.
   También corre solo en **Perfilamiento** cuando el caso tiene un dominio.

## Qué devuelve

| Resultado | Categoría | Contenido |
|---|---|---|
| `Salud de correo: dominio` | Network | Proveedor, SPF, DMARC, DKIM y **riesgo de suplantación** (alto / medio / bajo / n/a) |
| `⚠️ dominio: …` | Alerta | Hallazgos con gravedad alta, media o baja |

Hallazgos que genera:

| Gravedad | Caso |
|---|---|
| Alta | Sin SPF, sin DMARC, SPF `+all`, varios SPF (error) — solo si el dominio recibe correo |
| Media | DMARC `p=none`, DMARC sin `p=`, SPF `?all` o sin `all`, SPF con más de 10 consultas |
| Baja | DMARC con `pct` < 100, SPF con `ptr` |

Un dominio **sin MX** (o con MX nulo) no recibe correo, por lo que no se le
exige SPF/DMARC y el riesgo se marca `n/a`. `~all` (soft fail) no genera alerta:
es común y aceptable.

## Detalles técnicos

- Registros: `MX`, `TXT` del dominio, `_dmarc.<dominio>` (y padres),
  `<selector>._domainkey.<dominio>`.
- Un dominio inexistente (NXDOMAIN) o con DNS caído (SERVFAIL) no devuelve
  resultados, para no inventar datos.
- Caché de 1 hora.

## Limitaciones

- **DKIM no se puede listar**: solo se prueban selectores comunes. No
  encontrarlo no prueba que no exista (p. ej. Google usa selectores con fecha).
- No revisa MTA-STS, BIMI ni la reputación de los servidores.
- "Riesgo de suplantación" es una señal de configuración, no una prueba de que
  alguien esté suplantando el dominio.
