# Tech Detect

Identificación de **tecnologías/vendors** de un objetivo web.

## Descripción

A partir de un dominio, hace **una petición HTTP** y deduce qué tecnologías usa
el sitio por sus huellas: cabeceras de respuesta, cookies, la etiqueta
`<meta name="generator">` y marcadores en el HTML. Detecta:

- **Servidores web:** nginx, Apache, Microsoft IIS, LiteSpeed, OpenResty.
- **Lenguajes/frameworks:** PHP, ASP.NET, Express.
- **CDN / WAF / seguridad:** Cloudflare, Akamai, F5 BIG-IP, Imperva, Sucuri,
  Fortinet, Citrix, AWS/CloudFront.
- **CMS:** WordPress, Drupal, Joomla, Shopify, Wix, TYPO3, HubSpot.
- **Colaboración/correo:** Microsoft Exchange, Atlassian.

Los nombres se **alinean con los vendors del CTI**, de modo que al cruzar con la
inteligencia de amenazas (botón *Cruzar con CTI* en la pestaña Correlación) se
obtienen los CVEs activos de esa tecnología. Ejemplo: si detecta **Fortinet**,
el CTI muestra sus vulnerabilidades explotadas.

Sin clave de API ni binarios (solo `requests`, ya incluido).

## Requisitos

- **Entrada:** un dominio (ej: `empresa.com`) o una URL.
- **Produce:** tecnologías (entidad de tipo tecnología/vendor).

## Uso en SENTINEL

1. Añade un dato de tipo **Domain** al caso.
2. Pestaña **Herramientas** → **Tech Detect** → **▶ Ejecutar Tool**.
3. Las tecnologías aparecen en **Reportes**.
4. En **Correlación**, pulsa **🛡️ Cruzar con CTI**: verás qué tecnologías del
   objetivo tienen CVEs activos.

## Limitaciones

- Es una detección por huellas conocidas: no identifica tecnologías sin firma.
- Hace una sola petición al sitio; no rastrea rutas internas.
- CDN/WAF por delante (p. ej. Cloudflare) pueden ocultar la tecnología real de
  origen.
