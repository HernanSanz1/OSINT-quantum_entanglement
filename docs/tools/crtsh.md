# crt.sh

Descubrimiento pasivo de subdominios vía **Certificate Transparency**.

## Descripción

Cada certificado HTTPS emitido queda registrado en logs públicos de
transparencia de certificados (Certificate Transparency). [crt.sh](https://crt.sh)
es un buscador gratuito de esos registros. Consultando todos los certificados de
un dominio se obtienen, de paso, sus subdominios (correo, vpn, admin, dev, …).

A diferencia de Subfinder o Amass, **no necesita clave de API ni binarios
externos** (no requiere Go): funciona solo con la librería `requests`, que ya es
dependencia del proyecto. Es 100 % pasivo: no genera tráfico hacia el objetivo,
solo consulta un servicio público.

## Requisitos

- **Entrada obligatoria:** un dominio (ej: `empresa.com`).
- **Produce:** subdominios.
- **Sin clave de API. Sin instalación adicional.**

## Uso en SENTINEL

1. Crea un caso y añade un dato de tipo **Domain** (ej: `empresa.com`).
2. En la pestaña **Herramientas**, selecciona **crt.sh** y pulsa **▶ Ejecutar Tool**.
3. Los subdominios aparecen en **Reportes**, cada uno como un resultado con su URL.

También se ejecuta automáticamente en la pestaña **Perfilamiento** cuando el
caso tiene un dominio.

## Detalles técnicos

- Consulta: `https://crt.sh/?q=%25.<dominio>&output=json`.
- Limpieza: quita comodines (`*.`), pasa a minúsculas, **deduplica** y descarta
  nombres fuera de ámbito (p. ej. `empresa.com.sitio-falso.com` se ignora).
- **Reintentos:** crt.sh devuelve `502/503` de forma intermitente; la herramienta
  reintenta hasta 3 veces con espera antes de rendirse.
- Tope de 500 subdominios por consulta y caché de 30 min para no repetir
  peticiones.

## Limitaciones

- Solo encuentra subdominios que hayan tenido **certificado**; no descubre los que
  nunca usaron HTTPS público.
- crt.sh puede ir lento o caerse temporalmente; en ese caso, reintenta más tarde.
