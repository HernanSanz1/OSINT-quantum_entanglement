# Token de GitHub (opcional, recomendado)

Las herramientas que consultan GitHub (**GitHubOSINT**, **UsernameVariants**, el
perfilador) funcionan sin clave, pero **sin token** GitHub limita a **60
peticiones por hora** por IP. Un solo perfilamiento consume decenas, así que el
límite se agota rápido.

Con un token, el límite sube a **5.000 peticiones/hora**. El token solo necesita
permisos de **lectura pública** (no requiere acceso a repos privados).

## Cómo generarlo (1 vez, ~1 minuto)

1. Entra en GitHub → **Settings** → **Developer settings** →
   **Personal access tokens** → **Fine-grained tokens** (o *Tokens classic*).
2. **Generate new token**. Nombre: `SENTINEL OSINT`. Caducidad: la que prefieras.
3. Permisos: con **acceso de solo lectura público** basta (un token *classic*
   sin marcar ningún scope ya sirve para la API pública).
4. **Genera** el token y **cópialo** (se muestra una sola vez).

## Cómo añadirlo a SENTINEL

Elige UNA de estas formas (nunca se sube al repositorio):

- **Archivo de claves** (`~/.osint_v2_keys`), añade la línea:
  ```
  GitHub=ghp_tu_token_aqui
  ```
- **Variable de entorno** (estándar de GitHub):
  ```
  GITHUB_TOKEN=ghp_tu_token_aqui
  ```

SENTINEL lo detecta automáticamente en el arranque. No hace falta nada más.

> Nota de seguridad: el token es como una contraseña. No lo compartas ni lo
> subas a ningún repositorio. Si se filtra, revócalo en GitHub y genera otro.
