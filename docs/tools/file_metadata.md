# File Metadata (metadatos de archivos)

Extrae lo que un archivo revela sin que su autor lo note: dónde y con qué cámara
se tomó una foto, quién creó un documento, con qué programa y en qué organización.

## Descripción

Recibe la **URL pública** de una imagen, PDF o documento Office (o la **ruta de un
archivo local**) y lee sus metadatos. Es pasivo: solo descarga el archivo indicado.
No necesita clave de API.

| Tipo | Qué lee |
|---|---|
| **Imágenes** JPEG, PNG, WebP, TIFF | EXIF: marca y modelo de cámara, objetivo, número de serie, propietario, programa de edición, autor, fecha de captura (con zona horaria si existe) y **coordenadas GPS** con enlace al mapa |
| **PDF** | Autor, creador, productor, título, asunto, páginas, fechas de creación y modificación (con zona horaria) |
| **Office** (.docx, .xlsx, .pptx) | Autor, último en modificar, organización, programa y versión, título, fechas, revisión |

El tipo se detecta por el **contenido**, no por la extensión.

## Requisitos

- **Entrada obligatoria:** un dato de tipo **URL** en el caso (o la ruta de un archivo).
- Dependencias: `Pillow`, `pypdf` y `defusedxml` (`pip install -r osint_app/requirements.txt`).

## Uso en SENTINEL

1. Crea un caso y añade un dato de tipo **URL** con la dirección directa del archivo
   (por ejemplo `https://sitio.com/foto.jpg`) o la ruta de un archivo en tu equipo.
2. En **Herramientas**, selecciona **File Metadata** y pulsa **▶ Ejecutar Tool**.

No corre sola en Perfilamiento: necesita un archivo concreto, no un nombre o dominio.

## Qué devuelve

| Resultado | Categoría | Contenido |
|---|---|---|
| `Metadatos: archivo` | Metadatos | Resumen: equipo, fecha, programa, autor, organización, GPS… (todo en `raw_data`) |
| `⚠️ archivo: …` | Alerta | Hallazgos con gravedad: **alta** GPS; **media** número de serie, propietario, autor, organización; **baja** modificado por otra persona |

Si el archivo **no tiene metadatos** lo dice explícitamente: muchas webs y redes
sociales los borran al subir el archivo, así que su ausencia no prueba nada.

## Privacidad (LOPDP / RGPD)

Las coordenadas GPS y los nombres de autor son **datos personales**. Úsala solo en
investigaciones autorizadas y con un propósito legítimo; conserva y comparte el
resultado con el mismo cuidado que cualquier dato personal.

## Seguridad de la descarga

- Solo `http`/`https`; bloquea direcciones locales y privadas, **también cuando el
  nombre del servidor resuelve a una IP interna**.
- Valida cada redirección (máx. 3) y limita el tamaño a **15 MB**.
- El XML de Office se lee con `defusedxml` (rechaza entidades y DTD maliciosas).
- Identifica la herramienta con un `User-Agent` propio. Un reintento ante `429/503`
  respetando `Retry-After`.

## Limitaciones

- Una URL de **página web** no sirve: hace falta el enlace directo al archivo.
- No lee XMP, HEIC/HEIF, ni formatos antiguos de Office (.doc, .xls).
- La fecha EXIF no trae zona horaria salvo que la cámara la guarde.
- Un autor como "Picasa" o "Administrador" es el nombre del programa o del usuario del
  equipo, no necesariamente una persona.
- Algunos servidores (p. ej. Wikimedia) limitan los clientes que no declaran un
  contacto en el `User-Agent`; en ese caso se informa `HTTP 429`.
