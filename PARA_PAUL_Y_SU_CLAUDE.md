# SENTINEL: contexto completo para Paul y su Claude

Documento de traspaso escrito el 21-10-2026. Resume **todo lo hecho, cambiado, mejorado, lo que falta y lo que está en
desarrollo**, para que Paul (y el Claude que use) pueda seguir trabajando sin repetir errores ni deshacer decisiones.

> **Para el Claude de Paul:** lee este archivo entero antes de tocar nada. Después lee `docs/AUDITORIA_REAL.md`
> (detalle técnico y pruebas reales de cada cambio). Si algo de este archivo contradice al `README.md`, manda este
> archivo: el README todavía tiene instrucciones antiguas (Linux, `~/.osint_v2_keys`) que ya no son válidas.

## 1. Qué es SENTINEL

Aplicación de escritorio en **Python 3.12 + PySide6** (interfaz gráfica oscura tipo SOC) para investigaciones OSINT,
pensada para un **SOC en Ecuador** (ley de protección de datos **LOPDP**). Dos objetivos:

1. **Perfilar personas reales** (figuras públicas o con autorización) y **correlacionar** todo lo que se encuentra de
   ellas: cuentas, menciones, datos de contacto públicos, homónimos.
2. **Infraestructura y amenazas (CTI):** dominios, IP, correo, URL, tecnologías y su cruce con noticias y
   vulnerabilidades explotadas.

La idea central del proyecto es la **correlación** (perfilamiento + CTI). Los módulos de "IA triple"
(Ollama/ChatGPT/Venice) se **quitaron a propósito** el 25-09-2026; no volver a meterlos.

Historia: el proyecto lo empezó Hernán (HernanSanz1, primeros 4 commits del 22 y 23-09-2026). Desde el 24-09-2026
How1 (edupera91-cpu) trabajó en una copia privada, con ayuda de Claude Code: unos 58 commits más, subidos al
original el 21-10-2026.

## 2. Reglas obligatorias (no negociables)

1. **Responder siempre en español** y explicar en palabras sencillas: los usuarios no son programadores.
2. **Repositorios:** el original es `HernanSanz1/OSINT-quantum_entanglement` (público). Desde el 21-10-2026, con
   autorización de Hernán, los cambios se suben también ahí; la copia de trabajo es
   `edupera91-cpu/OSINT-quantum_entanglement` (privada). Subir **solo cuando la persona lo pida**, mejor en una **rama
   propia** (`paul/...`) con pull request a `main`, y **nunca** reescribir la historia de `main` (nada de
   `push --force`). Antes de subir al original, comprobar que no hay commits suyos sin combinar.
3. **Claves y contraseñas:** Claude **nunca** las escribe, ni las pide por el chat, ni las pone en el código, en
   archivos de prueba o en commits. Cada persona guarda **sus propias claves** con
   `env\Scripts\python.exe -m osint_app.main --set-key NOMBRE` (las pide ocultas y las guarda cifradas). Las claves
   no se comparten entre personas.
4. **Solo figuras públicas o personas que lo autoricen.** Nada de particulares sin autorización. Los datos personales
   que salgan son confidenciales (LOPDP): no copiarlos a documentos, issues ni commits.
5. **Nada ofensivo:** sin phishing, robo de credenciales, escaneo activo agresivo ni evasión. Solo OSINT pasivo y
   defensa.
6. **Licencias:** el proyecto es privado; **no copiar código GPL** (por ejemplo Horus). Se pueden reimplementar ideas
   desde cero o usar librerías MIT, BSD o Apache.
7. **Antes de borrar algo**, buscar dónde se usa y rescatar las funciones útiles. Nunca borrar datos del usuario
   (casos, noticias CTI, carpetas antiguas) sin que lo confirme.
8. **Solo pruebas reales** (decisión del 04-10-2026): además de los tests, cada cambio se verifica con objetivos
   públicos reales y se comprueba punto a punto (abrir las URL, contrastar con otra fuente). No dar nada por bueno
   solo porque pasan los tests.
9. **Homónimos:** se **marcan y se ordenan al final**, nunca se borran automáticamente. La decisión es del analista.
10. **El correo y los demás datos públicos se muestran en la ficha** (decisión del 14-10-2026: "todo dato es
    importante en OSINT"). La ficha lleva un aviso de confidencialidad.
11. **La estética va al final.** Primero que funcione y que se entienda.
12. Por ahora **solo Windows**, pero sin cerrar la puerta a Linux y Mac: usar `pathlib` y no meter nada exclusivo de
    Windows sin alternativa.

## 3. Instalación en Windows (paso a paso)

Requisitos: Windows 10/11, **Python 3.12** (marcar "Add to PATH" al instalarlo) y Git.

```powershell
git clone https://github.com/edupera91-cpu/OSINT-quantum_entanglement.git
cd OSINT-quantum_entanglement
python -m venv env
env\Scripts\python.exe -m pip install -r osint_app\requirements.txt
env\Scripts\python.exe -m osint_app.main --check-tools     # qué herramientas están listas
env\Scripts\python.exe -m osint_app.main                   # abre la ventana "SENTINEL SOC Dashboard"
```

- **Siempre usar `env\Scripts\python.exe`**: el Python del sistema no tiene las dependencias ni pytest.
- **Herramientas opcionales de Python** (en el mismo `env`): `sherlock-project`, `maigret`, `holehe`, `instaloader`.
- **Token de GitHub (muy recomendable):** sube el límite de 60 a 5.000 consultas por hora. Cada uno crea el suyo en
  GitHub → Settings → Developer settings → *Fine-grained tokens* (solo repositorios públicos, sin permisos, 90 días)
  y lo guarda **él mismo** con `--set-key GitHub`.
- **Ver qué claves hay** (nunca muestra el valor): `env\Scripts\python.exe -m osint_app.main --keys`.
- **Tests:** `env\Scripts\python.exe -m pytest osint_app/tests -q -p no:cacheprovider` (983 tests, unos 12 s).
- **Batería de pruebas reales** (usa internet): `env\Scripts\python.exe scripts\auditoria_real.py`.

### Docker y SearXNG (buscador propio)

Ver la sección 6 para el porqué. Instalación hecha y probada en Windows 11 Home:

1. En PowerShell **como administrador**: `wsl --install --no-distribution` y reiniciar.
2. `winget install -e --id Docker.DockerDesktop` (como administrador). Abrir Docker Desktop, aceptar y esperar a que
   diga **"Engine running"**.
3. `env\Scripts\python.exe scripts\searxng_local.py start`: crea la configuración del usuario con su propia clave
   secreta (fuera del proyecto), levanta el contenedor `sentinel-searxng` **solo en `127.0.0.1:8888`** y lo conecta
   con SENTINEL. También hay `status` y `stop`.
4. Docker Desktop exige licencia de pago en organizaciones de más de 250 empleados o 10 millones de USD de
   facturación.

Sin Docker, SENTINEL **sigue funcionando** con los buscadores de respaldo y avisa de que SearXNG no responde.

## 4. Dónde se guardan los datos (nada personal dentro del proyecto)

| Qué | Dónde | Notas |
|---|---|---|
| Casos (base SQLite `osint_v2.db`) | `%LOCALAPPDATA%\SENTINEL\` | Antes estaba dentro del proyecto (OneDrive). Se copió sin borrar la original. Se cambia con `SENTINEL_DATA_DIR` |
| Claves de API | Baúl cifrado con **DPAPI** de Windows en la carpeta personal | Nunca en el proyecto. En Linux/Mac aún no se cifra (pendiente: `keyring`) |
| Noticias CTI, dossiers y boletines | `%LOCALAPPDATA%\SENTINEL\cti\` (y `cti\boletines\`) | Movido el 14-10-2026; git ya no vigila las carpetas antiguas |
| Configuración de SearXNG | `%LOCALAPPDATA%\SENTINEL\searxng\` | La plantilla está en `deploy/searxng/settings.yml` |
| Fichas HTML y exportaciones | Carpeta Descargas | Pendiente: carpeta segura |

La app **avisa** si la carpeta de datos está en una carpeta sincronizada con la nube (OneDrive, Dropbox…). Los tests
usan siempre una carpeta temporal (`conftest.py` de la raíz) y **nunca** tocan los datos reales.

## 5. Mapa del código

```text
osint_app/
  main.py               Arranque: GUI, --check-tools, --keys, --set-key
  framework.py          Registro y ejecución de herramientas (un análisis por cada dato marcado, máx. 25)
  profiler_engine.py    Perfilamiento de personas: herramientas en paralelo, candidatos, homónimos, 2ª ronda
  correlation_engine.py Entidades, correlación del caso, correlación cruzada entre casos, cruce con CTI
  cti_link.py           Lee e indexa las noticias CTI (por CVE y por tecnología)
  case_manager.py, db/  Casos y base de datos
  gui/                  app.py (ventana), tab_cases, tab_data, tab_tools, tab_profiling, tab_correlation,
                        tab_reports, tab_cti, components.py (incluye DevNotice: franja "EN DESARROLLO")
  tools/                Herramientas (ver sección 7)
  reports/              person_report.py (ficha HTML de una persona), readable.py (reportes legibles), html_report.py
  utils/                search_engine.py (búsqueda multimotor), homonyms.py, identity.py, person_match.py,
                        data_paths.py (rutas de datos), secret_vault.py + dpapi.py (claves), data_validation.py,
                        entity_filters.py + tlds.txt, geo_data.py, directories.py, key_cli.py
  tests/                983 tests (pytest)
sentinel_unified/modules/cti/   Scripts CTI: harvest.py (recoger), dossier.py, render.py (boletín), fuentes, clientes
scripts/                auditoria_real.py, searxng_local.py, cti_metrics.py
deploy/searxng/         Plantilla de SearXNG (versión 2)
docs/                   AUDITORIA_REAL.md, MANUAL_USUARIO.md, MANUAL_DESARROLLADOR.md, tools/*.md (ficha de cada herramienta)
```

## 6. Por qué se empezó a usar Docker

El perfilamiento depende de **buscar a la persona en la web**, y ese fue el fallo más grave que se encontró:

1. La búsqueda original raspaba **DuckDuckGo**, que **bloquea por ráfagas** (límite por IP de 10 a 30 minutos o más).
   Tras 2 o 3 perfiles seguidos las búsquedas devolvían 0 resultados **sin avisar**.
2. Se probaron otros motores gratuitos desde Ecuador (04-10-2026): solo Yahoo respondía bien; Google, Brave, Mojeek,
   Startpage y DuckDuckGo (vía `ddgs`) daban 0 por bloqueo.
3. **Brave Search API** era la solución oficial, pero **desde febrero de 2026 ya no es gratis**: pide tarjeta y da
   unos 5 USD de crédito al mes (unas 1.000 consultas). Queda como opción (`--set-key BraveSearch`); el usuario aún
   no la ha contratado.
4. Se eligió **SearXNG**, un metabuscador libre que cada uno aloja: reparte las consultas entre varios buscadores,
   así que un bloqueo no deja la búsqueda en cero. Plantilla 3 (21-10-2026): **Yandex, Yep, Yahoo y Bing** son los que
   responden desde Ecuador; Google, Qwant y DuckDuckGo dan "403" desde la primera consulta y Brave ya no se puede leer
   (medido con un SearXNG de prueba aparte, buscador por buscador). No hay servidor compartido, así que se ejecuta en
   **Docker en el propio equipo** (solo accesible desde ese equipo).
5. **Medido con 10 búsquedas reales de personas:** con SearXNG, 94 resultados relevantes en 21 s; sin él, 74 en 49 s.

Orden de búsqueda actual (`utils/search_engine.py`): Brave (si hay clave) → SearXNG (si está configurado) → Yahoo y
modo "auto" de `ddgs` → DuckDuckGo. Cada motor que falla se aparta un tiempo ("enfriamiento"; SearXNG, 120 s).

**Filtro de pertinencia:** si la consulta lleva un nombre de 2+ palabras entre comillas, se descartan los resultados
que no lo mencionan (sin tildes, también en la URL). Bing ignora las comillas cuando el nombre lleva tildes y con
`"Jefferson Pérez"` devolvía páginas de Thomas Jefferson.

Si aun así los buscadores se bloquean, la app **avisa con "⚠️ búsqueda web INCOMPLETA"** (registro, resumen y ficha)
en vez de dar 0 en silencio, y no guarda en caché las búsquedas incompletas. Prueba real del 21-10-2026: 3 perfiles
seguidos sin pausa, 28 consultas, **0 incompletas** y el 98 % de los resultados sobre la persona buscada.

## 7. Herramientas: estado actual

Leyenda: **Nueva** = creada en esta copia · **Arreglada** = estaba rota o daba datos falsos · **Pulida** = mejorada.
Todas tienen tests y ficha en `docs/tools/`.

| Herramienta | Estado | Qué se hizo |
|---|---|---|
| WebSearch | Arreglada | Búsqueda multimotor (antes GET + regex = 0 resultados); avisa si queda incompleta |
| Google Dorks | Arreglada | Usa el buscador común; espera de 2 a 5 s; sin caché de búsquedas incompletas |
| Wikidata | Nueva | Ficha de figuras públicas y **cuentas oficiales**; detecta homónimos en vez de adivinar |
| GitHubOSINT | Pulida | Redes vinculadas y correos de commits; usa el token del baúl |
| UsernameVariants | Pulida | Variantes (inicial + apellido + año…); ya no cuenta como candidato |
| IP Reputation | Nueva | Shodan InternetDB, GreyNoise, Tor, Spamhaus DROP, FireHOL, URLhaus (sin clave); avisa si la IP no es válida |
| crt.sh | Nueva | Subdominios por Certificate Transparency |
| Domain WHOIS | Nueva | WHOIS por RDAP (.edu no tiene RDAP) |
| Mail Health | Nueva | MX, SPF, DMARC y DKIM: riesgo de suplantación |
| File Metadata | Nueva | EXIF de fotos, PDF y Office (URL o archivo local) |
| Link Shield | Nueva | Riesgo de una URL sin visitarla, más OpenPhish y URLhaus; sigue solo acortadores |
| Tech Detect | Nueva | Tecnologías y versiones expuestas; alimenta el cruce con CTI |
| Wayback, dnspython, ipwhois, phonenumbers | Revisadas | Limpieza de ruido en las entidades extraídas |
| Sherlock | Arreglada | Sin ventanas de consola; sus resultados salen como "SIN VERIFICAR" |
| Maigret | Arreglada | Formato JSON real y etiquetas para ocultar sitios sensibles. **Ver fallo nuevo en la sección 10** |
| Holehe, Instaloader | Arregladas | Instagram exige sesión; aplazado por decisión del usuario |
| Hunter.io | Lista | Necesita clave propia (opcional) |
| CENSYS | Rota | Usa la API antigua: hay que migrarla a `censys.search` y necesita clave |
| Subfinder, Amass, TheHarvester, SpiderFoot, Recon-ng | Sin probar | Hace falta instalar Go o sus programas |
| IntelOwl, OpenCTI, MISP, Cortex, IntelMQ | Plantillas | Sin código real; hace falta un servidor de prueba |
| GHunt, snscrape | Sin probar | GHunt necesita sesión de Google |

## 8. Lo hecho, por fases (con commits)

1. **24-09: limpieza y CI.** Falsos positivos de `--check-tools`, PySide6 en requirements, CI de GitHub (ruff con
   errores graves + pytest; y super-linter para Markdown), copias duplicadas fuera, legado con datos personales fuera.
2. **24 y 25-09: perfilador.** Respeta las herramientas elegidas, recibe contexto y país, guarda en un caso, "Refinar
   búsqueda", avisos de homónimos sin descartar, nombres de usuario sacados de las URL y **búsqueda encadenada**
   (segunda ronda con los usuarios descubiertos).
3. **25 a 28-09: correlación ↔ CTI.** Fuera la IA triple. Lector del almacén CTI, cruce de CVE y tecnologías del caso
   con amenazas explotadas, botón "Cruzar con CTI", Tech Detect, métricas reales (homónimos: precisión y cobertura del
   100 % sobre 20 casos; CTI: 71 tecnologías de clientes, 46 con CVE y 43 con CVE explotado).
4. **28-09 a 01-10: herramientas nuevas.** Token de GitHub, crt.sh, Domain WHOIS, Mail Health, File Metadata y Link
   Shield (medido con 300 phishing reales de OpenPhish y 3.000 sitios legítimos de Tranco).
5. **02-10: seguridad de datos.** Base fuera de OneDrive, claves cifradas con DPAPI, aviso de nube, comando
   `--set-key`, directorios de personas que ya no cuentan como candidatos, semilla rica (alias, ciudad, empresa…).
6. **03 y 04-10: tests y auditoría real.** Unos 1.000 tests; auditoría con objetivos reales (`docs/AUDITORIA_REAL.md`):
   búsqueda multimotor, Wikidata, IP Reputation, Maigret, Holehe e Instaloader arreglados, correlación limpia
   (55 → 20 entidades), HTML escapado.
7. **05 a 12-10: SearXNG con Docker y perfiles variados.** Perfiles reales (Boscán, Caicedo, Luisito Comunica,
   midudev, Ulloa…), encadenado corroborado, menciones, **ficha HTML legible** para no técnicos ("Generar Ficha") y
   pestaña Reportes legible.
8. **13-10: primera evaluación como usuario final** (Claude Cowork usando solo la interfaz). Notas: facilidad 5,
   utilidad 6, fiabilidad 5, claridad 5, ficha 6; 83 % de aciertos en los 10 primeros candidatos; unos 108 s por
   perfil; ningún cuelgue. **Todo lo que encontró se corrigió** (commits `5d27900` y `aaf6178`): aviso de búsqueda
   incompleta, todos los objetivos marcados, homónimos mejor ligados (gentilicio, contexto, web propia, cuenta
   oficial, nacionalidad), sitios sensibles ocultos en la ficha, "SIN VERIFICAR", detección automática del tipo de
   dato con validación, el perfil se vacía al cambiar de caso, "Refinar" en el mismo caso, exportar todo, botón Tor
   honesto (solo afecta a la terminal avanzada y comprueba el puerto 9050), "Opciones avanzadas", textos en español.
9. **14-10: CTI fuera del proyecto** (`3559a5d`). "Actualizar noticias" ya guarda de verdad (prueba real: 15 fuentes
   en 20 s, 2.029 noticias nuevas, 6.053 en total, sin duplicados). Franja **"EN DESARROLLO"** en CTI y Correlación.
10. **21-10:** `--check-tools` y `--keys` ya no se rompen en la consola de Windows por los emojis.

## 9. En desarrollo (funciona, pero no está terminado)

- **Correlación:** dentro de un caso y entre casos funciona (la cruzada solo usa correo, usuario, teléfono, dominio,
  IP o URL; ya no une casos por "país: Ecuador"). El cruce con CTI es básico: solo compara CVE y nombres de tecnología.
- **CTI:** recoger noticias, dossier por cliente (GLOBAL, CER, MAVESA, XTRIM, SERVIANDINA) y boletín HTML funcionan.
  "Validar" y "Enviar" (correo) están desactivados porque no están programados.
- La franja amarilla "EN DESARROLLO" (`DevNotice`) se quita cuando el cruce caso ↔ CTI sea real.

## 10. Segunda evaluación de usuario final: en curso (hallazgos parciales)

Cowork empezó el 14-10-2026 (bitácora fuera del repositorio, en la carpeta `evaluaciones` del equipo de How1) y se
pausó a mitad. Quedan midudev, Glenda Morejón, Gonzalo Plata, Correlación, Reportes, CTI y robustez.

- **Mejoró:** perfiles en unos 72 s (antes unos 80); **10 de 10 aciertos** en los 10 primeros de Boscán, Caicedo,
  Jefferson Pérez y Luisito; los avisos de búsqueda incompleta funcionan; están confirmados como corregidos todos los
  puntos de la evaluación 1 que se repitieron.
- **Fallos nuevos por corregir (prioridad alta primero):**
  1. **CORREGIDO (21-10):** la tabla de candidatos se veía con altura 0 en pantallas de portátil (1366×768,
     1536×864). Ahora tabla, detalles y registro van en un separador arrastrable (de 0 a 5 filas en 1536×864).
  2. **CORREGIDO (21-10):** Windows (Smart App Control) bloqueaba `env\Scripts\maigret.exe`, el lanzador sin firma
     que crea pip (WinError 4551; 18 bloqueos en el registro CodeIntegrity). Maigret, Sherlock y Holehe se lanzan ahora
     con el Python de SENTINEL (`utils/python_cli.py`) y, si algo se bloquea, se explica en palabras sencillas.
     Prueba real: Maigret con midudev, 38 perfiles en 66 s, 0 bloqueos. Pendiente menor: Maigret da como perfil una
     búsqueda de Stack Overflow (`users/filter?search=`).
  3. **CORREGIDO (21-10):** búsqueda incompleta desde el primer perfil. Solo 2-3 buscadores de SearXNG respondían
     (Bing, Yahoo, Google CSE) y Bing metía basura con nombres con tildes. Plantilla 3 con Yandex y Yep + filtro de
     pertinencia: 3 perfiles seguidos sin pausa, 0 de 28 consultas incompletas.
  4. Sitios sensibles no ocultos: `cracked.ax` (foro de cracking) y `cavalier.hudsonrock.com` (credenciales robadas).
  5. **CORREGIDO (21-10):** homónimos en "Cuentas" y cuentas suyas en "otra persona". Las cuentas y la web oficiales
     de Wikidata ya no bajan de 85 y salen como "Oficial"; el mismo usuario que una cuenta suya (reypalomo_) se queda
     con una nota; un perfil sin nada del nombre (LinkedIn "net-worth-fever") pasa a menciones; con < 40 % y solo el
     nombre (GitHub "jefferson-quezada") pasa a "otra persona" con el motivo (`person_report._sort_accounts`).
     Verificado con perfiles reales de Jefferson Pérez, Boscán y Luisito. La franja "Búsqueda incompleta" de la ficha
     ya solo recoge la búsqueda web (el aviso de DNS de Maigret salía en todos los perfiles).
  6. **CORREGIDO (26-10):** Forbes Colombia sobre Luisito iba a "otra persona" por "menciona Colombia": un alias
     distintivo (2+ palabras, fuera del nombre legal) liga el texto a la persona (`homonyms._mentions_alias`).
     Pendiente: Maigret avisa en todos los perfiles de "muchos sitios fallaron por red o DNS"; es.linkedin.com se
     toma como "de España".
  7. Menores: la barra de estado inferior no se actualiza al cambiar de caso; la columna de estado de Herramientas
     corta el texto; jerga en las guías (RDAP, DKIM, "note"); faltan tildes en "busqueda" y "Ejecucion"; tooltip de
     Hunter con un comando de consola; la tabla CTI sale vacía hasta refrescar.

## 11. Lo que falta (orden de trabajo acordado)

1. Corregir los fallos de la sección 10 y **terminar la segunda evaluación** con Cowork.
2. **HECHO (26-10): ficha desde un caso guardado y PDF.** El caso guarda la semilla exacta y los avisos
   (`profile_runs`) y las decisiones del analista (`candidate_verdicts`); `reports/case_profile.py` rehace los
   candidatos con la puntuación actual (casos antiguos incluidos, desde sus datos "seed"); el PDF sale del motor web
   de Qt (`gui/pdf_export.py`). Verificado con los casos reales #24-#28.
3. **Cruce real caso ↔ CTI** (dominios, IP y tecnologías del caso contra las amenazas guardadas); después, quitar la
   franja "EN DESARROLLO".
4. **Carpeta segura** para fichas e informes (hoy van a Descargas sin cifrar; la base tampoco está cifrada en disco:
   recomendar BitLocker).
5. **Herramientas pesadas:** instalar Go y probar Subfinder y Amass; después TheHarvester, SpiderFoot y Recon-ng.
6. **Limpieza de código:** importaciones sin uso que ya existían (`ruff check --select F401`), ruta fija de SpiderFoot
   en `binary_map` de `tab_tools`, archivos muy grandes.
7. **CENSYS:** migrar a la API actual (cada usuario con su clave).
8. **Linux y Mac:** baúl de claves con `keyring` y revisar rutas y procesos.
9. **Asistente `--setup`** (al final): detectar sistema y Python, instalar dependencias y herramientas opcionales
   preguntando, token de GitHub guiado, Docker + SearXNG, Instagram opcional y verificación con
   `scripts/auditoria_real.py`.

También pendiente:

- **Instagram:** aplazado. El método que funciona es iniciar sesión en Firefox con una cuenta secundaria y luego
  `instaloader --load-cookies firefox` (necesita `browser_cookie3`).
- **MailAccess** (MIT): probar en Windows antes de integrarlo.
- **Homónimos, enfoque C** (futuro): descartar solo lo clarísimo y dejarlo en una papelera recuperable.
- **InternetDB** devuelve a veces nombres de host raros (por ejemplo, para 8.8.8.8).
- El **README** está desactualizado: reescribirlo a partir de este archivo.

## 12. Cómo trabajar en este proyecto (lecciones aprendidas)

- **Cada cambio:** test que lo cubra + **prueba real** con un objetivo público + suite completa en verde + anotarlo
  en `docs/AUDITORIA_REAL.md` si cambia el comportamiento.
- **CI de GitHub** en cada push: "Tests Python" (ruff con errores graves + pytest en Windows y Ubuntu, con Python 3.12 y 3.14) y "Lint Code
  Base" (super-linter con **markdownlint**, solo en los archivos `.md` que cambian; exige lenguaje en los bloques de
  código, nada de URL sueltas y títulos sin dos puntos). Esperar a que ambos estén en verde.
- **No suponer el orden de hilos** en los tests (falló una vez en Ubuntu con Python 3.14).
- **Barras invertidas:** al editar con heredoc o `sed` desde bash se pierden (`\b`, `\d`, rutas de Windows). Usar la
  herramienta de edición de archivos o `chr(92)`.
- **Buscadores:** no lanzar perfilamientos en ráfaga mientras se prueba; espaciarlos unos 3 minutos.
- **Wikimedia** responde 429 si el User-Agent no lleva contacto: no poner el correo personal de nadie en el código.
- **Mensajes de commit** en español, explicando el porqué. En PowerShell 5.1, pasar mensajes largos con
  `git commit -F archivo.txt`.
- **Puntuación de candidatos:** ≥ 70 o confirmado = cuenta clara; con una cuenta clara en una plataforma, las demás de
  esa plataforma pasan a "posiblemente otra persona".

## 13. Primer mensaje sugerido para el Claude de Paul

```text
Lee PARA_PAUL_Y_SU_CLAUDE.md y docs/AUDITORIA_REAL.md completos. Respeta las reglas de la sección 2.
Instala el proyecto en mi Windows siguiendo la sección 3 (yo guardaré mis propias claves con --set-key),
ejecuta los tests y --check-tools, y dime qué funciona y qué falta en mi equipo.
Luego propón cómo empezar por el punto 1 de la sección 11, trabajando en una rama propia.
```
