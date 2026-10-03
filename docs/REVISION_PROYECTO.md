# Revisión del proyecto SENTINEL — fallos, riesgos y mejoras

Fecha: 2026-10-01. Revisión de código, pruebas con datos reales y comprobaciones
automáticas. Enfoque: **buscar personas reales y correlacionar su información**.

Cada hallazgo indica si está **verificado** (reproducido con una prueba o dato real) o
es una **sospecha** (leído en el código, sin reproducir). Nada de esto se ha modificado:
es una lista para decidir qué se hace y en qué orden.

Estado general: la integración continua está en verde (Ubuntu y Windows, Python 3.12 y
3.14) y los 429 tests pasan. Los fallos de abajo no los detectan los tests actuales.

---

## Estado de los hallazgos (actualizado 2026-10-01)

| Hallazgo | Estado | Cómo se comprobó |
|---|---|---|
| C1 datos personales en el repositorio | **Parcial**: dejaron de versionarse en tu copia (los archivos siguen en tu disco). Falta avisar a Hernán y limpiar el historial público | `git rm --cached` + `.gitignore`; nada del código los usa |
| C2 tiempo límite del perfilador | **Corregido** | 3 tests nuevos; una herramienta lenta ya no tira el resto (2 s en vez de 6 s y sin perder resultados) |
| C3 `raw_data` no se guardaba | **Corregido** | 4 tests nuevos de ida y vuelta por la base de datos |
| A1 correlaciones | **Corregido**: se calculan sobre todo el caso, no dependen del orden y se muestran todas | 4 tests nuevos |
| A2 faltan entidades de perfil/nombre/organización | **Hecho**: `profile`, `name`, `company`, `location` y 7 relaciones nuevas (ver abajo) | Cuenta real de GitHub (Kent C. Dodds): 6 entidades y 3 relaciones, todo coincide con la API; títulos reales de LinkedIn y X de una búsqueda web. La prueba real destapó 3 errores más, corregidos |
| A3 falsos "owns"/"same_person" | **Corregido** | 12 casos de test |
| A4 ruido del extractor | **Corregido** (correos falsos, IPs inválidas o privadas, `@código`) | Misma extracción real de python.org: 76 entidades, ninguna legítima perdida |
| A5 puntuación de nombres, teléfonos y URLs | **Corregido** (módulo nuevo `person_match`) | Los 6 casos de la tabla ahora dan lo esperado; 30 tests nuevos |
| A6 homónimos LATAM, ciudad, empresa | **Hecho**: señales graduadas (ver sección 7); la función estricta y su métrica no cambiaron | Métrica etiquetada de 20 casos (precisión 100%, recall 100%); búsqueda web real con "Carlos Andrade" (Ecuador): 3 de 16 marcados, los 3 de `mx.linkedin.com` |
| A7 GitHub confundía error con "no existe"; variantes puntuaban 90 siempre | **Corregido** | API real de GitHub: `torvalds` 90, `linus` (otra persona) 40, cuentas sin nombre 55 |
| A8 clasificación `x.com` por subcadena | **Corregido** | 15 casos de test |
| A9 dorks con categorías delicadas | **Pendiente**: es una decisión de política tuya | |
| A10 búsqueda por DuckDuckGo | **Pendiente**: necesita tu clave de API | |
| Candidatos sin URL se fundían en uno solo (hallado después) | **Corregido** | Test: 3 resultados distintos ya dan 3 candidatos |
| Link Shield + antigüedad del dominio | **Hecho** y medido con datos reales | Phishing marcado alto: 9% a 20% |
| M3 promoción de lo confirmado al caso | **Hecho** (sección 8) | 18 tests nuevos y flujo real con GitHub y búsqueda web |
| M2 semilla más rica | **Hecho** (sección 9) | Flujo real con datos solo adicionales; pestaña real probada en Windows; 16 tests nuevos |
| Directorios de LinkedIn como candidatos | **Hecho** (sección 10) | 28 tests; ver la nota sobre la verificación en vivo |
| M4 seguridad de los datos | **Hecho** (sección 11), con límites | Migración con tu base real (1 caso, 1 dato, 3 reportes, idéntica); DPAPI real en Windows; ventana real con el aviso |
| M1 restos de la IA y código duplicado | **Hecho** (sección 12) | Inventario completo, rescates con tests, ventana real construida sin el botón de IA |
| M5 a M8 | **Pendientes** | |

Pruebas: de 429 a **538** tests, todos en verde; ruff y bandit limpios.

---

## 1. Críticos

### C1. Informes sobre personas reales dentro del repositorio (verificado)
- `osint_results/` (informes forenses y JSON de una persona con nombre y apellido, con
  variantes), `veronicaup*.txt` (uno lleva un correo personal en el nombre del archivo),
  `prob.txt`, `duck.2023240.txt`, `logistica_ecuador.txt`, `amass_passive.txt`.
- Los añadió el **commit inicial de Hernán** (`458255a`, 2026-09-22). Su repositorio
  `HernanSanz1/OSINT-quantum_entanglement` es **PÚBLICO**: esos datos personales están
  expuestos en internet. Tu copia (`edupera91-cpu`) es privada.
- Riesgo: datos personales de terceros publicados (LOPDP / RGPD). Además sirven de
  mal ejemplo: nadie debería versionar resultados de investigaciones.
- Qué hacer (decisión tuya y de Hernán, **no se hace sin su autorización**):
  1. Avisar a Hernán. Quitarlos del historial público exige reescribir historia
     (`git filter-repo`) y es decisión suya.
  2. En tu copia: `git rm --cached` + añadir `osint_results/` y los `.txt` sueltos a
     `.gitignore`, **conservando los archivos en tu disco** (regla: verificar antes de borrar).
  3. Política: los resultados de casos nunca se versionan.

### C2. Una herramienta lenta aborta TODO el perfilamiento y pierde los resultados (verificado)
- `ProfilerEngine.run_parallel` (`profiler_engine.py`, bucle `as_completed(..., timeout=timeout_per_tool*2)`):
  la excepción `TimeoutError` se lanza **fuera** del `try`, así que no se captura.
- Prueba: dos herramientas, una de 0,1 s y otra de 6 s con límite de 1 s → excepción
  `TimeoutError`, tardó 6 s igualmente y `engine.results` quedó **vacío** (se perdió también
  el resultado de la herramienta rápida).
- Con los valores reales (120 s por herramienta, 240 s en total), Sherlock, Maigret o
  SpiderFoot pueden superarlo. Se pierde todo lo ya recogido.
- Corrección: capturar el `TimeoutError` del `as_completed`, marcar las pendientes como
  `timeout`, guardar siempre los resultados parciales y no esperar a los hilos colgados
  (`executor.shutdown(wait=False, cancel_futures=True)`). Añadir test con herramienta lenta.

### C3. `raw_data` no se guarda en los reportes (verificado)
- `SearchResult.to_dict()` (`core/models.py`) omite `raw_data`; solo guarda `extra_data`.
- Consecuencia: se pierden los datos estructurados de Domain WHOIS, Mail Health,
  **File Metadata (GPS, cámara)**, Link Shield (cadena de redirecciones, antigüedad),
  crt.sh, Hunter, Wayback, Google Dorks. En los reportes y en la correlación solo queda el
  título y el texto resumido.
- `cti_link.py` lee `item["raw_data"]["technology"]` de los reportes guardados y, como no
  existe, recurre al título: hoy funciona por casualidad.
- Corrección: incluir `raw_data` en `to_dict()` (o mover esos datos a `extra_data`) y
  añadir un test de ida y vuelta. Cuidado con el tamaño de los reportes grandes.

---

## 2. Altos — correlación de personas

### A1. La correlación casi no se muestra ni se conserva (verificado)
- Un caso con `email jriofrio@gmail.com` + `username jriofrio` + dominio: al abrir el motor
  hay **0 correlaciones**. Solo se comparan entidades nuevas contra las existentes; los
  datos semilla entre sí nunca se comparan.
- Las correlaciones viven solo en memoria: no se guardan. Al volver a analizar, las
  entidades ya existen, no se añaden y el contador sale casi en 0.
- La tabla de la pestaña solo muestra las 10 primeras (`top_correlations[:10]`).
- Corrección: calcular las correlaciones sobre **todas** las entidades del caso al cargar,
  guardarlas (la tabla `ai_correlations` y sus métodos `save_correlation`/`get_correlations` existen pero nadie los llama: pueden reutilizarse) y mostrarlas completas.

### A2. Faltan los tipos de entidad que identifican a una persona (verificado)
- Solo se extraen correo, dominio, IP, teléfono, usuario, hash y CVE. **No hay** nombre,
  **perfil social** (URL de LinkedIn, Facebook, Instagram, X, GitHub, TikTok), organización,
  ubicación ni universidad.
- `CORRELATION_WEIGHTS` es **código muerto** (no se usa) y promete relaciones que no existen:
  nombre~correo, teléfono~teléfono, dominio~IP. Hoy solo existen 4 relaciones
  (misma entidad, correo~dominio, correo~usuario, subdominio).
- Es la brecha más importante respecto al objetivo del proyecto: sin perfiles ni nombres
  como entidades no se puede unir "esta cuenta de X" con "este LinkedIn" y "este correo".
- Corrección (por pasos): extraer perfiles sociales por URL (ya hay expresiones en
  `extract_usernames_from_results`), añadir `profile`/`person`/`org`/`location`, y las
  relaciones: mismo usuario en varias plataformas, nombre del perfil ~ nombre del objetivo,
  mismo teléfono/correo en varias fuentes, empresa del perfil ~ empresa del caso.

### A3. Correlaciones falsas por comparar con subcadenas (verificado)
| Entrada | Resultado erróneo |
|---|---|
| correo `maria@gmail.com` y dominio `mail.com` | "owns" 85 (porque `mail.com` está dentro de `gmail.com`) |
| correo `mariana.paz@x.com` y usuario `ana` | "same_person" 75 |
| correo `admin@empresa.com` y usuario `admin` | "same_person" 75 (también `info`) |
- Además un correo `@gmail.com` "pertenece" al dominio gmail.com, que no es de nadie.
- `Entity.normalized()` hace `replace("www.", "")` en cualquier posición (`tuwww.com` → `tucom`).
- Corrección: comparar por límites (`@dominio` exacto o subdominio), lista de correos de rol
  (admin, info, contacto, ventas, soporte…) y de proveedores gratuitos, longitud mínima de
  usuario, y quitar solo el prefijo `www.`.

### A4. El extractor mete ruido que luego contamina el caso (verificado)
- Falsos correos: `logo@2x.png`, `sprite@3x.webp`. IP inválida `999.1.1.1` y privadas
  (`192.168.1.10`). Falsos usuarios `@media`, `@import`, `@Override`, `@param`.
- **Todo lo extraído se guarda como dato del caso** (`_persist_entity`) y luego alimenta a
  las demás herramientas: un `@media` puede acabar buscándose en Sherlock; 71 subdominios
  de una prueba pasan a ser "datos del objetivo".
- Corrección: validar el dominio del correo con la lista IANA (ya existe `tlds.txt`),
  validar IP con `ipaddress` y descartar privadas, lista de palabras reservadas para `@`,
  y guardar lo derivado aparte (con etiqueta "descubierto", confianza baja) separado de
  los datos que aportó el investigador.

### A5. Puntuación de candidatos poco fiable para nombres hispanos (verificado)
Resultados reales de `_calculate_confidence`:

| Nombre buscado | Texto del resultado | Puntos | Debería |
|---|---|---|---|
| Ana Paz | Mariana Pazmiño | **40** (coincidencia total falsa) | 0 |
| José Muñoz | jose munoz | **0** | alto |
| Riofrio Juan | Juan Riofrio | 25 (parcial) | alto |
| Juan Pérez Mora | Juan Perez | 10 | medio |
| teléfono +593 98 765 4321 | 098-765-4321 | **0** | coincidencia |
| teléfono 0987654321 | +593 98 765 4321 | **0** | coincidencia |

- Coincidencia por **subcadena**: "Ana Paz" coincide con "Mariana Pazmiño".
- Sin normalizar tildes ni mayúsculas Unicode: "José Muñoz" ≠ "jose munoz".
- No contempla el orden "Apellido Nombre" ni los dos apellidos (el nombre completo exacto
  casi nunca aparece tal cual).
- Teléfono: solo coincide si los dígitos están seguidos y con el mismo formato
  (`+593 98 765 4321` ≠ `098-765-4321`).
- Deduplicación por URL literal: `https://www.linkedin.com/in/x`, `https://linkedin.com/in/x/`
  y `http://...?trk=` cuentan como 3 (verificado).
- No compara ciudad, empresa ni profesión de forma estructurada.
- Corrección: normalizar texto (quitar tildes, minúsculas), coincidir por palabra completa
  y por conjunto de tokens, generar variantes (N1 A1, A1 N1, con y sin segundo apellido),
  normalizar teléfonos a E.164 antes de comparar y normalizar URLs antes de deduplicar.

### A6. Homónimos: solo por país y no cubre el caso más probable (verificado en código)
- `homonyms.py` marca un país "ajeno" solo si está en `OTHER_COUNTRIES`, que **no incluye
  países latinoamericanos**. Para un objetivo de Ecuador, un homónimo de Colombia, Perú o
  México (el caso más común) no se avisa. Ya figura como limitación conocida (3/3 sin detectar).
- No usa ciudad, profesión, empresa ni edad.
- Corrección: señales por ciudad/provincia, empresa y profesión del perfil frente a la
  semilla; marcar países latinoamericanos distintos del objetivo con aviso más suave.
  Mantener el enfoque A (marcar y bajar puntuación, nunca borrar).

### A7. GitHub y variantes de usuario: errores presentados como hechos (verificado en código)
- `GitHubOSINT._api_get` devuelve `{}` ante **cualquier** error (límite de 60 peticiones/h,
  red caída, 403); el resultado es "Usuario no encontrado". Un falso negativo se presenta
  como dato.
- `UsernameVariants` da "GitHub Match" con relevancia **90** a cualquier cuenta que exista
  con una variante del nombre, **sin comparar** el nombre del perfil, la ubicación ni la
  empresa. Con nombres comunes son casi todos falsos. Los errores 403 se descartan en silencio.
- No se aprovechan los **correos de los commits** (los eventos públicos `PushEvent` los
  traen): es un pivote clásico para vincular una cuenta con un correo.
- Corrección: distinguir "no existe" (404) de "no se pudo consultar" (403/red) y avisarlo;
  puntuar el parecido del nombre/ubicación del perfil con la semilla; extraer correos de commits.

### A8. WebSearch: clasificación y relevancia engañosas (verificado)
- La plataforma se decide con `'x.com' in url`: `linux.com`, `box.com` y `netflix.com`
  salen como "Twitter/X" con relevancia 85.
- La relevancia es fija por plataforma (LinkedIn 90) sin comprobar que el perfil sea de la
  persona; la confianza real se calcula después y por separado.
- Solo busca el nombre completo exacto entre comillas; no usa variantes con un apellido,
  sin tildes ni "Apellido Nombre". Recorta a 6 consultas, que pueden dejar fuera las de dominio.
- Corrección: clasificar por el dominio exacto (con `urlparse`), compartir con los dorks el
  generador de variantes de nombre (hoy solo lo tiene Google Dorks y con una lógica
  discutible para 4 palabras).

### A9. Dorks heredados con categorías sensibles (decisión de política)
- Plantillas con `court OR legal OR lawsuit`, `veteran OR military`, `investment OR stock`,
  `phone OR address OR location`, y `email (password OR secret OR token OR credential)`; y
  búsquedas en `funcionjudicial.gob.ec` con el nombre de una persona natural.
- No tocan salud, religión, política ni citas (regla ya acordada), pero lo judicial, lo
  militar y la dirección personal son datos delicados bajo la LOPDP.
- Decidir: dejarlos solo bajo "debida diligencia" con aviso, o quitarlos de la búsqueda de personas.

### A10. Búsqueda web frágil (ya conocido)
- DuckDuckGo por raspado se bloquea por volumen. Pendiente: buscador con API (necesita tu clave).

---

## 3. Medios

### M1. Restos de la IA y código duplicado (verificado)
- `smart_profiler.py` (501 líneas) **no lo usa ninguna parte de la aplicación**; solo lo
  mencionan tests. Duplica a `profiler_engine.py`. Antes de borrar, rescatar lo útil.
- Carpeta `osint_app/ai/` vacía, tabla `ai_correlations` (sin llamadas), claves ChatGPT/Venice en el baúl y
  `openai` en `requirements.txt`. Docstring de `profiler_engine` aún dice "La IA filtra…".
- Dependencias declaradas sin ningún import: `openai`, `pandas`, `networkx`, `lxml`.

### M2. La semilla de una persona es muy pobre
- `SeedData` solo tiene un nombre, contexto libre, país, un correo, un usuario, un teléfono,
  un dominio y una empresa. Faltan: **alias/apodos**, varios correos/usuarios/teléfonos,
  **ciudad**, año de nacimiento, **empleador y universidad** estructurados, y cédula/RUC
  (con cuidado legal). `QueryParameters` ya tiene `location` y `university` pero la semilla
  no los rellena. `context` y `country` se mezclan en un solo campo (`observable`).
- Link Shield y File Metadata no corren en el perfilamiento porque la semilla no tiene URL.

### M3. Lo que se descubre no se convierte en datos del caso
- Solo los perfiles de GitHub se promueven a datos (nombre, correo, empresa, ubicación,
  Twitter). Los hallazgos de Sherlock/Maigret, LinkedIn y demás quedan como texto de reporte.

### M4. Datos personales sin cifrar y en la nube (verificado en parte)
- La base de casos (`osint_app/data/osint_v2.db`) es SQLite en claro y está dentro de
  **OneDrive** (se sincroniza a la nube de Microsoft). No está versionada en git (bien).
- El baúl de claves guarda las claves en texto plano en `~/.osint_v2_keys`; el `chmod 600`
  no hace nada en Windows.
- Mejora: mover el directorio de datos fuera de OneDrive o cifrarlo; guardar claves con el
  almacén de credenciales de Windows (`keyring`/DPAPI).

### M5. Sugerencias de herramientas con nombres que no existen (verificado)
- `CorrelationEngine.suggest_tools` sugiere "Wayback", "IPWhois" y "Censys", pero en el
  registro se llaman "Wayback Machine", "ipwhois" y "CENSYS". El botón de auto-enriquecer
  puede pedir herramientas inexistentes.

### M6. Sin papelera / borrado lógico
- Borrar un caso, dato o reporte es definitivo (ya anotado como evolución del enfoque de homónimos).

### M7. Cobertura de pruebas
- Sin ninguna prueba: `social_tools`, `hunter`, `threat_intel`, `tool_checker`,
  `compatibility`, `html_report` y toda la interfaz. No se mide la cobertura
  (`pytest-cov` no está instalado). El tiempo límite del perfilador no estaba probado (C2).
- CI: no ejecuta `bandit` ni mide cobertura; `super-linter` solo valida HTML/CSS/JS/MD.

### M8. Calidad de código
- 57 imports sin usar (`ruff F401`), archivos muy grandes (`tab_profiling.py` 1235 líneas,
  `profiler_engine.py` 798), `datetime`/`Set`/`DataType` sin usar en `correlation_engine.py`.
- Reportes todavía en JSON crudo para el usuario no técnico (ya anotado; la estética va al final).

---

## 4. Mejoras propuestas para el objetivo "personas"

Ordenadas por impacto sobre buscar y correlacionar personas:

1. **Entidad "perfil social" + correlación por usuario compartido** (A2): une cuentas de
   distintas plataformas; es lo que más multiplica el valor del perfilamiento.
2. **Normalización de nombres y teléfonos** (A5): tildes, variantes de dos apellidos, E.164.
   Mejora a la vez la búsqueda, la puntuación y la deduplicación.
3. **Puntuación de coincidencia de perfiles**: comparar nombre, ciudad, empresa y foto
   (hash perceptual del avatar) entre cuentas candidatas, en vez de relevancia fija.
4. **Correos de commits de GitHub** (A7) y **correos probables** a partir de nombre +
   dominio de la empresa, comprobando con Mail Health (MX) y Holehe.
5. **Línea de tiempo**: fechas de creación de cuentas, de dominios (Domain WHOIS), de
   archivos (File Metadata) y de publicaciones, para ver actividad y cuadrar identidades.
6. **Semilla rica** (M2) y **promoción automática** de hallazgos a datos del caso con
   confirmación del investigador (M3).
7. **Grafo de relaciones** visible (los nodos y aristas ya existen en memoria; falta guardarlos
   y dibujarlos) y **correlación entre casos** sin entidades genéricas (según el código, valores como el
   país o el contexto se comparan entre casos y aparecerían como "compartidos"; sin verificar).
8. **Informe legible** por caso para personas no técnicas (al final, junto con la estética).
9. **Cruce Link Shield + Domain WHOIS** (antigüedad del dominio): en curso.
10. **Cumplimiento**: registro de finalidad y autorización por caso, aviso al exportar datos
    personales, y política de retención (la LOPDP exige minimizar y conservar lo justo).

---

## 5. Orden sugerido de trabajo

| Prioridad | Tarea | Esfuerzo |
|---|---|---|
| 1 | C1 sacar datos personales del repositorio (con autorización) | pequeño |
| 2 | C2 tiempo límite del perfilador + test | pequeño |
| 3 | C3 guardar `raw_data` + test | pequeño |
| 4 | A3 y A4 falsos positivos de correlación y extractor | pequeño |
| 5 | A1 correlaciones sobre todo el caso, persistentes y completas | medio |
| 6 | A5 normalización de nombres/teléfonos/URLs | medio |
| 7 | A2 perfil social como entidad + relaciones nuevas | medio-grande |
| 8 | A7, A8 GitHub y WebSearch honestos | medio |
| 9 | A6 homónimos por ciudad/empresa | medio |
| 10 | M1 limpieza de restos de la IA (tras verificar) | pequeño |


---

## 6. A2 — cómo se unen los datos de una persona (hecho)

Tipos de entidad nuevos: **perfil social** (LinkedIn, GitHub, X, Facebook, Instagram, TikTok,
YouTube, Telegram, Reddit, Medium), **nombre**, **empresa** y **ubicación**. Los perfiles se
normalizan: `twitter.com/Dan_Abramov`, `x.com/dan_abramov/` y `mobile.twitter.com/dan_abramov?s=20`
son el mismo perfil.

| Relación | Cuándo | Confianza |
|---|---|---|
| `profile_of` | el usuario del perfil es igual a un usuario del caso | 90 |
| `named_in` | el nombre se leyó en ese perfil | 85 |
| `same_handle` | mismo usuario en dos plataformas (4 letras o más) | 70 (45 si es corto) |
| `name_in_handle` | el correo o usuario sigue el patrón del nombre (`jriofrio` ~ Juan Riofrio) | 65 correo / 55 usuario |
| `same_name` | un nombre contiene al otro (con otras tildes, sin el segundo apellido…) | 60 |
| `same_person` | el usuario del perfil es igual a la parte local de un correo (no de rol) | 60 |

Los nombres solo se leen de **datos estructurados** (el campo "nombre" de GitHub) o del **título
de una página de perfil** reconocida; nunca de texto libre. Lo descubierto se guarda con prefijo
`found_` en los datos del caso, así que un nombre hallado en el perfil de un homónimo **nunca
sustituye** al objetivo con el que se lanzan las demás herramientas.

Errores que solo salieron con datos reales: títulos que genera la propia herramienta
("Lenguajes principales de x") tomados como nombre, `@epicweb-dev` cortado como `@epicweb` y
"Replies by Linus Torvalds" tomado como nombre.


---

## 7. A6 — señales graduadas de homónimo (hecho)

La función estricta `homonym_warning` (país claramente ajeno) **no cambió** y su métrica (precisión 100%,
recall 100%) sigue igual. Encima se añadieron señales más débiles, cada una con su penalización; nunca se
descarta un resultado (enfoque A): solo se avisa y baja la puntuación. El total se limita a 40 puntos.

| Señal | Ejemplo para un objetivo de Ecuador | Penalización |
|---|---|---|
| País ajeno (la de siempre) | "Madrid, Spain" | 30 |
| País vecino | "Bogotá, Colombia", "Lima, Perú" | 15 |
| Ciudad de otro país latinoamericano | "Medellín", "Monterrey" | 15 |
| Ciudad de fuera de Latinoamérica | "Miami" | 25 |
| LinkedIn de otro país | `mx.linkedin.com`, `pe.linkedin.com` | 20 |
| Sitio con extensión de otro país | `.com.mx`, `.es`, `.com.ar` | 10 |
| Otra ciudad del mismo país que el contexto | contexto "Loja", resultado "Guayaquil" | 8 |

Si el texto menciona el país del objetivo o una de sus ciudades, se considera ligado a él y no se aplican
las señales débiles. Si ya hay un país ajeno, su ciudad no se suma otra vez.

**Falsos positivos evitados a propósito:** una ciudad solo cuenta si aparece con mayúscula inicial, y la lista
excluye las que son también apellidos o nombres (Mendoza, Rosario, Zamora, Ibarra, Quevedo, Pereira, Trujillo,
Orlando, Roma…) o que existen en varios países (Valencia, Córdoba, Santiago, Cuenca, Guadalajara…).
"Juan Mendoza" en Quito o "la lima y la manta del cuarto" no generan ninguna señal.

Además, la **empresa** del objetivo ahora suma 15 puntos si aparece en el resultado (antes no puntuaba).

**Limitaciones:** el objetivo necesita un país reconocible (Latinoamérica, España, EE. UU. o Brasil) para las
señales débiles. Los homónimos sin ninguna pista de lugar siguen sin detectarse. Los resultados que son
**directorios** de LinkedIn ("600+ Carlos Andrade profiles") puntúan como candidatos aunque no sean una persona:
mejora pendiente.


---

## 8. M3 — lo que confirmas pasa al caso (hecho)

Antes, **Confirmar** solo marcaba el candidato en pantalla y **Refinar** extraía únicamente un usuario de
GitHub, un correo y un dominio. Ahora, al confirmar un candidato:

- Se añaden al **caso activo**, como datos confirmados (origen "confirmado", confianza 90): el **perfil**
  (LinkedIn, GitHub, X, Instagram…), el **usuario** (de cualquier plataforma, salvo ids de LinkedIn o canales
  de YouTube), el **correo** (nunca los de rol como `info@` ni falsos como `logo@2x.png`), la **empresa**, la
  **ubicación** y el **nombre** del perfil.
- No se duplica nada (se compara sin tildes, mayúsculas ni `@`), y los datos descubiertos antes
  (`found_*`) se convierten en datos del caso al confirmarlos.
- **El objetivo no cambia**: una variante de nombre confirmada no sustituye al nombre que escribiste.
- La interfaz avisa en el registro ("📌 Añadido al caso: …") y refresca la pestaña de datos.
- **Refinar** ahora usa también perfiles de otras plataformas y la empresa, y **ya no toma `gmail.com` como
  dominio del objetivo** (defecto que había: un correo `@gmail.com` confirmado ponía `site:gmail.com`).

Rechazar un candidato **no borra** lo que ya se añadió (regla de no borrar sin verificar): se corrige a mano
en la pestaña de datos.

Verificado con datos reales (Kent C. Dodds, figura pública): de 47 candidatos, al confirmar tres pasaron al
caso su perfil de GitHub, su LinkedIn real y el correo de su currículum; la semilla de "Refinar" obtuvo el
dominio `kentcdodds.com` y la empresa.


---

## 9. M2 — semilla más rica (hecho)

La semilla de una persona ya no es solo un nombre, un correo, un usuario y un teléfono. En la pestaña de
perfilamiento hay una sección plegable **"Más datos del objetivo"** con:

| Campo | Para qué sirve |
|---|---|
| **Empresa donde trabaja**, **Universidad**, **Ciudad** | Corroboran que un resultado es de la persona correcta: suman 15, 15 y 10 puntos si aparecen. La ciudad además da contexto a las señales de homónimo (otra ciudad del mismo país) y a las búsquedas |
| **Alias, apodos o variantes del nombre** | Se puntúan igual que el nombre ("Carlos Andrade León", "Charly Andrade") y se relanza la búsqueda con cada uno |
| **Otros correos, usernames y teléfonos** | Se comprueban en los resultados y se relanzan las herramientas adecuadas por cada uno |

Qué herramientas se relanzan por cada dato adicional: **usernames** → GitHub, Sherlock y Maigret; **correos** →
Holehe y Google Dorks; **teléfonos** → phonenumbers y Google Dorks; **alias** → WebSearch y UsernameVariants.
Se limita a **3 de cada tipo** para no multiplicar las peticiones (los buscadores bloquean por ráfaga) y se
respeta la selección de herramientas del usuario.

En el caso, los datos adicionales se guardan con confianza 95 y el principal con 100, así que **el objetivo
no cambia**. Los alias se unen al nombre mediante la relación `same_name` de la correlación.

La pantalla arma la semilla en un solo lugar (`_seed_from_inputs`), que ahora usan **Iniciar** y **Refinar**
(antes repetían el código y habrían olvidado los campos nuevos). Los campos aceptan comas, punto y coma o
saltos de línea, y quitan vacíos y repetidos.

Verificado con datos reales (Kent C. Dodds): con el usuario y el alias solo como datos adicionales, se lanzó
`GitHubOSINT:kentcdodds` (24 resultados) y el mejor candidato puntuó 85 coincidiendo en nombre, usuario, país y
ciudad. La pestaña real se probó sin pantalla en Windows (se salta en Linux por seguridad).


---

## 10. Listados de personas fuera de los candidatos (hecho)

Los resultados que son un **listado** y no una persona (por ejemplo `600+ "Carlos Andrade" profiles | LinkedIn`,
que apuntaba a `linkedin.com/pub/dir/...`) puntuaban como candidatos porque contienen el nombre buscado. Ahora
se dejan fuera de la lista de candidatos y **siguen guardados en los reportes** de la herramienta (no se pierde
nada); el registro avisa: "Omitidos N listados que no son una persona ... siguen en los reportes".

Se consideran listados: los directorios de LinkedIn (`/pub/dir/`, `/directory/`) y de Facebook (`/public/`), los
buscadores de personas (Spokeo, Whitepages, Radaris, BeenVerified, TruePeopleSearch, PeekYou…) y los títulos del
tipo `600+ "Nombre" profiles`, `400+ profiles`, `1.200 perfiles de Nombre`, `50 people named Nombre`.

**No** se omiten los perfiles reales: `ec.linkedin.com/in/...`, las URLs antiguas `linkedin.com/pub/nombre/12/345/678`,
las páginas `facebook.com/people/...` ni títulos como "3 profiles of the Open Source community" o "Los 10 mejores
perfiles de GitHub".

**Verificación:** los tres directorios de LinkedIn reales de la búsqueda "Carlos Andrade" (título y URL exactos) se
detectan, y su perfil real de `ec.linkedin.com` se conserva. No se pudo repetir la búsqueda en vivo al final
porque DuckDuckGo bloqueaba por ráfaga de consultas.

**Defecto propio hallado al probar:** mis primeras expresiones terminaban con un carácter invisible de "retroceso"
(la secuencia de escape se perdió al generar el archivo); se corrigió y se revisó **todo el código** sin hallar
otros caracteres de control.


---

## 11. M4 — seguridad de los datos (hecho, con límites)

Los casos tienen datos personales de terceros. Qué cambió:

| Antes | Ahora |
|---|---|
| La base de casos estaba dentro de la carpeta del proyecto, que en este equipo está en **OneDrive** (se sincroniza con la nube de Microsoft) | Va a `%LOCALAPPDATA%\SENTINEL` (fuera de la nube). Se puede cambiar con la variable `SENTINEL_DATA_DIR` |
| Las claves de API se guardaban en texto plano (`~/.osint_v2_keys`; el `chmod 600` no hace nada en Windows) | Se cifran con **DPAPI de Windows**: solo tu usuario de Windows, en este equipo, puede leerlas. Las que ya estaban en claro se cifran solas al leerlas |
| Nada avisaba si los datos quedaban en la nube | Al abrir el programa, un aviso rojo si la carpeta de datos está en OneDrive, Dropbox, Google Drive, iCloud, etc. |
| Los tests podían tocar la base real | Un `conftest.py` en la raíz fuerza una carpeta temporal: los tests no crean, migran ni modifican tus casos |

**La migración nunca pierde datos:** copia la base antigua con la copia segura de SQLite (aunque esté en uso),
comprueba que las filas coinciden y solo entonces la deja en su sitio. **No borra ni mueve el original.** Si la copia
falla, el programa sigue usando la base original en vez de arrancar vacío. Si el baúl cifrado no se puede leer
(p. ej. copiado desde otro equipo), se respalda en `.unreadable.bak` antes de reemplazarlo.

**Verificado con tus datos reales:** la base copiada es idéntica a la original (1 caso, 1 dato, 3 reportes) y el programa
ve tu caso desde la ruta nueva; el aviso de nube aparece en la ventana real al apuntar a la carpeta de OneDrive.

**Pendiente tuyo:** la base original sigue en `osint_app/data/osint_v2.db`, **dentro de OneDrive**, y por tanto
sincronizada. El programa ya no la usa. Cuando confirmes que todo está bien, bórrala (o muévela) para que deje de
estar en la nube.

**Límites (lo que esto NO resuelve):**
- La base nueva sigue **sin cifrar en disco**. Protege la carpeta de tu usuario de Windows, pero no un disco
  robado: conviene tener **BitLocker** activo. Cifrar la base exigiría SQLCipher (difícil de instalar en Windows) o
  pedir una contraseña al abrir.
- Los **informes exportados** a `Descargas` (JSON y HTML) siguen en texto plano.
- Lo que ya se haya sincronizado a OneDrive antes de este cambio puede conservar versiones anteriores en su historial.
- El cifrado de claves es solo de Windows; en otros sistemas se guardan en claro con permisos de solo propietario.


---

## 12. M1 — limpieza de los restos de la IA (hecho)

Primero un inventario de todo lo que quedaba y, antes de borrar, una búsqueda de lo rescatable.

**Eliminado** (los archivos siguen en el historial de git, por si hiciera falta recuperarlos):
- `osint_app/smart_profiler.py` (501 líneas): duplicaba a `profiler_engine.py` y no lo usaba ninguna parte del programa.
- `osint_app/ai/` (carpeta vacía).
- El botón **"🧠 Send to AI"** de Reportes: saltaba a la pestaña número 4, que hoy es *Correlación*, con un mensaje sobre
  "la pestaña de IA". Era un defecto visible para el usuario.
- Código muerto de `ai_correlations` (modelo `AICorrelation` y dos métodos de la base). **La tabla vacía se conserva** en el
  esquema para no tocar bases existentes.
- Claves ChatGPT y Venice del baúl; entradas de `openai`, `Ollama`, `pandas`, `networkx` y `lxml` de `tool_checker`, y las
  dependencias `openai`, `pandas`, `networkx` y `lxml` de `requirements.txt` (ninguna se importaba).
- Comentarios obsoletos (Ollama en `sanitizer`, "la IA filtra…").

**Rescatado de `smart_profiler` antes de borrarlo** (con tests):
1. **Variantes de usuario con inicial + apellido + año** (`jriofrio2006`, `jriofrio06`, `juanr2006`…): el bloque de años de
   `UsernameVariants` solo usaba las 15 primeras variantes básicas y nunca las combinaba con las iniciales.
2. **Usuarios con número al final** (`jriofrio99`, `juan.riofrio2006`) ahora cuentan como forma del nombre en la correlación.
3. **El apellido pesa más que el nombre de pila o el segundo nombre** cuando solo coincide una palabra (10 contra 5 puntos).

**No rescatado a propósito:** las reglas de **rechazo automático** (contradicen el enfoque de nunca descartar), la regla de
"estudiante frente a empresa grande" (demasiado específica) y el patrón `jdriofrio` (era el usuario de su propio autor).

**Documentación corregida:** `MANUAL_USUARIO.md` se reescribió (describía una "IA Triple", Ollama, macOS y **una ruta
personal de otra persona**); `MANUAL_DESARROLLADOR.md` (estructura real del proyecto, interfaz PySide6 en vez de una paleta de
Tkinter inexistente, base de datos y conexiones) y `SKILL_SENTINEL.md` (el ejemplo ahora usa `ProfilerEngine`).

**Hueco que apareció y se cerró:** no existía ninguna pantalla para guardar claves de API (vivía en la pestaña de IA
eliminada) y el baúl ahora va cifrado. Nuevo: `python -m osint_app.main --set-key GitHub` (pide la clave oculta; nunca como
argumento, para que no quede en el historial de la consola) y `--keys` (qué claves hay, sin mostrar valores).
