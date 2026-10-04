# Auditoría real de SENTINEL (octubre 2026)

Auditoría hecha con **pruebas reales**: cada herramienta se ejecutó contra objetivos reales y públicos (presidentes y
expresidentes de Ecuador, figuras públicas extranjeras, deportistas, colaboradores del proyecto, dominios e IP
públicas). Cada dato importante se comprobó contra una fuente independiente. Nada de lo que aquí se afirma sale de una
simulación.

Para repetirla en cualquier momento:

```bash
python scripts/auditoria_real.py
```

Resultado al cierre: **18 de 18 pruebas reales correctas**.

## 1. Resumen para no técnicos

Antes de la auditoría, la función más importante del proyecto (buscar a una persona y correlacionar su
información) **casi no funcionaba**, aunque las pruebas automáticas pasaban:

- El único buscador (DuckDuckGo) respondía con un captcha anti-robots y el programa lo trataba como "no hay
  resultados", sin avisar. Las búsquedas de personas daban **0 resultados** tras esperar hasta 3 minutos.
- El perfilador **descartaba** los perfiles encontrados por nombre de usuario (40 de 40 en una prueba).
- Herramientas como Maigret, Holehe e Instaloader **estaban rotas** o se colgaban, y nadie lo había notado porque
  nunca se habían ejecutado de verdad.

Medido con la misma persona pública (Kent C. Dodds), antes y después:

| Medida | Antes | Después |
|---|---|---|
| Candidatos encontrados | 2 | 112 |
| Tiempo total | 378 s | 150 s |
| Herramientas que agotaban su tiempo | 1 | 0 |

Con una persona ecuatoriana dando **solo su nombre y contexto** (Jefferson Pérez Quezada), ahora el sistema
encuentra su ficha pública, sus cuentas oficiales (X y Facebook), descubre su usuario, lo persigue en otras redes
(YouTube, TikTok, Threads) y lo correlaciona todo. Antes se quedaba en páginas sueltas.

## 2. Hallazgos y correcciones

Cada punto indica el fallo encontrado en real, la corrección y la verificación.

### 2.1 Búsqueda web de personas (el fallo más grave)

- **Fallo:** DuckDuckGo devolvía un captcha (HTTP 202) y todo daba 0 en silencio. WebSearch tardaba 205 s para 0
  resultados y Google Dorks agotaba su tiempo.
- **Corrección:** nueva capa `utils/search_engine.py` con varios motores y respaldo: API de Brave (si hay clave),
  SearXNG propio (si se configura), Yahoo y modo automático de la librería `ddgs` (licencia MIT) y DuckDuckGo al
  final. Detecta captchas, aparta 10 minutos el motor que bloquea, espacia las consultas y **avisa** cuando todos
  bloquean ("esto NO significa que no haya información").
- **Verificación:** Rafael Correa 30 resultados (28 relevantes), Satya Nadella 28 (su LinkedIn verificado), Gabriela
  Sommerfeld 9. Antes: 0, 0 y 0.
- **Medición honesta de motores** desde Ecuador: solo Yahoo respondió de forma fiable (3 de 5 consultas). Google,
  Brave, Mojeek, Startpage y DuckDuckGo vía `ddgs` dieron 0. En la primera medición me equivoqué: "bing" y "yandex"
  no existen como motores de texto en `ddgs` 9.x y lo que funcionaba era el modo automático; se corrigió antes de
  construir sobre ese dato.
- **Resultados pegados:** Yahoo a veces entrega varios resultados unidos en uno; un vídeo de YouTube traía el texto
  de una página de Facebook con un teléfono. Ahora se separan.

### 2.2 Google Dorks

- **Fallo:** de 5 resultados para "Jefferson Pérez Quezada", **4 eran otras personas** (bastaba una palabra del
  nombre, como "pérez") y todos puntuaban 0. Además buscaba "Pérez Quezada" (solo apellidos), que atrae homónimos.
- **Fallo:** `netloc.replace("m.", "")` borraba "m." en cualquier parte del dominio: `forum.x.com` quedaba como
  `forux.com`.
- **Corrección:** verificación por nombre completo o nombre de pila más apellido, contexto del caso como
  corroboración, sin búsquedas de solo apellidos, URL corregidas.
- **Verificación:** 3 de 4 resultados correctos (Wikipedia, Expreso, biografía) con puntuación coherente.

### 2.3 Coincidencia de nombres y homónimos

- **Fallo:** "dos palabras cualesquiera" contaba como coincidencia: "Carlos Pérez Quezada" puntuaba como
  "Jefferson Pérez Quezada", y "Noboa Azín Álvaro" (el padre) como "Daniel Noboa Azín".
- **Corrección:** hace falta el nombre de pila más un apellido; solo apellidos ya no basta.
- **Fallo:** un medio ecuatoriano sobre una persona ecuatoriana se marcaba como posible homónimo porque mencionaba
  "Atlanta 1996". **Corrección:** un sitio del país del objetivo lo liga a él.

### 2.4 Perfilador (correlación de una persona)

- Los perfiles encontrados por el usuario exacto (Sherlock, Maigret) valían 25 puntos, por debajo del mínimo de 30:
  se descartaban todos. Ahora valen 30.
- La segunda ronda perseguía usuarios de **otras personas** (`kent`, `dodds`, 198 resultados ajenos) y un usuario
  inexistente (`profiles`). Ahora solo sigue resultados que coinciden con la persona y usa un analizador estricto de
  URLs de perfil.
- Los perfiles de la segunda ronda no puntuaban; ahora el usuario descubierto cuenta.
- Se lanzaban herramientas sin el dato que necesitan (Sherlock sin usuario) y el informe decía "ok, 0 resultados".
- Los avisos de error ("GitHub limitó las consultas") aparecían como candidatos.
- El contexto del caso viajaba en el campo `observable`, que es para indicadores (dominio, IP, correo): ahora va en
  `context`. Este fallo lo introduje yo en una corrección anterior (commit `c776713`) y quedó corregido.

### 2.5 Correlación de entidades

Caso real de Jefferson Pérez: **55 entidades con ruido → 20 relevantes**.

- 7 "teléfonos" falsos (por ejemplo el ID de Facebook `100047132710726`): ahora se validan con la librería
  `phonenumbers`. Queda 1, real: el teléfono público de su página oficial de Facebook.
- 27 "dominios" que eran las plataformas donde se encontró a la persona (tiktok.com, wikipedia.org…) y CDN de
  avatares. Ahora queda su web oficial `jeffersonperez.com`.
- Resultados de búsqueda sobre otras personas ya no se atribuyen al objetivo.

### 2.6 Herramientas que estaban rotas

| Herramienta | Fallo real | Corrección y verificación |
|---|---|---|
| Maigret | Formato de salida distinto al que leía el código; DNS 100% fallido en Windows | Informe JSON real y resolvedor del sistema. 44 perfiles de kentcdodds, muchos con nombre extraído |
| Holehe | Se caía en Windows (codificación cp1252) y contaba su leyenda como servicio | UTF-8 en los subprocesos y análisis estricto. Correo público con 3 servicios reales |
| Instaloader | `--login=anon` pedía contraseña y se colgaba 120 s; descargaba fotos | API de Python, solo metadatos, sesión del usuario. Falla en 0,7 s explicando por qué |
| Sherlock, Holehe, Maigret | Aparecían "no instalados" si no se activaba el entorno virtual | La carpeta de programas del entorno se añade al PATH al arrancar |
| crt.sh | Caído (HTTP 502) en todo el mundo y sin respaldo | Tres fuentes: crt.sh, CertSpotter y HackerTarget. python.org 64 subdominios con IP |
| Wayback | Agotaba el tiempo con dominios grandes | Modo `matchType=domain`: sri.gob.ec 257 registros en 6 s |
| File Metadata | Wikimedia respondía 429 | User-Agent con contacto, como exige su política |
| Mail Health | gmail.com y yahoo.com aparecían "sin all" | Sigue el `redirect=` de SPF; comprobado contra el DNS |
| UsernameVariants | Usaba el segundo apellido ("mariamora") | Convención hispana N1 N2 A1 A2 |

### 2.7 Seguridad

- **Informe HTML sin escapar:** títulos y biografías de terceros se insertaban tal cual; un objetivo podía plantar
  `<script>` y ejecutarlo en el equipo del analista. Ahora todo se escapa y solo se enlaza http(s). Verificado con
  datos reales y contenido plantado: 0 scripts ejecutables.
- La ficha del perfilamiento permitía enlaces `javascript:`: corregido.

### 2.8 Lo que estaba sin terminar

- **IntelOwl, OpenCTI, MISP, Cortex e IntelMQ son plantillas vacías:** su URL nunca se configura y no hay código
  que consulte esos servidores. Ahora lo dicen claramente y remiten a la nueva herramienta de reputación de IP.
- **CENSYS** usa una API antigua que el paquete actual ya no incluye (pendiente de migrar; necesita clave para
  verificarlo).

## 3. Herramientas nuevas

| Herramienta | Qué aporta | Verificación real |
|---|---|---|
| Wikidata | Ficha de personas públicas: nacimiento, cargos, estudios, partido y **cuentas oficiales** | Noboa, Correa, Lasso, Torvalds, Jefferson Pérez y otros; homónimos detectados en vez de adivinar |
| IP Reputation | Shodan InternetDB, GreyNoise, Tor, Spamhaus DROP, FireHOL y URLhaus, sin clave | IP de Tor, red de DROP e IP que reparte malware detectadas; 8.8.8.8 riesgo bajo |
| GitHub ampliado | Redes vinculadas al perfil y correos de los commits | kentcdodds (X, YouTube, Bluesky) y torvalds (correo real de la Linux Foundation) |
| Link Shield con listas | Phishing activo (OpenPhish) y malware activo (URLhaus) | 6 phishing y 2 malware reales en "alto"; python.org en "bajo" |
| Tech Detect ampliado | 45 firmas propias más y versiones expuestas | presidencia.gob.ec expone PHP 8.1.34 y WordPress 7.0.4 |

## 4. Limitaciones y cómo superarlas

| Limitación | Por qué | Cómo resolverla |
|---|---|---|
| Los buscadores gratuitos bloquean | Raspar buscadores no es estable; hoy solo Yahoo responde bien | Crear una clave gratuita de Brave Search API y guardarla con `--set-key BraveSearch`, o montar un SearXNG propio y guardar su URL con `--set-key SearXNG` |
| GitHub sin token: 60 consultas por hora | Un perfilamiento completo puede gastar unas 30 | Crear un token sin permisos especiales en GitHub y guardarlo con `--set-key GitHub` (sube a 5.000 por hora) |
| Instagram exige sesión | Responde HTTP 429 a toda consulta anónima | Con una cuenta secundaria: `instaloader --login USUARIO` y luego `--set-key Instagram` con ese usuario |
| Hunter.io, CENSYS sin probar | Necesitan clave | Añadir las claves; CENSYS además necesita migrar a la API actual |
| GHunt sin probar | Necesita iniciar sesión de Google | Instalar GHunt y ejecutar `ghunt login` |
| Subfinder, Amass, TheHarvester, SpiderFoot y Recon-ng sin probar | No hay Go, Docker ni esos programas en este equipo | Instalar Go para Subfinder y Amass; clonar los repositorios del resto; luego `python scripts/auditoria_real.py` |
| Servidores CTI (IntelOwl y otros) | Son plantillas sin código | Hace falta un servidor de prueba para programar y verificar cada cliente |
| Homónimos con el mismo nombre y apellido | Solo con el nombre no se pueden separar | Añadir contexto (ciudad, empresa, universidad): el sistema lo usa para desempatar |

## 5. Cómo se verificó

- Herramientas ejecutadas contra objetivos reales: Daniel Noboa, Rafael Correa, Guillermo Lasso, Luisa González,
  María Paula Romo, Andrés Arauz, Gabriela Sommerfeld, Jefferson Pérez, Linus Torvalds, Satya Nadella, Kent C. Dodds,
  Dan Abramov y el colaborador del proyecto; dominios python.org, sri.gob.ec, presidencia.gob.ec, utpl.edu.ec,
  eluniverso.com y otros; IP 8.8.8.8, 1.1.1.1, una salida de Tor, una red de Spamhaus DROP y una IP de URLhaus.
- Datos comprobados punto a punto contra fuentes independientes: IP de subdominios contra el DNS actual, registros
  SPF y DMARC contra el DNS, cuentas oficiales contra lo conocido públicamente y el teléfono hasta su página de origen.
- Interfaz gráfica: abierta en modo sin pantalla, recorridas las 7 pestañas sin errores y un perfilamiento real
  lanzado desde la propia interfaz (36 candidatos en 98 s, guardados en un caso).
- Suite automática y CI en verde en cada punto de control (Windows y Ubuntu, Python 3.12 y 3.14).
