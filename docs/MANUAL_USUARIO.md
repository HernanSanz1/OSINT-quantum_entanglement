# Manual de Usuario — SENTINEL (OSINT Framework v2)

> SENTINEL ayuda a **buscar información pública** sobre personas y organizaciones y a **unir esos datos**
> (correos, usuarios, perfiles, teléfonos, dominios) en un solo caso. No usa inteligencia artificial: todo lo
> que muestra viene de fuentes públicas y de reglas explicadas en este manual.
>
> **Úsalo solo en investigaciones autorizadas y con un propósito legítimo.** Los casos contienen datos personales
> de terceros (LOPDP / RGPD): guárdalos, compártelos y bórralos con ese cuidado.

---

## 1. Primeros pasos

**Requisitos:** Python 3.12 o superior. Probado en Windows; la suite de pruebas también corre en Linux.

```bash
# 1. Instala las dependencias
pip install -r osint_app/requirements.txt

# 2. Abre el programa
python -m osint_app.main
```

Para ver qué herramientas tienes disponibles sin abrir la ventana: `python -m osint_app.main --check-tools`

### Dónde se guardan tus datos

Los casos se guardan en una carpeta **propia de tu usuario, fuera de la carpeta del proyecto**:

- Windows: `C:\Users\<tu usuario>\AppData\Local\SENTINEL`
- Otra carpeta: define la variable de entorno `SENTINEL_DATA_DIR`

Si esa carpeta está dentro de OneDrive, Dropbox, Google Drive o iCloud, el programa te lo avisa al abrir, porque
los datos personales se subirían a la nube. La base **no está cifrada por el programa**: si tu disco no está cifrado,
SENTINEL te avisa al abrir; actívalo en Configuración → Privacidad y seguridad → **Cifrado de dispositivo** (Windows
Home) o **BitLocker** (Windows Pro).

Las **fichas, PDF y exportaciones** van a la subcarpeta `informes` de esa misma carpeta (antes, a Descargas). Solo
tu usuario de Windows puede abrirla. Al guardar una ficha, un PDF o una exportación, el aviso dice dónde quedó y trae el
botón **📂 Abrir carpeta**. También: **Generar Ficha → 📂 Abrir la carpeta de informes**.

---

## 2. Las pestañas

| Pestaña | Para qué sirve |
|---|---|
| **Casos** | Crear, abrir y borrar casos. Cada caso aísla sus datos y reportes. Botón **💾 Copia de seguridad…** (ver el apartado 6) |
| **Datos** | Los datos que conoces del objetivo (correo, usuario, teléfono, dominio, URL…) |
| **Herramientas** | Ejecutar una herramienta sobre los datos del caso, con indicador 🟢 🟡 🔴 de si tienes lo que necesita |
| **Perfilamiento** | Buscar a una **persona** con muchas herramientas a la vez y revisar candidatos |
| **Correlación** | Ver cómo se relacionan los datos del caso (qué correo va con qué usuario, qué perfil con qué nombre…), comparar casos y **buscar el objetivo en la inteligencia de amenazas** (botón "Cruzar con CTI": ¿es víctima de ransomware?, ¿lo citan noticias de seguridad?, ¿sus IP salen en avisos?, ¿sus tecnologías tienen vulnerabilidades explotadas?) |
| **CTI** | Recolectar feeds de amenazas y generar el boletín de los **últimos 7 días**, general o para un cliente (ver el apartado 4b). **✅ Validar** revisa el último boletín (frases cortadas, párrafos en inglés, productos dudosos o repetidos, noticias sin enlace). **📧 Enviar** lo prepara como correo |
| **Reportes** | Ver y exportar lo que devolvió cada herramienta |

---

## 3. Perfilar a una persona (la función principal)

1. En **Perfilamiento** escribe el **nombre**, el **país** y un **contexto** (universidad, empresa, profesión).
2. Si lo conoces, añade usuario, correo, teléfono o dominio.
3. Despliega **"Más datos del objetivo"** para dar más pistas. Cuantas más des, mejor se distingue a la persona de otra
   con el mismo nombre:
   - **Empresa**, **universidad** y **ciudad**
   - **Alias o apodos** ("Charly Andrade") y variantes del nombre ("Carlos Andrade León")
   - **Otros correos, usuarios y teléfonos** (separados por coma)
4. Elige las herramientas (o déjalas todas) y pulsa **Iniciar perfilamiento**.
5. Se crea un **caso nuevo** con todo lo hallado y aparece una tabla de **candidatos** con su **confianza**.

### Cómo leer los candidatos

- **Confianza:** cuántos datos coinciden con lo que sabes (nombre, usuario, correo, teléfono, empresa, universidad, ciudad…).
  El nombre se compara sin importar tildes, mayúsculas ni el orden "Apellido Nombre".
- **⚠️ Aviso de posible homónimo:** el resultado menciona otro país, otra ciudad o un LinkedIn de otro país
  (por ejemplo `mx.linkedin.com` cuando buscas a alguien de Ecuador). **Solo avisa y baja la puntuación**: la decisión
  es tuya.
- **🗑 Descartados (papelera):** lo que es *claramente* otra persona sale de la tabla. Por ejemplo, un LinkedIn de
  otra profesión, un lugar con su nombre («Coliseo Jefferson Pérez») o varias señales a la vez (como otro país), siempre
  que **no coincida ningún dato** del objetivo (usuario, correo, teléfono, empresa, ciudad…). Mencionar otro país, por
  sí solo, no basta: un deportista sale en noticias de fuera. **No se borra nada:** el botón **🗑 Descartados (N)**
  muestra cada uno con su motivo, y **↩ Devolver a la tabla** lo recupera (el caso lo recuerda).
- **Listados omitidos:** los directorios y buscadores de personas ("600+ perfiles"), los directorios oficiales (notarías,
  nóminas de funcionarios) y las páginas de búsqueda o etiquetas de redes sociales (TikTok «discover», Pinterest «ideas»)
  no son una persona y no aparecen como candidatos, pero siguen guardados en el reporte.
- **Búsqueda web incompleta:** si los buscadores bloquean algunas consultas, aparece una barra amarilla con
  **🔁 Reintentar**. Repite solo las consultas que fallaron y conserva lo confirmado y lo descartado. Si pide esperar unos
  minutos, es porque antes los buscadores seguirían bloqueando.

### Confirmar, descartar y refinar

- **✅ Confirmar** un candidato pasa al caso lo que aporta (su perfil, usuario, correo, empresa y ubicación) como dato
  confirmado. No cambia el objetivo ni duplica datos.
- **❌ Descartar** solo marca el candidato; **no borra** lo que ya se hubiera añadido (se corrige en la pestaña Datos).
  Confirmar y descartar se guardan en el caso: la ficha los respeta aunque cierres el programa.
- **🔄 Refinar búsqueda** vuelve a buscar usando lo que aportaron los candidatos confirmados. Con la tabla vacía, primero
  carga el perfil guardado del caso abierto.
- **🎖️ Generar Ficha** abre un menú: **Ver en el navegador** o **Guardar como PDF**. Si no hay un perfilamiento en
  pantalla, la ficha se rehace con el perfil guardado en el **caso abierto** (ábrelo en Casos y pulsa Generar Ficha).
- **Correos y teléfonos ocultos:** en la ficha, en el detalle del candidato y en Reportes salen como `m•••@gmail.com`
  (protección de datos, LOPDP). Si tienes una finalidad legítima, **Generar Ficha → Ver con datos de contacto** los
  muestra completos.
- **Exportar** guarda el resultado en tu carpeta privada de informes (JSON/HTML/PDF: trátalo como dato
  personal).

---

## 4. Herramientas sueltas

Algunas funcionan sin clave y solo con un dato:

| Necesitas | Herramienta | Qué te dice |
|---|---|---|
| Un **dominio** | Domain WHOIS | Quién lo registró, desde cuándo, cuándo vence, alertas si es muy nuevo |
| Un **dominio** | Mail Health | Qué correo usa y si se puede suplantar (SPF, DMARC, MX) |
| Un **dominio** | crt.sh, dnspython, Tech Detect, Wayback | Subdominios, registros DNS, tecnologías, historial |
| Una **URL** | **Link Shield** | Si el enlace parece phishing, **sin abrirlo** (y la antigüedad de su dominio) |
| Una **URL o ruta de archivo** | **File Metadata** | Autor, cámara, programa y **GPS** de una foto, PDF o documento Office |
| Un usuario | GitHub, Sherlock, Maigret | En qué sitios existe |
| Un correo | Holehe | En qué servicios está registrado |
| Un dominio de empresa | Hunter.io (necesita clave) | Correos asociados a ese dominio |

Para Link Shield y File Metadata, añade primero en **Datos** un dato de tipo **URL** (o la ruta de un archivo).

### 4b. Boletín CTI y botón Enviar

- **Qué días cubre:** los últimos 7 días hasta hoy. Lo que ya salió en un boletín anterior no se repite.
- **Boletín de un cliente:** empieza con **«Lo que afecta a la infraestructura de …»**: las noticias que nombran un
  producto o servicio de su inventario (por ejemplo VMware vCenter o Microsoft 365) y qué revisar. Esas noticias no se
  repiten en las demás secciones.
- **Qué entra:** las vulnerabilidades (CVE) pasan un filtro estricto (críticas y de tecnologías que usan los clientes).
  Las secciones de noticias aceptan también campañas, ransomware, phishing y fugas de datos. Si una sección queda vacía,
  el boletín lo explica.
- **📧 Enviar no envía nada por sí solo.** Revisa el boletín y abre una ventana con los destinatarios del cliente
  (SENTINEL los recuerda; avisa si una dirección es de otro cliente). Luego:
  - **Abrir borrador:** un correo nuevo en tu programa de correo (Outlook, Correo de Windows, Thunderbird) con el
    boletín dentro. Si tu equipo no tiene programa para eso, abre un correo nuevo con destinatarios y asunto y deja el
    boletín copiado: pégalo con **Ctrl+V**.
  - **Copiar para pegar:** para el correo en el navegador. Abre **Gmail** u **Outlook web** con destinatarios y asunto;
    pega el boletín con **Ctrl+V**.
  - SENTINEL no guarda contraseñas de correo: sale desde tu cuenta, con tu firma, y tú pulsas Enviar.

---

## 5. Claves de API

La mayoría de las herramientas **no necesitan clave**. Para las que sí (GitHub, Hunter.io, CENSYS, etc.), en
**Herramientas** elige la herramienta → **Verificar Estado** → **🔑 Guardar clave**. O desde la consola:

```bash
python -m osint_app.main --set-key GitHub     # te pide la clave sin mostrarla y la guarda
python -m osint_app.main --keys               # qué claves tienes (nunca muestra su valor)
```

- **No escribas la clave en el mismo comando**: quedaría en el historial de la consola.
- En Windows las claves se guardan **cifradas** (solo tu usuario de Windows en este equipo puede leerlas).
- También sirven las variables de entorno (`GITHUB_TOKEN`, `OSINT_HUNTER_KEY`…); tienen prioridad sobre las guardadas.
- Tener un token de **GitHub** sube el límite de consultas de 60 a 5.000 por hora.
- **abuse.ch** (opcional y gratuita, en [auth.abuse.ch](https://auth.abuse.ch/)): con ella IP Reputation y Link Shield
  consultan **URLhaus** (si una IP o un enlace reparte malware ahora mismo). Se guarda con `--set-key abuse.ch` o en
  Herramientas → IP Reputation → **🔑 Guardar clave de abuse.ch (opcional)**.

---

## 6. Copias de seguridad y comprobar la instalación

- **Copia automática:** una al día al abrir SENTINEL (se guardan las 7 últimas, en una carpeta que solo tu usuario puede
  abrir). En **Casos** se ve la fecha de la última.
- **Copia en un USB u otro disco:** **Casos → 💾 Copia de seguridad…** Contiene datos personales: guárdala en un lugar
  seguro y no en una carpeta que se suba a la nube (SENTINEL avisa si lo es). Las claves de API no se copian.
- **Restaurar**, con SENTINEL cerrado: `python -m osint_app.main --restore "ruta\de\la\copia.zip"`. Antes de reemplazar
  nada guarda una copia de lo que haya.
- **¿Está todo bien instalado?** `python -m osint_app.main --setup` revisa paso a paso Python, dependencias, claves,
  Docker y SearXNG, la carpeta de datos y las copias, y dice qué hacer con lo que falte. No cambia nada.

---

## 7. Preguntas frecuentes

**¿Mis datos salen a internet?**
Las consultas sí: cada herramienta consulta fuentes públicas (buscadores, GitHub, registros de dominios…). Tus **casos** se
guardan solo en tu equipo.

**¿Por qué una búsqueda devuelve 0 resultados?**
Los buscadores públicos bloquean las ráfagas de consultas (de 10 a 30 minutos). Si aparece la barra de búsqueda
incompleta, pulsa **🔁 Reintentar** cuando se active. Con el buscador propio SearXNG (Docker abierto) casi no pasa.

**¿Qué hago con los candidatos con ⚠️?**
Míralos antes de confirmar: pueden ser otra persona con el mismo nombre. Añadir empresa, universidad y ciudad en
"Más datos del objetivo" ayuda a distinguirlos.

**¿Dónde veo cómo se unen los datos?**
En **Correlación → Analizar**: muestra, por ejemplo, que un perfil de GitHub y una cuenta de X usan el mismo usuario, o
que un correo sigue el patrón del nombre (`jriofrio` ~ Juan Riofrio).

**¿Qué hago con la base antigua dentro de OneDrive?**
Si venías de una versión anterior, tu base se **copió** a la carpeta nueva y la original quedó donde estaba. Cuando
confirmes que todo está bien en la nueva, borra la antigua (`osint_app/data/osint_v2.db`) para que deje de estar en la nube.
