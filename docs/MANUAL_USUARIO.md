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
los datos personales se subirían a la nube. La base **no está cifrada en disco**: activa **BitLocker** en Windows.

---

## 2. Las pestañas

| Pestaña | Para qué sirve |
|---|---|
| **Casos** | Crear, abrir y borrar casos. Cada caso aísla sus datos y reportes |
| **Datos** | Los datos que conoces del objetivo (correo, usuario, teléfono, dominio, URL…) |
| **Herramientas** | Ejecutar una herramienta sobre los datos del caso, con indicador 🟢 🟡 🔴 de si tienes lo que necesita |
| **Perfilamiento** | Buscar a una **persona** con muchas herramientas a la vez y revisar candidatos |
| **Correlación** | Ver cómo se relacionan los datos del caso (qué correo va con qué usuario, qué perfil con qué nombre…), comparar casos y **cruzar las tecnologías detectadas con el CTI** (botón "Cruzar con CTI") |
| **CTI** | Recolectar feeds de amenazas y generar dossiers por cliente y boletines HTML |
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
  (por ejemplo `mx.linkedin.com` cuando buscas a alguien de Ecuador). **Solo avisa y baja la puntuación; nunca descarta**:
  la decisión es tuya.
- **Listados omitidos:** los directorios y buscadores de personas ("600+ perfiles") no son una persona y no aparecen como
  candidatos, pero siguen guardados en el reporte.

### Confirmar, descartar y refinar

- **✅ Confirmar** un candidato pasa al caso lo que aporta (su perfil, usuario, correo, empresa y ubicación) como dato
  confirmado. No cambia el objetivo ni duplica datos.
- **❌ Descartar** solo marca el candidato; **no borra** lo que ya se hubiera añadido (se corrige en la pestaña Datos).
- **🔄 Refinar búsqueda** vuelve a buscar usando lo que aportaron los candidatos confirmados.
- **Exportar** guarda el resultado en tu carpeta de Descargas (JSON/HTML, **sin cifrar**: trátalo como dato personal).

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

---

## 5. Claves de API

La mayoría de las herramientas **no necesitan clave**. Para las que sí (GitHub, Hunter.io, CENSYS, etc.):

```bash
python -m osint_app.main --set-key GitHub     # te pide la clave sin mostrarla y la guarda
python -m osint_app.main --keys               # qué claves tienes (nunca muestra su valor)
```

- **No escribas la clave en el mismo comando**: quedaría en el historial de la consola.
- En Windows las claves se guardan **cifradas** (solo tu usuario de Windows en este equipo puede leerlas).
- También sirven las variables de entorno (`GITHUB_TOKEN`, `OSINT_HUNTER_KEY`…); tienen prioridad sobre las guardadas.
- Tener un token de **GitHub** sube el límite de consultas de 60 a 5.000 por hora.

---

## 6. Preguntas frecuentes

**¿Mis datos salen a internet?**
Las consultas sí: cada herramienta consulta fuentes públicas (buscadores, GitHub, registros de dominios…). Tus **casos** se
guardan solo en tu equipo.

**¿Por qué una búsqueda devuelve 0 resultados?**
DuckDuckGo bloquea por ráfagas de consultas (dura de 10 a 30 minutos). Espera un rato o reduce las herramientas de búsqueda.
Una clave de una API de búsqueda lo resolvería.

**¿Qué hago con los candidatos con ⚠️?**
Míralos antes de confirmar: pueden ser otra persona con el mismo nombre. Añadir empresa, universidad y ciudad en
"Más datos del objetivo" ayuda a distinguirlos.

**¿Dónde veo cómo se unen los datos?**
En **Correlación → Analizar**: muestra, por ejemplo, que un perfil de GitHub y una cuenta de X usan el mismo usuario, o
que un correo sigue el patrón del nombre (`jriofrio` ~ Juan Riofrio).

**¿Qué hago con la base antigua dentro de OneDrive?**
Si venías de una versión anterior, tu base se **copió** a la carpeta nueva y la original quedó donde estaba. Cuando
confirmes que todo está bien en la nueva, borra la antigua (`osint_app/data/osint_v2.db`) para que deje de estar en la nube.
