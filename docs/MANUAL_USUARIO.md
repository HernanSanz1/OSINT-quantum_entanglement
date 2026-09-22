# 📖 Manual de Usuario — OSINT Framework v2

> **Versión:** 2.0 Sentinel Edition  
> **Plataforma:** macOS / Linux  
> **Requisito mínimo:** Python 3.9+, 3 GB RAM libre

---

## 1. Primeros pasos

### Instalación

```bash
# 1. Clona o descarga el proyecto
cd /Users/gabysanz/Downloads/IAprototipe

# 2. Instala dependencias Python
pip install -r osint_app/requirements.txt

# 3. (Opcional) Baja el modelo de IA local
ollama pull llama3.2
```

### Lanzar la aplicación

```bash
python3 -m osint_app.main
```

Para verificar qué herramientas están instaladas sin abrir la GUI:

```bash
python3 -m osint_app.main --check-tools
```

---

## 2. Flujo de trabajo básico

```
[Abrir/Crear Caso] → [Ingresar Datos] → [Ejecutar Herramientas] → [Revisar Reportes] → [Análisis IA]
```

### Paso 1 — Casos (tab 🗂 Casos)
- Clic en **"＋ Nuevo Caso"** → ingresa nombre y descripción
- Los casos aíslan completamente sus datos y reportes
- Puedes tener múltiples casos simultáneos (ej: una investigación por persona)

### Paso 2 — Datos del objetivo (tab 📋 Datos)
- Agrega los datos conocidos sobre el objetivo:
  | Campo | Ejemplo |
  |---|---|
  | `domain` | `ejemplo.com` |
  | `email` | `info@ejemplo.com` |
  | `username` | `user123` |
  | `ip` | `192.0.2.1` |
  | `phone` | `+593912345678` |
  | `target_name` | `Juan Pérez` |
- La **confianza** (0–100) indica cuán seguro estás del dato
- Los datos se guardan automáticamente en la base de datos del caso

### Paso 3 — Herramientas (tab 🔧 Herramientas)
Cada herramienta muestra un indicador de compatibilidad:
- 🟢 **VERDE** — tienes todos los datos que esta tool necesita → clic en **Ejecutar**
- 🟡 **AMARILLO** — tienes datos parciales, la tool puede dar resultados incompletos
- 🔴 **ROJO** — faltan datos requeridos → agrega los datos indicados primero

Al terminar la ejecución, el sistema detecta **nuevas entidades** en los resultados y pregunta si quieres agregarlas al caso para usarlas con la próxima herramienta.

### Paso 4 — Reportes (tab 📄 Reportes)
- Ve los resultados de cada herramienta ejecutada
- Filtra por herramienta, categoría o puntuación
- Exporta el reporte como **JSON** o **HTML** (con tema oscuro)
- Botón **"Pasar a IA"** → envía el reporte al análisis triple-brain

### Paso 5 — IA Triple (tab 🤖 IA Triple)
- Selecciona los reportes a analizar (☑)
- Clic en **"🔍 Analizar seleccionados"**
- Los 3 cerebros responden en paralelo:
  - 🦙 **Ollama** (local) — análisis privado, sin internet
  - 🧠 **ChatGPT** — razonamiento complejo
  - 🔓 **Venice** — sin censura ni restricciones
- El panel **Consenso** muestra los puntos en común + herramientas sugeridas
- Usa el **chat** para hacer preguntas específicas sobre el caso

---

## 3. Configurar API Keys

> ⚠️ Las claves se guardan en `~/.osint_v2_keys` (fuera del repositorio, chmod 600).  
> **Nunca se guardan dentro del proyecto** y no aparecerán en git.

### Opción A — Desde la GUI
Tab **🤖 IA Triple** → botón **⚙️ Ajustes API** → ingresa tus keys → **Guardar**

### Opción B — Variables de entorno del sistema (recomendado)

Las variables van en el **shell de tu sistema** (`~/.zshrc`), completamente fuera del proyecto y del repositorio git. La app las lee automáticamente; nunca escribe nada en el proyecto.

```bash
# Abre ~/.zshrc con cualquier editor
echo 'export OSINT_OPENAI_KEY="sk-..."'  >> ~/.zshrc
echo 'export OSINT_VENICE_KEY="ven-..."' >> ~/.zshrc
echo 'export OSINT_HUNTER_KEY="..."'     >> ~/.zshrc
source ~/.zshrc   # aplica sin reiniciar
```

> ✅ Aunque descargues el proyecto, compartas el repo, o hagas `git push`, las keys **nunca viajan** — están solo en tu `~/.zshrc`.


### Opción C — Editar directamente el vault
```bash
# Abre el archivo de keys (solo tú)
cat ~/.osint_v2_keys   # solo para ver
```

---

## 4. Instalar modelos de IA local (Ollama)

```bash
# Modelo recomendado — encaja en 3 GB RAM
ollama pull llama3.2

# Modelo más potente (requiere ~5 GB RAM)
ollama pull llama3.2:8b

# Ver qué modelos tienes
ollama list
```

Desde la GUI: tab **🤖 IA** → sección **Ollama** → botón **📥 Descargar modelo**

---

## 5. Herramientas de terceros (binarios)

Estas herramientas necesitan instalación separada. Si no están instaladas, aparecen como 🔴 en la GUI:

| Herramienta | Instalación |
|---|---|
| Subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| AMASS | `brew install amass` |
| TheHarvester | `pip install theHarvester` |
| Sherlock | `pip install sherlock-project` |
| Holehe | `pip install holehe` |
| Maigret | `pip install maigret` |
| Recon-ng | `pip install recon-ng` |

---

## 6. Preguntas frecuentes

**¿Mis datos salen a internet?**  
Solo cuando usas herramientas que lo requieren (Hunter, CENSYS, etc.) y tienes su API key configurada. Ollama es 100% local.

**¿Las API keys están seguras?**  
Sí. Se guardan en `~/.osint_v2_keys` con permisos 600 (solo tú puedes leerlo) y nunca dentro del repositorio.

**¿Puedo usar la app sin API keys?**  
Sí. Ollama (local) funciona sin API keys. Las herramientas de red públicas (dnspython, Wayback, phonenumbers) tampoco las necesitan.

**¿Cuánta RAM usa la app?**  
La GUI base usa ~80 MB. Con Ollama llama3.2 activo: ~2 GB adicionales.
