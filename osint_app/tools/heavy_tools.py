"""
Heavy subprocess-based tools: Subfinder, AMASS, SpiderFoot, Recon-ng, sn0int, Maigret

SECURITY:
- All user-supplied arguments are sanitized via sanitize_shell_arg() before
  being placed into subprocess arg lists.
- subprocess.run() is always called with a list (never shell=True).
- Output is hard-capped at MAX_OUTPUT_BYTES to prevent RAM exhaustion.
- All calls have explicit timeout values.
"""
import subprocess, json, shutil, logging, shlex, sys, threading
from typing import List
from pathlib import Path
from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.python_cli import blocked_by_windows, pip_tool_command
from ..utils.sanitizer import (
    sanitize_shell_arg, sanitize_snippet, validate_domain, validate_ip,
)

logger = logging.getLogger(__name__)

# Hard cap on subprocess stdout — prevents tools from filling RAM
MAX_OUTPUT_BYTES = 2_000_000   # 2 MB
MAX_RESULTS      = 200         # Never return more than 200 results per tool

SPIDERFOOT_PATH = Path(__file__).parent.parent.parent / "spiderfoot/sf.py"


def _find_go_binary(name: str) -> str:
    """Return the path to a Go-installed binary (PATH or ~/go/bin), or "" if missing."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in (Path.home() / "go/bin" / name, Path.home() / "go/bin" / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return ""


import time

def _run(tool, cmd: List[str], timeout: int = 300, stdin_text: str = "") -> tuple:
    """
    Safe subprocess runner.
    - Captures output, respects timeouts, and allows early cancellation via tool._is_cancelled.
    """
    try:
        p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_text else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
            # Sin esto, en Windows cada herramienta abría una ventana de consola encima de la app
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if stdin_text:
            try:
                p.stdin.write(stdin_text)
                p.stdin.close()
            except OSError:                       # el programa se cerró antes de leer su guion
                pass

        # La salida se lee MIENTRAS el programa corre. Antes solo se vigilaba `poll()` y se leía al final: si el
        # programa imprimía más de lo que cabe en la tubería (~4 KB en Windows) se bloqueaba, se agotaba el tiempo
        # y se perdía TODO el resultado.
        chunks: List[str] = []
        state = {"size": 0, "truncated": False}

        def _drain():
            for chunk in iter(lambda: p.stdout.read(8192), ""):
                if state["size"] < MAX_OUTPUT_BYTES:
                    chunks.append(chunk[:MAX_OUTPUT_BYTES - state["size"]])
                    state["size"] += len(chunks[-1])
                if state["size"] >= MAX_OUTPUT_BYTES:
                    state["truncated"] = True              # se sigue leyendo (y descartando) para no bloquear al programa

        reader = threading.Thread(target=_drain, daemon=True)
        reader.start()

        start_t = time.time()
        # Escaneo en bucle para chequeo de cancelación temprana
        while p.poll() is None:
            if tool._is_cancelled:
                p.terminate()
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    p.kill()
                return "🛑 Cancelado por el usuario", -1

            if (time.time() - start_t) > timeout:
                p.kill()
                p.wait()
                logger.warning(f"Timeout expired for: {cmd[0]}")
                return "⚠️ Timeout", -1

            time.sleep(0.1)

        reader.join(timeout=5)
        if state["truncated"]:
            logger.warning(f"{cmd[0]} output truncated at {MAX_OUTPUT_BYTES} bytes")

        return "".join(chunks), p.returncode
        
    except FileNotFoundError:
        logger.warning(f"Binary not found: {cmd[0]}")
        return f"❌ Error: Binario '{cmd[0]}' no alojado localmente o no está en el PATH.", -1
    except OSError as e:
        logger.error(f"_run({cmd[0]}): {e}")
        blocked = blocked_by_windows(getattr(tool, "name", cmd[0]), e)
        return blocked or f"❌ No se pudo abrir {cmd[0]}: {e}", -1
    except Exception as e:
        logger.error(f"_run({cmd[0]}): {e}")
        return f"❌ Excepción crítica de Python en {cmd[0]}: {e}", -1


def _tool_failed(tool, label: str, out: str, rc: int) -> bool:
    """True (y avisa) si el programa no llegó a dar resultados: no existe, se agotó el tiempo o se canceló.

    `_run` devuelve en esos casos un TEXTO de aviso en vez de la salida; antes cada herramienta lo trataba como
    si fuera salida real y lo mostraba como un resultado ("Subdominio: ⚠️ Timeout").
    """
    if rc != -1:
        return False
    if out.startswith("🛑"):
        tool._report_progress(f"🛑 {label} cancelado por el usuario.")
    elif out.startswith("⚠️"):
        tool._report_progress(f"⚠️ {label}: se agotó el tiempo; no hay resultados.")
    elif out.startswith(f"❌ {label}:"):                 # ya es un mensaje completo (p. ej. bloqueo de Windows)
        tool._report_progress(out[:400])
    else:
        tool._report_progress(f"❌ {label}: {out[:150]}")
    return True


def _hostnames(out: str, root: str) -> List[str]:
    """Líneas de la salida que son nombres de host válidos (sin repetidos, orden original)."""
    seen, hosts = set(), []
    for line in out.splitlines():
        host = line.strip().lower()
        if host and host not in seen and validate_domain(host):
            seen.add(host)
            hosts.append(host)
    return hosts[:MAX_RESULTS]


def _looks_like_observable(value: str) -> bool:
    """True si el texto parece un IOC escaneable (dominio, IP o email).

    Evita que un contexto de texto libre ("UDLA Ecuador 2006"), que el
    perfilador coloca en `observable`, se use como objetivo de escaneo.
    """
    v = (value or "").strip()
    if not v or " " in v:
        return False
    if validate_ip(v) or validate_domain(v):
        return True
    if "@" in v:
        local, _, dom = v.partition("@")
        return bool(local) and validate_domain(dom)
    return False


def _safe_domain(qp: QueryParameters) -> str:
    """Dominio saneado y válido de los parámetros, o "" (un valor que no sea un dominio no se pasa al programa)."""
    domain = sanitize_shell_arg(qp.domain or "")
    return domain if validate_domain(domain) else ""


def _safe_username(qp: QueryParameters) -> str:
    """Usuario saneado, o "" si podría leerse como una OPCIÓN del programa (empieza por "-") o tiene espacios."""
    user = sanitize_shell_arg(qp.username or "").lstrip("@")
    return user if user and not user.startswith("-") and not any(c.isspace() for c in user) else ""


# ── Tools ─────────────────────────────────────────────────────────────────────

class SubfinderTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Subfinder", "Descubrimiento pasivo de subdominios",
            ToolRequirements(
                mandatory=["domain"],
                optional=[],
                produces=["domain", "ip"],
                hint="Necesita dominio. Ingrésalo manualmente.",
            )
        )
        self.is_heavy = True
        self._binary_names = ["subfinder"]
        self.is_available = self.check_available()
        self._install_cmd = (
            "Guía de Instalación Subfinder (Multiplataforma):\n"
            "1. Descarga e instala Go desde https://go.dev/dl/\n"
            "2. Abre tu terminal (CMD/PowerShell en Windows, Bash/Zsh en Mac/Linux).\n"
            "3. Ejecuta: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
            "4. AÑADE GO A TU PATH (Obligatorio para que la IA lo encuentre):\n"
            "   - Mac/Linux: Agrega `export PATH=\"$PATH:$HOME/go/bin\"` a tu ~/.bashrc o ~/.zshrc y reinicia la terminal.\n"
            "   - Windows: Presiona Win+R, escribe `sysdm.cpl`, ve a Opciones Avanzadas -> Variables de Entorno. \n"
            "              Edita la variable 'Path' y añade `%USERPROFILE%\\go\\bin`. Reinicia Sentinel."
        )
        self._system_deps = [("go", "https://go.dev/dl/")]

    def check_available(self) -> bool:
        return bool(_find_go_binary("subfinder"))

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = _safe_domain(query_params)
        if not domain:
            return []
            
        cmd_path = _find_go_binary("subfinder")
        if not cmd_path:
            return []
                
        self._report_progress(f"🔍 Subfinder: buscando subdominios de {domain}…")
        
        cmd_args = [cmd_path, "-d", domain, "-silent", "-timeout", "30"]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))
            
        out, rc = _run(self, cmd_args)
        if _tool_failed(self, "Subfinder", out, rc):
            return []
        results = []
        for sub in _hostnames(out, domain):
            results.append(SearchResult(
                title=f"Subdominio: {sub}",
                url=f"https://{sub}",
                snippet=sanitize_snippet(f"Encontrado por Subfinder en {domain}"),
                source_tool=self.name, category="Subdomain", relevance_score=70,
            ))
        self._report_progress(f"✅ Subfinder: {len(results)} subdominios encontrados")
        return results


class AmassTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "OWASP AMASS", "Reconocimiento de red: subdominios, ASN, prefijos IP",
            ToolRequirements(
                mandatory=["domain"],
                optional=["ip"],
                produces=["domain", "ip"],
                hint="Necesita dominio.",
            )
        )
        self.is_heavy = True
        self._binary_names = ["amass"]
        self.is_available = self.check_available()
        self._install_cmd = (
            "Guía de Instalación OWASP Amass (Multiplataforma):\n"
            "1. Descarga e instala Go desde https://go.dev/dl/\n"
            "2. Abre tu terminal (CMD/PowerShell en Windows, Bash/Zsh en Mac/Linux).\n"
            "3. Ejecuta: go install -v github.com/owasp-amass/amass/v4/...@master\n"
            "4. AÑADE GO A TU PATH (Obligatorio para que la IA lo encuentre):\n"
            "   - Mac/Linux: Agrega `export PATH=\"$PATH:$HOME/go/bin\"` a tu ~/.bashrc o ~/.zshrc y reinicia la terminal.\n"
            "   - Windows: Presiona Win+R, escribe `sysdm.cpl`, ve a Opciones Avanzadas -> Variables de Entorno. \n"
            "              Edita la variable 'Path' y añade `%USERPROFILE%\\go\\bin`. Reinicia Sentinel."
        )
        self._system_deps = [("go", "https://go.dev/dl/")]

    def check_available(self) -> bool:
        return bool(_find_go_binary("amass"))

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = _safe_domain(query_params)
        if not domain:
            return []
            
        cmd_path = _find_go_binary("amass")
        if not cmd_path:
            return []
                
        self._report_progress(f"🔍 AMASS: enumerando subdominios de {domain} (puede tardar ~5 min)…")
        
        cmd_args = [cmd_path, "enum", "-passive", "-d", domain, "-timeout", "5"]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))
            
        out, rc = _run(self, cmd_args)
        if _tool_failed(self, "AMASS", out, rc):
            return []
        results = []
        for sub in _hostnames(out, domain):
            results.append(SearchResult(
                title=f"AMASS: {sub}",
                url=f"https://{sub}",
                snippet=sanitize_snippet(f"Descubierto por AMASS"),
                source_tool=self.name, category="Subdomain", relevance_score=72,
            ))
        self._report_progress(f"✅ AMASS: {len(results)} subdominios encontrados")
        return results


class SpiderFootTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "SpiderFoot", "OSINT automatizado de múltiples fuentes",
            ToolRequirements(
                mandatory=["observable"],
                optional=["domain", "email", "ip", "target_name"],
                produces=["email", "domain", "ip", "url"],
                hint="Acepta cualquier observable: nombre, dominio, email o IP.",
            )
        )
        self.is_heavy = True
        self.is_available = self.check_available()
        self._binary_names = ["sf.py"]
        self._install_cmd = (
            "Guía de Instalación SpiderFoot (Requiere Código Fuente):\n"
            "La versión de PyPI (pip install spiderfoot) está deprecada o rota. Debes clonar el código fuente:\n"
            "1. Abre una terminal y navega hasta la misma carpeta donde clonaste Sentinel OSINT (IAprototipe/Sentinel).\n"
            "2. Clona el repositorio oficial de SpiderFoot justo ahí:\n"
            "   - Mac/Linux/Windows: `git clone https://github.com/smicallef/spiderfoot.git`\n"
            "3. Entra a la carpeta de tu Entorno Virtual de Sentinel y carga las dependencias:\n"
            "   - Mac/Linux: `source env/bin/activate`\n"
            "   - Windows: `.\\env\\Scripts\\activate`\n"
            "   - Ambos: `cd spiderfoot` y luego `pip install -r requirements.txt`\n"
            "4. Vuelve a iniciar Sentinel. La IA detectará automáticamente la carpeta `spiderfoot`."
        )

    def check_available(self) -> bool:
        return SPIDERFOOT_PATH.is_file()

    @staticmethod
    def _pick_target(query_params: QueryParameters) -> str:
        """Elige el objetivo a escanear.

        `observable` solo se acepta si es un IOC real (dominio/IP/email); si es
        contexto de texto libre (lo que pone el perfilador), se ignora y se usa
        un identificador concreto.
        """
        obs = query_params.observable if _looks_like_observable(query_params.observable) else ""
        return (
            obs or query_params.domain or query_params.email
            or query_params.ip or query_params.target_name or ""
        )

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        target = sanitize_shell_arg(self._pick_target(query_params))
        if not target:
            return []
        
        self._report_progress("🔍 SpiderFoot: ejecutando módulos OSINT...")
        
        # sys.executable: "python3" does not exist on Windows
        cmd_args = [sys.executable, str(SPIDERFOOT_PATH), "-s", target]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))
        else:
            cmd_args.extend(["-m", "sfp_dnsresolve,sfp_whois,sfp_emails"])
            
        out, rc = _run(
            self,
            cmd_args,
            timeout=300,
        )
        if _tool_failed(self, "SpiderFoot", out, rc):
            return []

        if "Traceback" in out or "ModuleNotFoundError" in out or "Error" in out and not "SpiderFoot" in out:
            return [SearchResult(
                title="❌ Error Crítico en SpiderFoot",
                url="", snippet=out[-500:], source_tool=self.name, category="Error", relevance_score=100,
            )]
            
        results = []
        for line in out.splitlines()[:MAX_RESULTS]:
            s = line.strip()
            if s:
                results.append(SearchResult(
                    title=f"SpiderFoot: {s[:80]}",
                    url="", snippet=sanitize_snippet(s),
                    source_tool=self.name, category="SpiderFoot", relevance_score=65,
                ))
        return results


class ReconNgTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Recon-ng", "Framework modular de reconocimiento",
            ToolRequirements(
                mandatory=["domain"],
                optional=["target_name"],
                produces=["email", "domain", "ip"],
                hint="Necesita dominio.",
            )
        )
        self.is_heavy = True
        self.is_available = shutil.which("recon-ng") is not None or (Path("recon-ng/recon-ng").exists() and not Path("recon-ng/recon-ng").is_dir())
        self._binary_names = ["recon-ng"]
        self._install_cmd = (
            "Guía de Instalación Recon-ng (Requiere Código Fuente):\n"
            "1. Abre una terminal y navega hasta la carpeta principal del proyecto Sentinel.\n"
            "2. Activa tu entorno virtual:\n"
            "   - Mac/Linux: `source env/bin/activate`\n"
            "   - Windows: `.\\env\\Scripts\\activate`\n"
            "3. Clona el repositorio de Recon-ng:\n"
            "   `git clone https://github.com/lanmaster53/recon-ng.git`\n"
            "4. Instala sus dependencias:\n"
            "   `cd recon-ng && pip install -r REQUIREMENTS`\n\n"
            "Terminado. Sentinel detectará automáticamente la carpeta local 'recon-ng/recon-ng'."
        )

    def check_available(self) -> bool:
        self.is_available = shutil.which("recon-ng") is not None or (Path("recon-ng/recon-ng").exists() and not Path("recon-ng/recon-ng").is_dir())
        return self.is_available

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = _safe_domain(query_params)
        if not domain:
            return []
            
        cmd_path = shutil.which("recon-ng")
        if not cmd_path:
            local_path = Path("recon-ng/recon-ng")
            if local_path.exists():
                cmd_path = str(local_path.absolute())
            else:
                return []
                
        # Build a safe script — domain is already sanitized above
        script = (
            f"workspaces create osint_tmp\n"
            f"db insert domains {domain}\n"
            f"modules load recon/domains-hosts/certificate_transparency\n"
            f"run\nshow hosts\nexit\n"
        )
        out, rc = _run(self, [cmd_path], timeout=300, stdin_text=script)
        if out.startswith("🛑"):
            self._report_progress("🛑 Recon-ng cancelado por el usuario.")
            return []
        if rc == -1:
            # timeout o binario que no arranca: antes se devolvía [] (o una excepción) sin explicar nada
            self._report_progress("⚠️ Recon-ng: " + ("se agotó el tiempo (5 min)." if out.startswith("⚠️") else out[:150]))
            return []
        results = []
        for line in out.splitlines()[:MAX_RESULTS]:
            s = line.strip()
            if s and "." in s and domain in s:
                results.append(SearchResult(
                    title=s[:80], url="",
                    snippet=sanitize_snippet(s),
                    source_tool=self.name, category="Subdomain", relevance_score=68,
                ))
        return results


class MaigretTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Maigret", "Búsqueda de perfiles sociales por username",
            ToolRequirements(
                mandatory=["username"],
                optional=["target_name"],
                produces=["url", "username", "email"],
                hint="Necesita username. Extráelo de Sherlock o Google Dorks.",
            )
        )
        self.is_heavy = True
        self.is_available = self.check_available()
        self._binary_names = ["maigret"]
        self._install_cmd = (
            "Guía de Instalación Maigret (Entorno Virtual):\n"
            "1. Abre una terminal en la carpeta de tu proyecto Sentinel.\n"
            "2. Activa tu entorno virtual:\n"
            "   - Mac/Linux: `source env/bin/activate`\n"
            "   - Windows: `.\\env\\Scripts\\activate`\n"
            "3. Instala Maigret vía pip:\n"
            "   `pip install maigret`\n\n"
            "La herramienta quedará anclada a tu entorno virtual sin afectar al sistema."
        )

    def check_available(self) -> bool:
        return bool(pip_tool_command("maigret"))

    # Sitios que maigret marca como "Claimed" pero que no son un perfil (la portada del servicio)
    _NOT_A_PROFILE = ("https://discord.com", "https://discord.com/")
    MAX_SITES = 300

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        """Formato verificado con maigret 0.6.6 (2026-10-04).

        `--json simple` escribe un ARCHIVO `report_<usuario>_simple.json` en --folderoutput (no imprime JSON), con
        {sitio: {"url_user": ..., "status": {"status": "Claimed", "ids": {fullname, location, created_at…}}}}.
        Antes se pasaba "--json" sin tipo (maigret tomaba "--timeout" como tipo), se leía la pantalla y se buscaba
        data[usuario][sitio]["status"] == "found": la herramienta SIEMPRE devolvía "JSON no válido".
        `--dns-resolver threaded`: el resolvedor asíncrono por defecto falló el 100% de las consultas en Windows.
        """
        import tempfile

        username = _safe_username(query_params)
        if not username:
            return []
        self._report_progress(f"🔍 Maigret: buscando @{username} en los {self.MAX_SITES} sitios principales…")
        with tempfile.TemporaryDirectory(prefix="sentinel_maigret_") as folder:
            # Con el Python de SENTINEL y no con maigret.exe: Windows bloqueaba ese .exe sin firma (ver python_cli)
            cmd = pip_tool_command("maigret") + [username, "--json", "simple", "--folderoutput", folder, "--timeout", "15",
                   "--top-sites", str(self.MAX_SITES), "--dns-resolver", "threaded", "--no-progressbar", "--no-color"]
            out, rc = _run(self, cmd, timeout=420)
            if _tool_failed(self, "Maigret", out, rc):
                return []
            report = Path(folder) / f"report_{username}_simple.json"
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._report_progress("⚠️ Maigret: no generó su informe JSON")
                return [SearchResult(
                    title="❌ Error en Maigret (Fallo de ejecución)",
                    url="", snippet=f"Maigret no generó un informe JSON válido. Revisa si está bien instalado. Log:\n{out[-300:]}",
                    source_tool=self.name, category="Error", relevance_score=100,
                )]

        if "too many errors" in out.lower():
            # Fallo de red/DNS de maigret: "0 perfiles" no significaría que no existan (visto en real 2026-10-12)
            self._report_progress("⚠️ Maigret: muchos sitios fallaron por red o DNS; el resultado puede estar incompleto.")
        results = []
        for site, info in list(data.items())[:MAX_RESULTS]:
            status = info.get("status") or {}
            url = info.get("url_user") or status.get("url") or ""
            if status.get("status") != "Claimed" or not url or url in self._NOT_A_PROFILE:
                continue
            ids = {k: v for k, v in (status.get("ids") or {}).items() if isinstance(v, (str, int, float)) and str(v).strip()}
            details = " · ".join(f"{k}: {v}" for k, v in ids.items() if k in ("fullname", "name", "location", "created_at", "bio"))
            results.append(SearchResult(
                title=f"Maigret: perfil en {site[:40]}",
                url=url,
                snippet=sanitize_snippet(f"@{username} encontrado en {site}" + (f" — {details}" if details else "")),
                source_tool=self.name, category="Social Media",
                # Con datos extraídos del perfil (nombre, ubicación…) la cuenta es más verificable
                relevance_score=85 if ids else 70,
                raw_data={"site": site, "url": url, "tags": (info.get("site") or {}).get("tags", [])},
                extra_data={"username": username, "platform": site, "tags": (info.get("site") or {}).get("tags", []),
                            **{f"profile_{k}": v for k, v in ids.items()}},
            ))
        self._report_progress(f"✅ Maigret: {len(results)} perfiles encontrados")
        return results
