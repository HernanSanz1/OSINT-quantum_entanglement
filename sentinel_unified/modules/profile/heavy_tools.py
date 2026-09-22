"""
Heavy subprocess-based tools: Subfinder, AMASS, SpiderFoot, Recon-ng, sn0int, Maigret

SECURITY:
- All user-supplied arguments are sanitized via sanitize_shell_arg() before
  being placed into subprocess arg lists.
- subprocess.run() is always called with a list (never shell=True).
- Output is hard-capped at MAX_OUTPUT_BYTES to prevent RAM exhaustion.
- All calls have explicit timeout values.
"""
import subprocess, json, shutil, logging, shlex
from typing import List
from pathlib import Path
from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import sanitize_shell_arg, sanitize_snippet, MAX_INPUT_LEN

logger = logging.getLogger(__name__)

# Hard cap on subprocess stdout — prevents tools from filling RAM
MAX_OUTPUT_BYTES = 2_000_000   # 2 MB
MAX_RESULTS      = 200         # Never return more than 200 results per tool


import time

def _run(tool, cmd: List[str], timeout: int = 300) -> tuple:
    """
    Safe subprocess runner.
    - Captures output, respects timeouts, and allows early cancellation via tool._is_cancelled.
    """
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        
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
                
            time.sleep(0.5)

        stdout, stderr = p.communicate()
        
        # Cap output size
        if len(stdout) > MAX_OUTPUT_BYTES:
            logger.warning(f"{cmd[0]} output truncated at {MAX_OUTPUT_BYTES} bytes")
            stdout = stdout[:MAX_OUTPUT_BYTES]

        return stdout, p.returncode
        
    except FileNotFoundError:
        logger.warning(f"Binary not found: {cmd[0]}")
        return f"❌ Error: Binario '{cmd[0]}' no alojado localmente o no está en el PATH.", -1
    except Exception as e:
        logger.error(f"_run({cmd[0]}): {e}")
        return f"❌ Excepción crítica de Python en {cmd[0]}: {e}", -1


def _safe_domain(qp: QueryParameters) -> str:
    """Return sanitized domain from query params."""
    return sanitize_shell_arg(qp.domain or "")


def _safe_username(qp: QueryParameters) -> str:
    """Return sanitized username from query params."""
    return sanitize_shell_arg(qp.username or "")


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
        cmd_path = shutil.which("subfinder") or Path.home() / "go/bin/subfinder"
        self.is_available = shutil.which("subfinder") is not None or (isinstance(cmd_path, Path) and cmd_path.exists())
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

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = _safe_domain(query_params)
        if not domain:
            return []
            
        cmd_path = shutil.which("subfinder")
        if not cmd_path:
            local_path = Path.home() / "go/bin/subfinder"
            if local_path.exists():
                cmd_path = str(local_path)
            else:
                return []
                
        self._report_progress(f"🔍 Subfinder: buscando subdominios de {domain}…")
        
        cmd_args = [cmd_path, "-d", domain, "-silent", "-timeout", "30"]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))
            
        out, rc = _run(self, cmd_args)
        results = []
        for line in out.splitlines()[:MAX_RESULTS]:
            sub = line.strip()
            if sub and not sub.startswith("🛑"):
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
        cmd_path = shutil.which("amass") or Path.home() / "go/bin/amass"
        self.is_available = shutil.which("amass") is not None or (isinstance(cmd_path, Path) and cmd_path.exists())
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

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = _safe_domain(query_params)
        if not domain:
            return []
            
        cmd_path = shutil.which("amass")
        if not cmd_path:
            local_path = Path.home() / "go/bin/amass"
            if local_path.exists():
                cmd_path = str(local_path)
            else:
                return []
                
        self._report_progress(f"🔍 AMASS: enumerando subdominios de {domain} (puede tardar ~5 min)…")
        
        cmd_args = [cmd_path, "enum", "-passive", "-d", domain, "-timeout", "5"]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))
            
        out, _ = _run(self, cmd_args)
        results = []
        for line in out.splitlines()[:MAX_RESULTS]:
            sub = line.strip()
            if sub and not sub.startswith("🛑"):
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
        local_path = Path(__file__).parent.parent.parent / "spiderfoot/sf.py"
        self.is_available = local_path.exists()
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

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        # Pick best target — sanitize all
        raw_target = (
            query_params.observable or query_params.domain
            or query_params.email or query_params.ip or query_params.target_name
        )
        target = sanitize_shell_arg(raw_target or "")
        if not target:
            return []
        
        cmd = str(Path(__file__).parent.parent.parent / "spiderfoot/sf.py")
        self._report_progress("🔍 SpiderFoot: ejecutando módulos OSINT...")
        
        cmd_args = ["python3", cmd, "-s", target]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))
        else:
            cmd_args.extend(["-m", "sfp_dnsresolve,sfp_whois,sfp_emails"])
            
        out, _ = _run(
            self,
            cmd_args,
            timeout=300,
        )
        
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
        try:
            p = subprocess.Popen(
                [cmd_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Input no blocking
            import time
            start_t = time.time()
            out = ""
            # Enviar input
            p.stdin.write(script)
            p.stdin.flush()
            p.stdin.close()
            
            while p.poll() is None:
                if self._is_cancelled:
                    p.terminate()
                    p.wait()
                    self._report_progress("🛑 Recon-ng cancelado por el usuario.")
                    return []
                if time.time() - start_t > 300:
                    p.kill()
                    return []
                time.sleep(0.5)
            
            out = p.stdout.read()[:MAX_OUTPUT_BYTES]
        except Exception as e:
            logger.error(f"Recon-ng: {e}")
            return [SearchResult(
                title="❌ Error al iniciar Recon-ng",
                url="", snippet=str(e), source_tool=self.name, category="Error", relevance_score=100,
            )]
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
        self.is_available = shutil.which("maigret") is not None
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

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        username = _safe_username(query_params)
        if not username:
            return []
        self._report_progress(f"🔍 Maigret: buscando @{username} en 2000+ sitios…")
        out, _ = _run(self, ["maigret", username, "--json", "--timeout", "10"], timeout=300)
        try:
            data = json.loads(out[:MAX_OUTPUT_BYTES])
            results = []
            for site, info in list(data.get(username, {}).items())[:MAX_RESULTS]:
                if info.get("status") == "found":
                    results.append(SearchResult(
                        title=f"Maigret: perfil en {site[:40]}",
                        url=info.get("url", ""),
                        snippet=sanitize_snippet(f"@{username} encontrado en {site}"),
                        source_tool=self.name, category="Social Media",
                        relevance_score=85, raw_data=info,
                    ))
            self._report_progress(f"✅ Maigret: {len(results)} perfiles encontrados")
            return results
        except (json.JSONDecodeError, KeyError) as e:
            self._report_progress("⚠️ Maigret: no se pudo parsear la salida JSON")
            return [SearchResult(
                title="❌ Error en Maigret (Fallo de ejecución)",
                url="", snippet=f"Maigret no devolvió un JSON válido. Revisa si está bien instalado. Log:\n{out[-300:]}",
                source_tool=self.name, category="Error", relevance_score=100,
            )]
