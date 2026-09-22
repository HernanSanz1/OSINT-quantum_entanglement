"""
Social tools: Sherlock, Holehe, GHunt, snscrape
All via subprocess — declared with ToolRequirements.
"""
import subprocess, json, time, shutil, logging, shlex
from typing import List
from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool

logger = logging.getLogger(__name__)


def _run(cmd: List[str], timeout: int = 300):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.stdout, p.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning(f"Subprocess error ({cmd[0]}): {e}")
        return "", -1


class SherlockTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Sherlock", "Busca un username en 300+ redes sociales",
            ToolRequirements(
                mandatory=["username"],
                optional=["target_name"],
                produces=["url", "username"],
                hint="Necesita un username. Extráelo de Google Dorks o ingresa manualmente.",
            )
        )
        self.is_heavy = True
        self.is_available = shutil.which("sherlock") is not None
        self._binary_names = ["sherlock"]
        self._install_cmd = (
            "Guía de Instalación Sherlock (Entorno Virtual):\n"
            "1. Abre la terminal en IAprototipe.\n"
            "2. Activa tu entorno virtual:\n"
            "   - Mac/Linux: `source env/bin/activate`\n"
            "   - Windows: `.\\env\\Scripts\\activate`\n"
            "3. Instala a través de pip:\n"
            "   `pip install sherlock-project`"
        )

    def check_available(self) -> bool:
        self.is_available = shutil.which("sherlock") is not None
        return self.is_available

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        cmd_path = shutil.which("sherlock")
        if not cmd_path:
            return []
            
        cmd_args = [cmd_path, query_params.username]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))
        else:
            cmd_args.extend(["--print-found", "--timeout", "10"])
            
        out, code = _run(cmd_args)
        results = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                # "[+] SiteName: https://..."
                parts = line[3:].split(":", 1)
                if len(parts) == 2:
                    site, url = parts[0].strip(), parts[1].strip()
                    results.append(SearchResult(
                        title=f"Perfil en {site}: {query_params.username}",
                        url=url, snippet=f"Username {query_params.username} encontrado en {site}",
                        source_tool=self.name, category="Social Media", relevance_score=80,
                    ))
        return results


class HoleheTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Holehe", "Verifica en qué servicios está registrado un email",
            ToolRequirements(
                mandatory=["email"],
                optional=[],
                produces=["url", "domain"],
                hint="Necesita un email. Extráelo de Google Dorks o Hunter.io.",
            )
        )
        self.is_available = shutil.which("holehe") is not None
        self._binary_names = ["holehe"]
        self._install_cmd = (
            "Guía de Instalación Holehe (Entorno Virtual):\n"
            "1. Abre la terminal en IAprototipe.\n"
            "2. Activa tu entorno virtual:\n"
            "   - Mac/Linux: `source env/bin/activate`\n"
            "   - Windows: `.\\env\\Scripts\\activate`\n"
            "3. Instala a través de pip:\n"
            "   `pip install holehe`"
        )

    def check_available(self) -> bool:
        self.is_available = shutil.which("holehe") is not None
        return self.is_available

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        cmd_path = shutil.which("holehe")
        if not cmd_path:
            return []
        out, _ = _run([cmd_path, query_params.email, "--only-used"])
        results = []
        for line in out.splitlines():
            line = line.strip()
            if "[+]" in line or "used" in line.lower():
                service = line.replace("[+]", "").strip()
                results.append(SearchResult(
                    title=f"Email registrado en: {service}",
                    url="", snippet=f"{query_params.email} tiene cuenta en {service}",
                    source_tool=self.name, category="Email Social", relevance_score=85,
                ))
        return results


class GHuntTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "GHunt", "OSINT sobre cuenta Google (Gmail)",
            ToolRequirements(
                mandatory=["email"],
                optional=[],
                produces=["name", "url", "username"],
                hint="Necesita un email Gmail. Ingresa manualmente.",
            )
        )
        self.is_available = shutil.which("ghunt") is not None
        self._binary_names = ["ghunt"]
        self._install_cmd = (
            "Guía de Instalación GHunt (Entorno Virtual):\n"
            "1. Abre la terminal en IAprototipe.\n"
            "2. Activa tu entorno virtual:\n"
            "   - Mac/Linux: `source env/bin/activate`\n"
            "   - Windows: `.\\env\\Scripts\\activate`\n"
            "3. Instala a través de pip:\n"
            "   `pip install ghunt`\n"
            "4. IMPORTANTE: Para usarlo, primero debes autenticarte. Ejecuta en la terminal:\n"
            "   `ghunt login`\n"
            "Sigue las instrucciones en pantalla para inyectar tus cookies de sesión de Google."
        )

    def check_available(self) -> bool:
        self.is_available = shutil.which("ghunt") is not None
        return self.is_available

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        cmd_path = shutil.which("ghunt")
        if not cmd_path:
            return []
        
        cmd_args = [cmd_path, "email", query_params.email]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))
            
        out, _ = _run(cmd_args, timeout=120)
        if not out:
            return []
            
        # Detect auth error in merged stdout/stderr
        if "load_and_auth" in out or "ghunt login" in out.lower() or "auth" in out.lower():
            return [SearchResult(
                title=f"⚠️ GHunt Bloqueado: Falta Autenticación",
                url="", snippet="GHunt requiere que inicies sesión primero. Abre una terminal, activa el entorno y ejecuta 'ghunt login'.\n" + out[-200:],
                source_tool=self.name, category="Error", relevance_score=100,
            )]
            
        return [SearchResult(
            title=f"GHunt — análisis de {query_params.email}",
            url=f"https://accounts.google.com/",
            snippet=out[:500],
            source_tool=self.name, category="Google Account", relevance_score=90,
        )]


class SnscrapeYoutubeTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "snscrape", "Scraping de publicaciones en redes sociales",
            ToolRequirements(
                mandatory=["username"],
                optional=["target_name"],
                produces=["url", "note"],
                hint="Necesita un username. Obtén uno con Sherlock o Google Dorks primero.",
            )
        )
        self.is_available = shutil.which("snscrape") is not None
        self._binary_names = ["snscrape"]
        self._install_cmd = (
            "Guía de Instalación (Entorno Virtual Python):\n"
            "1. Abre la terminal en IAprototipe y activa tu entorno virtual:\n"
            "   source env/bin/activate\n"
            "2. Instala snscrape a través de pip:\n"
            "   pip install snscrape"
        )

    def check_available(self) -> bool:
        self.is_available = shutil.which("snscrape") is not None
        return self.is_available

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        return [SearchResult(
            title=f"❌ Herramienta Obsoleta: snscrape",
            url="",
            snippet="snscrape ha sido desactivado permanentemente en Sentinel.\n"
                    "1. La API pública de Twitter/X fue cerrada, impidiendo el scraping anónimo.\n"
                    "2. El paquete `snscrape` está abandonado y su código usa `find_module`, el cual fue eliminado en Python 3.12, causando crasheos (AttributeError).\n\n"
                    "👉 Recomendación: Utilizar herramientas alternativas modernas basadas en cookies o APIs oficiales para inteligencia en redes sociales.",
            source_tool=self.name,
            category="Error / Deprecado",
            relevance_score=100,
        )]


class InstagramTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Instaloader", "Extracción OSINT de perfiles y posts de Instagram",
            ToolRequirements(
                mandatory=["username"],
                optional=["observable"],
                produces=["url", "note", "username"],
                hint="Pon el username de la cuenta, o el Shortcode del Post en 'observable'.",
            )
        )
        self.is_heavy = False
        self.is_available = shutil.which("instaloader") is not None
        self._binary_names = ["instaloader"]
        self._install_cmd = (
            "Guía de Instalación Instaloader (Entorno Virtual):\n"
            "1. Abre la terminal en IAprototipe.\n"
            "2. Activa tu entorno virtual:\n"
            "   - Mac/Linux: `source env/bin/activate`\n"
            "   - Windows: `.\\env\\Scripts\\activate`\n"
            "3. Instala a través de pip:\n"
            "   `pip install instaloader`"
        )

    def check_available(self) -> bool:
        import importlib.util, sys
        self.is_available = (shutil.which("instaloader") is not None) or (importlib.util.find_spec("instaloader") is not None)
        return self.is_available

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        import importlib.util, sys
        
        cmd_path = shutil.which("instaloader")
        has_module = importlib.util.find_spec("instaloader") is not None
        
        if not cmd_path and not has_module:
            return []
            
        target = query_params.observable if query_params.observable else query_params.username
        if not target:
            return []
            
        # Basic anonymous scraping
        if has_module:
            cmd = [sys.executable, "-m", "instaloader", "--login=anon", "--fast-update"]
        else:
            cmd = [cmd_path, "--login=anon", "--fast-update"]
        
        if query_params.extra_args:
             cmd.extend(shlex.split(query_params.extra_args))
        else:
             if query_params.observable and len(query_params.observable) >= 10:
                  cmd.extend(["--post", target])
             else:
                  cmd.append(target)
             
        out, _ = _run(cmd, timeout=120)
        
        if not out.strip():
             return []
             
        # Guard against huge outputs
        snippet = out[:1000] + "..." if len(out) > 1000 else out
             
        return [SearchResult(
            title=f"Extracción Instaloader: {target}",
            url=f"https://instagram.com/p/{target}" if "--post" in cmd else f"https://instagram.com/{target}",
            snippet=snippet,
            source_tool=self.name, category="Social Media", relevance_score=85,
        )]
