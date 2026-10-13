"""
Social tools: Sherlock, Holehe, GHunt, snscrape
All via subprocess — declared with ToolRequirements.
"""
import subprocess, shutil, logging, shlex, re
from typing import List
from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import sanitize_snippet

logger = logging.getLogger(__name__)


# Los datos que llegan al programa externo se validan: uno que empiece por "-" se leería como una OPCIÓN del
# programa (y los usuarios pueden venir de URLs de resultados web de terceros en la búsqueda encadenada).
_USERNAME_RE = re.compile(r"^[^\W-][\w.-]{0,63}$")
_EMAIL_RE = re.compile(r"^[^\s@-][^\s@]*@[^\s@]+\.[^\s@]+$")
_SHORTCODE_RE = re.compile(r"^[A-Za-z0-9_-]{10,40}$")      # código de una publicación de Instagram
_HOLEHE_SERVICE = re.compile(r"^\[\+\]\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})$", re.IGNORECASE)   # "[+] twitter.com"


def _clean_username(value: str) -> str:
    """Usuario sin '@' o '' si no es seguro pasarlo a un programa externo."""
    user = (value or "").strip().lstrip("@")
    return user if _USERNAME_RE.match(user) else ""


def _clean_email(value: str) -> str:
    email = (value or "").strip()
    return email if _EMAIL_RE.match(email) else ""


def child_env() -> dict:
    """Entorno para programas externos: que los hechos en Python escriban en UTF-8 (en Windows usan cp1252)."""
    import os
    return {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}


def _run(cmd: List[str], timeout: int = 300):
    # encoding explícito: con text=True a secas Windows decodifica en cp1252 y la barra de progreso de Holehe
    # ("█") hacía caer la lectura (UnicodeDecodeError) y luego la herramienta (stdout None). Verificado en real.
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, env=child_env(),
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))  # sin ventana de consola en Windows
        return p.stdout or "", p.returncode
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
        username = _clean_username(query_params.username)
        if not username:
            self._report_progress("⚠️ Sherlock: el usuario está vacío o no es válido (no puede empezar por '-').")
            return []

        cmd_args = [cmd_path, username]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))
        else:
            cmd_args.extend(["--print-found", "--timeout", "10"])

        out, code = _run(cmd_args)
        if code == -1:
            self._report_progress("⚠️ Sherlock: se agotó el tiempo (5 min) o no se pudo ejecutar; no hay resultados.")
        results = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("[+]"):
                # "[+] SiteName: https://..."
                parts = line[3:].split(":", 1)
                if len(parts) == 2:
                    site, url = parts[0].strip(), parts[1].strip()
                    results.append(SearchResult(
                        title=f"Perfil en {site}: {username}",
                        url=url, snippet=f"Username {username} encontrado en {site}",
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
        email = _clean_email(query_params.email)
        if not email:
            self._report_progress("⚠️ Holehe: el correo está vacío o no es válido.")
            return []
        out, code = _run([cmd_path, email, "--only-used"])
        if code == -1:
            self._report_progress("⚠️ Holehe: se agotó el tiempo o no se pudo ejecutar; no hay resultados.")
        results = []
        for line in out.splitlines():
            line = line.strip()
            # Solo "[+] servicio.com" (antes también cualquier línea con "used": la propia ayuda de Holehe).
            # Verificado con holehe 1.61 real: imprime SIEMPRE la leyenda "[+] Email used, [-] Email not used,
            # [x] Rate limit", que empieza por "[+]" y se habría dado como servicio en cada búsqueda.
            match = _HOLEHE_SERVICE.match(line)
            if match:
                service = match.group(1)
                results.append(SearchResult(
                    title=f"Email registrado en: {service}",
                    url="", snippet=f"{email} tiene cuenta en {service}",
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
        email = _clean_email(query_params.email)
        if not email:
            self._report_progress("⚠️ GHunt: el correo está vacío o no es válido.")
            return []

        cmd_args = [cmd_path, "email", email]
        if query_params.extra_args:
            cmd_args.extend(shlex.split(query_params.extra_args))

        out, code = _run(cmd_args, timeout=120)
        if code == -1:
            self._report_progress("⚠️ GHunt: se agotó el tiempo o no se pudo ejecutar; no hay resultados.")
        if not out:
            return []

        # Falta de sesión: solo por las marcas propias de GHunt (antes bastaba que la salida contuviera "auth",
        # y un resultado normal con esa palabra se daba como "bloqueado")
        if "load_and_auth" in out or "ghunt login" in out.lower():
            return [SearchResult(
                title=f"⚠️ GHunt Bloqueado: Falta Autenticación",
                url="", snippet="GHunt requiere que inicies sesión primero. Abre una terminal, activa el entorno y ejecuta 'ghunt login'.\n" + out[-200:],
                source_tool=self.name, category="Error", relevance_score=100,
            )]
            
        return [SearchResult(
            title=f"GHunt — análisis de {email}",
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
        self.is_available = self.check_available()
        self._binary_names = ["instaloader"]
        self._python_pkgs = ["instaloader"]
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
        import importlib.util
        self.is_available = importlib.util.find_spec("instaloader") is not None     # se usa su API de Python
        return self.is_available

    def diagnose_status(self) -> dict:
        """Instalada no basta: Instagram rechaza las consultas anónimas (HTTP 429), hace falta una sesión."""
        base = super().diagnose_status()
        if base.get("status") != "ready":
            return base
        from ..utils.secret_vault import vault
        if not ((self.api_key or "").strip() or (vault.get("Instagram") or "").strip()):
            return {
                "status": "needs_key", "icon": "🔑",
                "message": ("Instaloader está instalado, pero Instagram no permite consultas anónimas. Hace falta "
                            "una sesión de una cuenta secundaria."),
                "install_cmd": ("instaloader --login TU_USUARIO      (o --load-cookies firefox)\n"
                                "python -m osint_app.main --set-key Instagram"),
            }
        return base

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        """Metadatos públicos del perfil (o de una publicación) con la API de Instaloader, sin descargar fotos.

        Verificado en real (2026-10-04):
        - Antes se lanzaba `instaloader --login=anon`, que significa "inicia sesión como el usuario anon": el
          programa esperaba la contraseña por teclado y la herramienta se colgaba 120 s sin resultado. Además,
          sin más opciones descargaba todas las fotos al disco.
        - Instagram responde HTTP 429 a TODA consulta anónima: hace falta una sesión. Si el usuario la creó
          (`instaloader --login SU_USUARIO`) y guardó su usuario con `--set-key Instagram`, se reutiliza.
        """
        try:
            import instaloader
        except ImportError:
            return []

        shortcode = query_params.observable if _SHORTCODE_RE.match(query_params.observable or "") else ""
        username = _clean_username(query_params.username)
        if not shortcode and not username:
            self._report_progress("⚠️ Instaloader: falta un usuario válido o el código de una publicación.")
            return []

        loader = instaloader.Instaloader(download_pictures=False, download_videos=False,
                                         download_video_thumbnails=False, save_metadata=False,
                                         quiet=True, max_connection_attempts=1, request_timeout=20)
        session_user = (self.api_key or "").strip()
        if not session_user:
            from ..utils.secret_vault import vault
            session_user = (vault.get("Instagram") or "").strip()
        if session_user:
            try:
                loader.load_session_from_file(session_user)
            except (FileNotFoundError, OSError):
                self._report_progress(f"⚠️ Instaloader: no hay sesión guardada de '{session_user}'. "
                                      f"Créala con: instaloader --login {session_user}")
        try:
            if shortcode:
                post = instaloader.Post.from_shortcode(loader.context, shortcode)
                return [SearchResult(
                    title=f"Publicación de Instagram de @{post.owner_username}",
                    url=f"https://www.instagram.com/p/{shortcode}",
                    snippet=sanitize_snippet(f"Fecha: {post.date_utc:%Y-%m-%d} · Me gusta: {post.likes} · "
                                             f"Ubicación: {getattr(post.location, 'name', '') or 'sin datos'} · "
                                             f"Texto: {(post.caption or '')[:300]}"),
                    source_tool=self.name, category="Social Media", relevance_score=85,
                    extra_data={"username": post.owner_username, "platform": "Instagram"},
                )]
            profile = instaloader.Profile.from_username(loader.context, username)
        except instaloader.exceptions.ProfileNotExistsException:
            self._report_progress(f"✅ Instaloader: la cuenta @{username} no existe.")
            return []
        except (instaloader.exceptions.LoginRequiredException, instaloader.exceptions.ConnectionException,
                instaloader.exceptions.QueryReturnedBadRequestException) as e:
            blocked = "429" in str(e) or "login" in str(e).lower() or isinstance(e, instaloader.exceptions.LoginRequiredException)
            self._report_progress(
                "⚠️ Instaloader: Instagram no permite consultas anónimas (HTTP 429). Inicia sesión una vez con "
                "`instaloader --login TU_USUARIO` (mejor una cuenta secundaria) y guarda ese usuario con "
                "`python -m osint_app.main --set-key Instagram`." if blocked and not session_user else
                f"⚠️ Instaloader: Instagram rechazó la consulta ({type(e).__name__}).")
            return []
        except Exception as e:
            self._report_progress(f"❌ Instaloader: error inesperado ({type(e).__name__}).")
            return []

        facts = [f"Nombre: {profile.full_name or 'sin nombre'}", f"Seguidores: {profile.followers}",
                 f"Siguiendo: {profile.followees}", f"Publicaciones: {profile.mediacount}"]
        if profile.is_verified:
            facts.append("Cuenta verificada")
        if profile.is_private:
            facts.append("Cuenta privada")
        if profile.business_category_name:
            facts.append(f"Categoría: {profile.business_category_name}")
        if profile.external_url:
            facts.append(f"Web: {profile.external_url}")
        if profile.biography:
            facts.append(f"Bio: {profile.biography[:300]}")
        return [SearchResult(
            title=f"Instagram: {profile.full_name or username} (@{profile.username})",
            url=f"https://www.instagram.com/{profile.username}",
            snippet=sanitize_snippet(" · ".join(facts)),
            source_tool=self.name, category="Social Media", relevance_score=90 if profile.is_verified else 80,
            extra_data={"name": profile.full_name, "username": profile.username, "platform": "Instagram",
                        "followers": profile.followers, "external_url": profile.external_url,
                        "verified": profile.is_verified},
        )]
