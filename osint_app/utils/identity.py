"""Identidad de personas: perfiles sociales, nombres y su relación con usuarios y correos.

Sin IA ni listas de nombres: se apoya en la estructura de las URLs de cada plataforma, en
los títulos de sus páginas de perfil y en cómo la gente arma sus usuarios y correos
(jriofrio, juan.riofrio, riofrio.juan…).
"""
import re
from typing import Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

from .person_match import name_tokens, normalize_text

# Primeros segmentos que NO son un usuario en cada plataforma
_GITHUB_RESERVED = {
    "search", "orgs", "topics", "about", "login", "settings", "explore", "users", "sponsors", "marketplace",
    "collections", "trending", "features", "pricing", "notifications", "new", "pulls", "issues", "apps", "enterprise",
    "customer-stories", "readme", "security", "site", "contact", "join", "signup", "organizations", "codespaces",
}
_X_RESERVED = {"search", "explore", "i", "home", "hashtag", "share", "intent", "settings", "login", "signup", "tos", "privacy", "messages", "notifications", "compose"}
_FACEBOOK_RESERVED = {
    "sharer", "sharer.php", "share.php", "share", "groups", "pages", "watch", "events", "marketplace", "login", "login.php",
    "people", "photo", "photos", "permalink.php", "story.php", "hashtag", "dialog", "plugins", "policies", "help", "gaming",
    "reel", "reels", "stories", "videos", "public", "profile.php",
}
_INSTAGRAM_RESERVED = {"p", "reel", "reels", "explore", "accounts", "stories", "tv", "direct", "about", "legal", "web", "challenge"}
_TELEGRAM_RESERVED = {"s", "joinchat", "share", "addstickers", "c", "iv", "proxy", "login", "setlanguage"}

# Textos que aparecen en títulos de página y no son nombres de persona
_NOT_NAMES = {
    "linkedin", "github", "twitter", "facebook", "instagram", "tiktok", "youtube", "reddit", "medium", "telegram",
    "perfil", "profile", "official", "oficial", "page", "pagina", "inicio", "home", "login", "sign", "log", "in",
    "mas", "more", "photos", "videos", "log", "watch", "sin", "titulo", "untitled", "null", "none", "unknown",
    # textos de interfaz que aparecen como título de páginas de acceso o de error
    "iniciar", "sesion", "entrar", "acceder", "ingresar", "registrarse", "registrate", "crear", "cuenta", "account",
    "recuperar", "contrasena", "password", "olvidaste", "ayuda", "help", "error", "found", "noticias", "news",
    "welcome", "bienvenido", "bienvenida", "search", "buscar", "resultados", "results", "inicio", "menu",
}
# "Replies by Linus Torvalds", "Publicaciones de María Pérez": páginas ligadas a un perfil, no el perfil
_PAGE_PREFIX = re.compile(
    r"^\s*(?:replies|posts|tweets|photos|videos|likes|media|followers|following|highlights|reels|"
    r"publicaciones|respuestas|fotos|videos|seguidores)\s+(?:by|of|from|de|por)\s+", re.I)
_TITLE_DELIMITERS = (" - ", " – ", " — ", " | ", " • ", " / ", " (@", " on ", " en ", ": ")

_URL_IN_TEXT = re.compile(
    r"(?<![\w.-])(?:https?://)?(?:[a-z0-9-]+\.)*(?:linkedin\.com|github\.com|twitter\.com|x\.com|facebook\.com|"
    r"instagram\.com|tiktok\.com|youtube\.com|t\.me|reddit\.com|medium\.com)/[^\s\"'<>)\]},;]+", re.I)


def _segments(path: str):
    return [unquote(s) for s in path.split("/") if s]


# Segmentos que convierten una URL de perfil en una PUBLICACIÓN de esa cuenta (x.com/radio/status/1…)
_CONTENT_SEGMENTS = {"status", "statuses", "video", "videos", "photo", "photos", "posts", "post", "p", "reel", "reels",
                     "story", "stories", "watch", "shorts", "live", "comments", "permalink.php", "media", "tv", "events"}


def is_content_url(url: str) -> bool:
    """True si la URL es una publicación (tuit, vídeo, post), no la página del perfil.

    El autor de una publicación que menciona a la persona suele ser OTRA cuenta (en la prueba real con Jorge Ulloa:
    el vídeo de "radiocentro.ec"), así que no sirve para encadenar ni cuenta como su perfil.
    """
    try:
        parts = urlsplit(url if re.match(r"^[a-z][a-z0-9+.-]*://", url or "", re.I) else "https://" + (url or ""))
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if host.endswith("youtube.com") and parts.path.rstrip("/") == "/watch":
        return True
    # github.com/<dueño>/<repositorio>: un repositorio (de quien sea) no es la página de un perfil. Prueba real:
    # "github.com/francogenre/midudev" (repo de otra persona sobre midudev) encadenaba a "francogenre"
    if host in ("github.com", "www.github.com") and len(_segments(parts.path)) >= 2:
        return True
    return any(seg.lower() in _CONTENT_SEGMENTS for seg in _segments(parts.path) if not seg.startswith("@"))


def parse_profile_url(url: str) -> Optional[Tuple[str, str, str]]:
    """(plataforma, usuario en minúsculas, URL canónica) de un enlace a un perfil, o None.

    twitter.com y x.com dan la misma URL canónica; mayúsculas, www, barra final y parámetros no importan.
    """
    raw = (url or "").strip()
    if not raw:
        return None
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        query = parse_qs(parts.query)
    except ValueError:
        return None
    if not host:
        return None
    segs = _segments(parts.path)

    def on(domain: str) -> bool:
        return host == domain or host.endswith("." + domain)

    handle, platform, base = "", "", ""
    if on("linkedin.com") and len(segs) >= 2 and segs[0].lower() == "in":
        platform, handle, base = "linkedin", segs[1], "linkedin.com/in"
    elif host in ("github.com", "www.github.com") and segs:
        user = segs[0]
        if user.lower() not in _GITHUB_RESERVED and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", user):
            platform, handle, base = "github", user, "github.com"
    elif (on("twitter.com") or on("x.com")) and segs:
        user = segs[0]
        if user.lower() not in _X_RESERVED and re.fullmatch(r"[A-Za-z0-9_]{1,15}", user):
            platform, handle, base = "x", user, "x.com"
    elif on("facebook.com") and segs:
        if segs[0].lower() == "profile.php" and query.get("id"):
            platform, handle, base = "facebook", "id" + query["id"][0], "facebook.com"
        elif segs[0].lower() not in _FACEBOOK_RESERVED and re.fullmatch(r"[A-Za-z0-9.]{5,50}", segs[0]):
            platform, handle, base = "facebook", segs[0], "facebook.com"
    elif on("instagram.com") and segs:
        if segs[0].lower() not in _INSTAGRAM_RESERVED and re.fullmatch(r"[A-Za-z0-9._]{1,30}", segs[0]):
            platform, handle, base = "instagram", segs[0], "instagram.com"
    elif on("tiktok.com") and segs and segs[0].startswith("@") and len(segs[0]) > 1:
        platform, handle, base = "tiktok", segs[0][1:], "tiktok.com/@"
    elif on("youtube.com") and segs:
        if segs[0].startswith("@") and len(segs[0]) > 1:
            platform, handle, base = "youtube", segs[0][1:], "youtube.com/@"
        elif segs[0].lower() in ("channel", "user", "c") and len(segs) > 1:
            platform, handle, base = "youtube", f"{segs[0].lower()}/{segs[1]}", "youtube.com"
    elif host == "t.me" and segs and segs[0].lower() not in _TELEGRAM_RESERVED and not segs[0].startswith("+"):
        if re.fullmatch(r"[A-Za-z0-9_]{5,32}", segs[0]):
            platform, handle, base = "telegram", segs[0], "t.me"
    elif on("reddit.com") and len(segs) >= 2 and segs[0].lower() in ("user", "u"):
        platform, handle, base = "reddit", segs[1], "reddit.com/user"
    elif on("medium.com") and segs and segs[0].startswith("@") and len(segs[0]) > 1:
        platform, handle, base = "medium", segs[0][1:], "medium.com/@"

    if not platform:
        return None
    handle = handle.lower()
    joiner = "" if base.endswith("@") else "/"
    return platform, handle, f"https://{base}{joiner}{handle}"


def find_profile_urls(text: str):
    """Perfiles sociales mencionados en un texto: lista de (plataforma, usuario, URL canónica), sin repetir."""
    found, seen = [], set()
    for match in _URL_IN_TEXT.finditer(text or ""):
        parsed = parse_profile_url(match.group(0).rstrip(".,"))
        if parsed and parsed[2] not in seen:
            seen.add(parsed[2])
            found.append(parsed)
    return found


def profile_key(url: str) -> str:
    """Clave de comparación de un perfil: 'github.com/jperez' (sin esquema ni mayúsculas ni barra final)."""
    parsed = parse_profile_url(url)
    canonical = parsed[2] if parsed else (url or "")
    return re.sub(r"^https?://", "", canonical.strip().lower()).rstrip("/")


# ── Nombres ──────────────────────────────────────────────────────────────────

def looks_like_person_name(text: str) -> bool:
    """2 a 5 palabras de letras, sin números ni palabras de plataforma ('LinkedIn', 'Perfil'…)."""
    tokens = (text or "").split()
    if not 2 <= len(tokens) <= 5:
        return False
    for tok in tokens:
        if not re.fullmatch(r"[^\W\d_][^\W\d_'’.\-]*(?:['’.\-][^\W\d_]+)*\.?", tok):
            return False
    if any(normalize_text(t) in _NOT_NAMES for t in tokens):
        return False
    return sum(1 for t in tokens if len(normalize_text(t)) >= 2) >= 2


def name_from_profile_title(title: str, platform: str = "", handle: str = "") -> str:
    """Nombre de la persona a partir del título de su página de perfil, o ''.

    'Juan Pérez - Ingeniero - UTPL | LinkedIn', 'Dan Abramov (@dan) / X', 'GitHub: Linus Torvalds'.
    En GitHub el nombre solo se acepta del campo estructurado del perfil (los títulos de sus resultados
    los genera la herramienta: "Lenguajes principales de x"). Un título que contiene el propio usuario
    como palabra suelta tampoco es un nombre.
    """
    if platform == "github":
        return ""
    text = re.sub(r"^\s*(GitHub|LinkedIn|Twitter|Facebook|Instagram)\s*:\s*", "", (title or "").strip(), flags=re.I)
    text = _PAGE_PREFIX.sub("", text)
    cut = min((text.find(d) for d in _TITLE_DELIMITERS if d in text), default=-1)
    candidate = (text if cut < 0 else text[:cut]).strip(" \"'")
    if handle and handle.lower() in normalize_text(candidate).split():
        return ""
    return candidate if looks_like_person_name(candidate) else ""


def handle_matches_name(handle: str, name: str) -> bool:
    """¿El usuario o la parte local de un correo es una forma típica del nombre? (jriofrio ~ Juan Riofrio)."""
    h = normalize_text((handle or "").lstrip("@").split("+")[0]).replace(" ", "")
    toks = name_tokens(name)
    if not h or len(toks) < 2:
        return False
    first, last = toks[0], toks[-1]
    lasts = [last] + ([toks[-2]] if len(toks) >= 4 else [])
    candidates = set()
    for l in lasts:
        candidates |= {first + l, l + first, first[0] + l, l + first[0]}
    if len(last) >= 6:
        candidates.add(last)
    if len(first) >= 6:
        candidates.add(first)
    # Un año o número al final no cambia de quién es el usuario: jriofrio99, juan.riofrio2006 (rescatado de smart_profiler)
    without_digits = re.sub(r"\d{1,4}$", "", h)
    return h in candidates or (bool(without_digits) and without_digits in candidates)
