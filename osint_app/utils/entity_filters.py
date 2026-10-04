"""Filtros compartidos por los extractores de entidades (correlación y framework).

Los patrones regex por sí solos confunden marcas de tiempo con teléfonos y
nombres de archivo con dominios. Estos filtros descartan ese ruido.
"""
import ipaddress
import re
from functools import lru_cache
from pathlib import Path

TLD_FILE = Path(__file__).with_name("tlds.txt")   # lista oficial IANA (tlds-alpha-by-domain)

# Dominio: sin "..." final (texto recortado) ni letras/guiones pegados (p. ej. ".txt" cortado en ".tx");
# no empieza a mitad de palabra ni tras una "/" suelta (ruta de URL: /md5sum.py), sí tras "//" (http://dominio)
DOMAIN_PATTERN = r'(?<![\w.-])(?<!(?<!/)/)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w-]|\.\.)'

# Teléfono: con "+" admite códigos de área cortos (+593 2 299 3000); sin dígitos ni "/" pegados
PHONE_PATTERN = (r'(?<![\w/.])(?:\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}'
                 r'|(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4})(?![\w/])')

_IP_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
_DECIMAL_RE = re.compile(r'^-?\d+\.\d+$')           # 39.112579: coordenada, precio o versión, no teléfono
_TIMESTAMP_RE = re.compile(
    r'^(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:(?:[01]\d|2[0-3])[0-5]\d[0-5]\d)?$')

# Extensiones de archivo que ni siquiera son TLD (las que sí lo son las cubre la lista IANA)
FILE_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.js', '.html', '.htm',
    '.txt', '.pdf', '.xml', '.json', '.csv', '.log', '.map', '.woff', '.woff2', '.ttf',
    '.gz', '.tgz', '.tar', '.bz2', '.xz', '.rpm', '.deb', '.exe', '.dll', '.whl',
    '.docx', '.xlsx', '.pptx', '.ini', '.cfg', '.yml', '.yaml', '.php', '.asp', '.aspx', '.jsp',
)
# Hosts de infraestructura de las propias herramientas: no forman parte del objetivo
IGNORED_DOMAINS = {"web.archive.org", "rdap.org", "crt.sh", "openstreetmap.org"}

# Plataformas donde se ENCUENTRA a la gente: que aparezcan en un texto no las hace "dominio" de la persona
PLATFORM_DOMAINS = {
    "facebook.com", "instagram.com", "x.com", "twitter.com", "linkedin.com", "tiktok.com", "youtube.com", "youtu.be",
    "github.com", "gitlab.com", "wikipedia.org", "wikidata.org", "wikimedia.org", "threads.net", "threads.com",
    "reddit.com", "medium.com", "t.me", "telegram.org", "pinterest.com", "tumblr.com", "snapchat.com", "twitch.tv",
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com", "blogspot.com", "wordpress.com", "pscp.tv",
    "periscope.tv", "bsky.app", "mastodon.social", "scribd.com", "slideshare.net", "academia.edu", "grokipedia.com",
}


def is_platform_domain(value: str) -> bool:
    v = value.lower().rstrip(".")
    return any(v == d or v.endswith("." + d) for d in PLATFORM_DOMAINS)


@lru_cache(maxsize=1)
def _tlds() -> frozenset:
    try:
        lines = TLD_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return frozenset()
    return frozenset(l.strip().lower() for l in lines if l.strip() and not l.startswith("#"))


def has_known_tld(domain: str) -> bool:
    """True si la última etiqueta es una extensión registrada en IANA (o si no hay lista: no filtrar)."""
    tlds = _tlds()
    return not tlds or domain.rstrip(".").rsplit(".", 1)[-1].lower() in tlds


def is_noise_domain(value: str) -> bool:
    v = value.lower()
    ignored = any(v == d or v.endswith("." + d) for d in IGNORED_DOMAINS)
    return v.endswith(FILE_EXTENSIONS) or ignored or not has_known_tld(v)


def is_plausible_phone(value: str, default_region: str = "EC") -> bool:
    digits = re.sub(r'\D', '', value)
    if not 7 <= len(digits) <= 15:                # E.164: 15 dígitos como máximo
        return False
    if _TIMESTAMP_RE.match(digits):               # 20000815065837 = marca de tiempo (p. ej. Wayback)
        return False
    if _IP_RE.match(value.strip()) or _DECIMAL_RE.match(value.strip()):
        return False
    # Validación real del plan de numeración (librería phonenumbers, ya dependencia del proyecto). Antes bastaba
    # con tener 7–15 dígitos: en un caso real salían "100047132710726" (ID de Facebook) o "23000 120000".
    try:
        import phonenumbers
    except ImportError:
        return True
    try:
        number = phonenumbers.parse(value, None if value.strip().startswith("+") else default_region)
    except phonenumbers.NumberParseException:
        return False
    return phonenumbers.is_valid_number(number)


# Proveedores de correo gratuito: un correo @gmail.com no "pertenece" al dominio gmail.com de nadie
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.es", "outlook.com", "outlook.es", "live.com", "msn.com",
    "yahoo.com", "yahoo.es", "ymail.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com",
}
# Buzones de rol: los usan organizaciones, no una persona concreta
ROLE_ACCOUNTS = {
    "admin", "administrator", "info", "contact", "contacto", "support", "soporte", "sales", "ventas", "hello",
    "office", "mail", "email", "webmaster", "postmaster", "noreply", "no-reply", "root", "help", "ayuda",
    "billing", "abuse", "security", "marketing", "rrhh", "hr", "jobs", "careers", "news", "team", "service",
}
# "@algo" que es código (CSS, JavaScript, Java, Python, decoradores…) y no un usuario de red social
CODE_HANDLES = {
    "media", "import", "font-face", "fontface", "keyframes", "charset", "supports", "page", "namespace", "viewport",
    "tailwind", "apply", "layer", "container", "property", "override", "deprecated", "param", "return", "returns",
    "throws", "see", "since", "author", "version", "link", "example", "type", "typedef", "interface", "class",
    "ngmodule", "component", "injectable", "input", "output", "hostlistener", "viewchild", "dataclass", "staticmethod",
    "classmethod", "wraps", "abstractmethod", "pytest", "fixture", "test", "autowired", "entity", "table", "column",
    "getter", "setter", "service", "controller", "route", "app", "todo", "fixme", "private", "public", "protected",
    "implements", "extends", "default", "export", "mixin", "include", "extend", "function", "if", "else", "each",
}


def is_valid_email(value: str) -> bool:
    """El dominio del correo debe ser real: descarta logo@2x.png, sprite@3x.webp, etc."""
    if "@" not in value:
        return False
    return not is_noise_domain(value.rsplit("@", 1)[1])


def is_public_ip(value: str) -> bool:
    """IP válida y pública. Descarta 999.1.1.1 y las privadas, locales o reservadas (192.168.x.x, 127.x…)."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def is_code_handle(value: str) -> bool:
    return value.lstrip("@").lower() in CODE_HANDLES


def is_dns_txt_record(title: str) -> bool:
    """Registros TXT del DNS: guardan tokens de verificación de servicios (Twilio, Google…), no hashes de archivos."""
    return str(title or "").upper().startswith("DNS TXT")
