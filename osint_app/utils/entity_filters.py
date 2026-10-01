"""Filtros compartidos por los extractores de entidades (correlación y framework).

Los patrones regex por sí solos confunden marcas de tiempo con teléfonos y
nombres de archivo con dominios. Estos filtros descartan ese ruido.
"""
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
IGNORED_DOMAINS = {"web.archive.org", "rdap.org", "crt.sh"}


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
    return v.endswith(FILE_EXTENSIONS) or v in IGNORED_DOMAINS or not has_known_tld(v)


def is_plausible_phone(value: str) -> bool:
    digits = re.sub(r'\D', '', value)
    if not 7 <= len(digits) <= 15:                # E.164: 15 dígitos como máximo
        return False
    if _TIMESTAMP_RE.match(digits):               # 20000815065837 = marca de tiempo (p. ej. Wayback)
        return False
    return not _IP_RE.match(value.strip())


def is_dns_txt_record(title: str) -> bool:
    """Registros TXT del DNS: guardan tokens de verificación de servicios (Twilio, Google…), no hashes de archivos."""
    return str(title or "").upper().startswith("DNS TXT")
