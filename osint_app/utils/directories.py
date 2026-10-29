"""Resultados que son LISTADOS de personas y no una persona (directorios y buscadores de personas).

"600+ 'Carlos Andrade' profiles | LinkedIn" o linkedin.com/pub/dir/Carlos/Andrade agrupan a todos los que
se llaman igual: no son un candidato, son ruido que además puntúa alto porque contiene el nombre buscado.
Se dejan fuera de la lista de candidatos, pero siguen guardados en los reportes de la herramienta.
"""
import re
from urllib.parse import urlsplit

# Buscadores de personas y agregadores: perfiles automáticos sin valor propio
PEOPLE_SEARCH_DOMAINS = {
    "spokeo.com", "whitepages.com", "beenverified.com", "radaris.com", "truepeoplesearch.com", "fastpeoplesearch.com",
    "peekyou.com", "zabasearch.com", "intelius.com", "mylife.com", "ussearch.com", "411.com", "peoplefinders.com",
}

# Títulos de listado: '600+ "Carlos Andrade" profiles' (nombre entre comillas), '400+ profiles' (con +),
# '1.200 perfiles de Carlos Andrade', '50 people named Juan Perez'. Un título como
# '3 profiles of the Open Source community' NO es un listado de personas.
_COUNT_QUOTED = re.compile(r"^\s*\d[\d.,]*\+?\s+[\"“«'].{1,80}?[\"”»']\s+(?:profiles?|perfiles|people|personas)\b", re.I)
_COUNT_PLUS = re.compile(r"^\s*\d[\d.,]*\+\s+(?:profiles?|perfiles|people|personas)\b", re.I)
_LISTING_TITLE = re.compile(
    r"^\s*(?:\d[\d.,]*\+?\s+)?(?:perfiles de|profiles for|profiles named|people named|personas llamadas)\b", re.I)


# Directorios oficiales (notarías, funcionarios, servidores): listan a cualquiera que se llame igual con su teléfono y
# su correo. Evaluación 4: un PDF de funcionjudicial.gob.ec con el notario "Jefferson Pérez Quezada" de Cuenca salía al
# 60 % en el perfil del atleta. "Directorio" a secas no basta: en Ecuador también es la junta directiva de una
# federación, que sí puede citar a la persona.
_OFFICIAL_LISTING = re.compile(
    r"directorio[\s_+-]*(?:notarial|de[\s_+-]+notar|telef|de[\s_+-]+(?:funcionarios|servidores|autoridades|personal|"
    r"empleados|docentes|jueces)|institucional)"
    r"|\b(?:n[oó]mina|listado|distributivo)\s+de\s+(?:funcionarios|servidores|personal|empleados|notarios|docentes|"
    r"jueces)\b"
    r"|\bnotar[ií]as?\b.{0,80}\bnotario", re.I)
# Título hecho de cabeceras de tabla: "PROVINCIA CANTÓN NOTARÍA NOTARIO (A) DIRECCIÓN TELÉFONO E-MAIL"
_TABLE_HEADER_TITLE = re.compile(r"\btel[eé]fonos?\b.{0,40}\b(?:e-?mail|correo)", re.I)


def is_directory_result(title: str, url: str, snippet: str = "") -> str:
    """Motivo (texto corto) si el resultado es un listado de personas; '' si puede ser una persona."""
    try:
        parts = urlsplit(url or "")
        host = (parts.hostname or "").lower()
    except ValueError:
        host, parts = "", urlsplit("")
    path = (parts.path or "").lower()

    if (host == "linkedin.com" or host.endswith(".linkedin.com")) and (path.startswith("/pub/dir/") or path.startswith("/directory/")):
        return "directorio de LinkedIn"
    if (host == "facebook.com" or host.endswith(".facebook.com")) and path.startswith("/public/"):
        return "directorio de Facebook"
    for domain in PEOPLE_SEARCH_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return "buscador de personas"
    text = title or ""
    if _COUNT_QUOTED.search(text) or _COUNT_PLUS.search(text) or _LISTING_TITLE.search(text):
        return "listado de perfiles"
    if _OFFICIAL_LISTING.search(f"{text} {snippet or ''} {path}") or _TABLE_HEADER_TITLE.search(text):
        return "directorio oficial de funcionarios"
    return ""
