"""Comparación de nombres, teléfonos, usuarios y URLs para puntuar candidatos.

Pensado para nombres hispanos: no depende de tildes ni de mayúsculas, ni del orden
"Nombre Apellido" / "Apellido Nombre", ni de que aparezcan los dos apellidos.
"""
import re
import unicodedata
from typing import List, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit

NAME_STOPWORDS = {"del", "las", "los", "van", "von", "dos", "das", "mac", "san"}
TRACKING_PARAMS = {"fbclid", "gclid", "trk", "ref", "si", "igshid", "mc_cid", "mc_eid", "feature", "source"}


def normalize_text(text: str) -> str:
    """Minúsculas, sin tildes y con todo lo que no sea letra o número convertido en espacio."""
    decomposed = unicodedata.normalize("NFKD", str(text or ""))
    plain = "".join(c for c in decomposed if not unicodedata.combining(c)).lower()
    return re.sub(r"[^a-z0-9]+", " ", plain).strip()


def name_tokens(name: str) -> List[str]:
    return [t for t in normalize_text(name).split() if len(t) > 2 and t not in NAME_STOPWORDS]


def name_match(name: str, text: str) -> Tuple[float, str]:
    """(puntos, tipo) de cuánto aparece `name` en `text`, por palabras completas.

    40 'name': están todas las palabras del nombre (en cualquier orden y sin tildes).
    25 'name_partial': el nombre de pila (o el segundo nombre) MÁS al menos un apellido.
    12 sin tipo: solo apellidos o solo nombres de pila. Una sola palabra: 10 si es un apellido, 5 si es un nombre.

    Antes "dos palabras cualesquiera" ya era 'name_partial': "Carlos Pérez Quezada" puntuaba como
    "Jefferson Pérez Quezada" por compartir los dos apellidos (homónimos muy frecuentes en Ecuador).
    """
    tokens = name_tokens(name)
    if not tokens:
        return 0.0, ""
    words = set(normalize_text(text).split())
    hits = sum(1 for t in tokens if t in words)
    if hits == len(tokens) and hits >= 2:
        return 40.0, "name"
    if hits >= 2:
        given, surnames = _split_given_and_surnames(tokens)
        if any(t in words for t in given) and any(t in words for t in surnames):
            return 25.0, "name_partial"
        return 12.0, ""
    if hits == 1:
        # Coincidir solo en el apellido dice más que coincidir solo en el nombre de pila o en el segundo nombre
        # (en nombres de 4 palabras, los apellidos son las dos últimas). Rescatado de smart_profiler.
        surnames = {tokens[-1]} | ({tokens[-2]} if len(tokens) >= 4 else set())
        only_hit = next(t for t in tokens if t in words)
        return (10.0 if only_hit in surnames else 5.0), ""
    return 0.0, ""


def _split_given_and_surnames(tokens: List[str]) -> Tuple[List[str], List[str]]:
    """Nombres de pila y apellidos de un nombre ya tokenizado (convención hispana).

    2 palabras: N A · 3: N N A o N A A, ambiguo, así que solo cuenta como nombre de pila la PRIMERA (si no,
    "Noboa Azín Álvaro" —el padre— pasaba por "Daniel Noboa Azín") · 4 o más: N N A A.
    """
    if len(tokens) <= 3:
        return tokens[:1], tokens[1:]
    return tokens[:-2], tokens[-2:]


def phone_key(phone: str) -> str:
    """Últimos 9 dígitos (o todos si hay menos): igual con o sin prefijo de país o 0 inicial."""
    digits = re.sub(r"\D", "", phone or "")
    return digits[-9:] if len(digits) >= 7 else ""


def phone_in_text(phone: str, text: str) -> bool:
    """True si algún número del texto termina igual que `phone`, sin importar el formato."""
    key = phone_key(phone)
    if not key:
        return False
    for run in re.findall(r"\+?\d[\d\s().-]{5,}\d", text or ""):
        digits = re.sub(r"\D", "", run)
        if len(digits) >= len(key) and digits.endswith(key):
            return True
    return False


def username_in_text(username: str, text: str) -> bool:
    """El usuario como palabra completa (no 'ana' dentro de 'banana')."""
    user = (username or "").lstrip("@").lower()
    if not user:
        return False
    return re.search(rf"(?<![a-z0-9]){re.escape(user)}(?![a-z0-9])", (text or "").lower()) is not None


def normalize_url(url: str) -> str:
    """Clave para detectar la misma página escrita de formas distintas (http/https, www, barra final, rastreo)."""
    try:
        parts = urlsplit((url or "").strip())
    except ValueError:
        return (url or "").strip()
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    query = urlencode(sorted((k, v) for k, v in parse_qsl(parts.query)
                             if not k.lower().startswith("utm_") and k.lower() not in TRACKING_PARAMS))
    path = parts.path.rstrip("/")
    return f"{host}{path}" + (f"?{query}" if query else "")
