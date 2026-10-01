"""Señales de homónimo compartidas por los perfiladores.

Un homónimo es alguien con el mismo nombre que NO es el objetivo. Aquí solo se
detectan señales blandas (que se muestran como aviso); la decisión de aceptar o
descartar es siempre del investigador. Antes esta lógica estaba duplicada en
smart_profiler.py; ahora vive aquí y la usan los dos perfiladores.
"""
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from urllib.parse import urlsplit

from .geo_data import COUNTRY_ALIASES, COUNTRY_BY_CODE, LATAM_CITIES, LATAM_COUNTRIES, OTHER_CITIES
from .person_match import normalize_text

# Países/regiones latinoamericanos (mismo contexto que el objetivo típico).
LATAM = [
    "ecuador", "colombia", "perú", "peru", "chile", "argentina",
    "mexico", "méxico", "latam", "latinoamerica", "south america",
    "bolivia", "venezuela", "uruguay", "paraguay",
]

# Nombres de países ajenos (coincidencia por palabra completa, sin distinguir
# mayúsculas). No incluir siglas ambiguas aquí (ver COUNTRY_ABBREV).
OTHER_COUNTRIES = [
    "spain", "españa", "united states", "germany", "alemania", "france",
    "francia", "england", "china", "japan", "japón", "india", "canada",
    "canadá", "australia", "russia", "rusia", "italy", "italia", "portugal",
]

# Siglas ambiguas: "usa" es también el verbo español "usa"; "uk" aparece dentro
# de palabras. Solo se aceptan como país si están en MAYÚSCULAS y como palabra.
COUNTRY_ABBREV = ["USA", "UK"]


def _word_present(text_lower: str, term: str) -> bool:
    return re.search(rf"\b{re.escape(term)}\b", text_lower) is not None


def is_same_region(location: str, country: str) -> bool:
    """True si ubicación y país objetivo están ambos en Latinoamérica."""
    loc, ctry = (location or "").lower(), (country or "").lower()
    return any(_word_present(loc, c) for c in LATAM) and any(_word_present(ctry, c) for c in LATAM)


def different_country(location: str, expected_country: str) -> Optional[str]:
    """Devuelve el país ajeno mencionado en `location` (en minúsculas), o None.

    Coincidencia por palabra completa para evitar falsos positivos como
    'usa' dentro de 'usar' o 'india' dentro de 'Indiana'. Ignora el país
    esperado.
    """
    original = location or ""
    low = original.lower()
    exp = (expected_country or "").lower()
    for name in OTHER_COUNTRIES:
        if name not in exp and _word_present(low, name):
            return name
    for abbr in COUNTRY_ABBREV:
        # Sensible a mayúsculas sobre el texto original (país, no verbo).
        if abbr.lower() not in exp and re.search(rf"\b{re.escape(abbr)}\b", original):
            return abbr.lower()
    return None


def homonym_warning(text: str, seed_country: str) -> Optional[str]:
    """Aviso legible si `text` sugiere un país distinto al del objetivo, o None."""
    if not seed_country:
        return None
    other = different_country(text, seed_country)
    if other:
        return f"posible homónimo: menciona «{other}» pero el objetivo es de {seed_country}"
    return None


# ── Señales graduadas ────────────────────────────────────────────────────────
# homonym_warning (arriba) solo marca un país claramente ajeno. Estas señales añaden indicios más
# débiles, cada uno con su penalización. Nunca se descarta nada: solo se avisa y baja la puntuación.

STRONG_PENALTY = 30.0          # país ajeno a Latinoamérica
NEIGHBOR_PENALTY = 15.0        # otro país latinoamericano
CITY_LATAM_PENALTY = 15.0      # ciudad de otro país latinoamericano
CITY_OTHER_PENALTY = 25.0      # ciudad de fuera de Latinoamérica
LINKEDIN_PENALTY = 20.0        # perfil de LinkedIn de otro país (xx.linkedin.com)
TLD_PENALTY = 10.0             # sitio con extensión de otro país
OTHER_CITY_PENALTY = 8.0       # otra ciudad del mismo país que el contexto del objetivo
MAX_PENALTY = 40.0
_GLOBAL_SHORT_HOSTS = {"t.co", "youtu.be", "bit.ly", "goo.gl"}      # su extensión no indica un país
_LATAM_CODES = set(LATAM_COUNTRIES.values())


@dataclass(frozen=True)
class Signal:
    code: str
    message: str
    penalty: float


def _phrase_in(norm_text: str, phrase: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", norm_text) is not None


def country_code(country: str) -> str:
    """Código de país ('ec') a partir de texto libre ('Ecuador', 'ecuador, quito'); '' si no se reconoce."""
    norm = normalize_text(country)
    for name, code in LATAM_COUNTRIES.items():
        if _phrase_in(norm, name):
            return code
    for alias, code in COUNTRY_ALIASES.items():
        if _phrase_in(norm, alias):
            return code
    return ""


def _countries_in(norm_text: str) -> Set[str]:
    found = {code for name, code in LATAM_COUNTRIES.items() if _phrase_in(norm_text, name)}
    found |= {code for alias, code in COUNTRY_ALIASES.items() if _phrase_in(norm_text, alias)}
    return found


def _cities_in(text: str) -> Dict[str, Set[str]]:
    """Ciudades del texto, solo si aparecen con mayúscula inicial ('Quito', no 'quito').

    Muchas coinciden con apellidos o palabras comunes (Lima, Manta, Puebla, Cali): la mayúscula
    descarta el uso como palabra común, y la lista ya excluye los apellidos más frecuentes.
    """
    plain = "".join(c for c in unicodedata.normalize("NFKD", text or "") if not unicodedata.combining(c))
    plain = re.sub(r"[^A-Za-z0-9]+", " ", plain)
    found: Dict[str, Set[str]] = {}
    for table in (LATAM_CITIES, OTHER_CITIES):
        for code, cities in table.items():
            for city in cities:
                pattern = r"(?<![A-Za-z0-9])" + r"\s+".join(re.escape(w) for w in city.split()) + r"(?![A-Za-z0-9])"
                if any(m.group(0)[:1].isupper() for m in re.finditer(pattern, plain, re.I)):
                    found.setdefault(code, set()).add(city)
    return found


def _url_signals(url: str, target: str) -> List[Signal]:
    try:
        host = (urlsplit(url if "://" in (url or "") else "https://" + (url or "")).hostname or "").lower()
    except ValueError:
        return []
    if not host or host in _GLOBAL_SHORT_HOSTS:
        return []
    match = re.match(r"^([a-z]{2})\.linkedin\.com$", host)
    if match:
        code = match.group(1)
        if code in COUNTRY_BY_CODE and code != target:
            return [Signal("linkedin_country", f"posible homónimo (señal débil): perfil de LinkedIn de {COUNTRY_BY_CODE[code]}", LINKEDIN_PENALTY)]
        return []
    tld = host.rsplit(".", 1)[-1]
    if len(tld) == 2 and tld in COUNTRY_BY_CODE and tld != target:
        return [Signal("tld", f"posible homónimo (señal débil): sitio de {COUNTRY_BY_CODE[tld]} (.{tld})", TLD_PENALTY)]
    return []


def homonym_signals(text: str, url: str, seed_country: str, seed_context: str = "") -> List[Signal]:
    """Indicios de que un resultado habla de otra persona con el mismo nombre. Lista vacía = ninguno.

    Las señales débiles necesitan reconocer el país del objetivo; si el texto menciona el país del
    objetivo o una de sus ciudades, se considera ligado a él y no se aplican.
    """
    signals: List[Signal] = []
    strong = homonym_warning(text, seed_country)
    if strong:
        signals.append(Signal("country", strong, STRONG_PENALTY))
    target = country_code(seed_country)
    if not target:
        return signals

    norm = normalize_text(text)
    countries = _countries_in(norm)
    cities = _cities_in(text)
    own = cities.get(target, set())
    tied_to_target = target in countries or bool(own)

    if not tied_to_target and not strong:        # con un país ajeno ya detectado, la ciudad es la misma evidencia
        flagged: Set[str] = set()
        for code in sorted(c for c in countries if c in _LATAM_CODES and c != target):
            name = COUNTRY_BY_CODE[code]
            signals.append(Signal("neighbor_country", f"posible homónimo (señal débil): menciona {name}; el objetivo es de {seed_country}", NEIGHBOR_PENALTY))
            flagged.add(code)
            break
        for code in sorted(cities):
            if code == target or code in flagged:
                continue
            city = sorted(cities[code])[0]
            penalty = CITY_LATAM_PENALTY if code in _LATAM_CODES else CITY_OTHER_PENALTY
            signals.append(Signal("foreign_city", f"posible homónimo (señal débil): menciona {city} ({COUNTRY_BY_CODE.get(code, code)}); el objetivo es de {seed_country}", penalty))
            break
    elif seed_context:
        ctx_cities = _cities_in(seed_context).get(target, set())
        if ctx_cities and own and not (own & ctx_cities):
            signals.append(Signal("other_city", f"posible homónimo (señal débil): menciona {sorted(own)[0]}; el contexto del objetivo dice {sorted(ctx_cities)[0]}", OTHER_CITY_PENALTY))

    signals.extend(_url_signals(url, target))
    return signals


def total_penalty(signals: List[Signal]) -> float:
    return min(MAX_PENALTY, sum(s.penalty for s in signals))


def warning_text(signals: List[Signal]) -> str:
    return "; ".join(s.message for s in signals)
