"""Señales de homónimo compartidas por los perfiladores.

Un homónimo es alguien con el mismo nombre que NO es el objetivo. Aquí solo se
detectan señales blandas (que se muestran como aviso); la decisión de aceptar o
descartar es siempre del investigador. Antes esta lógica estaba duplicada en
smart_profiler.py; ahora vive aquí y la usan los dos perfiladores.
"""
import re
from typing import Optional

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
