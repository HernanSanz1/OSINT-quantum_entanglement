"""Señales de homónimo compartidas por los perfiladores.

Un homónimo es alguien con el mismo nombre que NO es el objetivo. Aquí solo se
detectan señales blandas (que se muestran como aviso); la decisión de aceptar o
descartar es siempre del investigador. Antes esta lógica estaba duplicada en
smart_profiler.py; ahora vive aquí y la usan los dos perfiladores.
"""
from typing import Optional

# Países/regiones latinoamericanos (mismo contexto que el objetivo típico).
LATAM = [
    "ecuador", "colombia", "perú", "peru", "chile", "argentina",
    "mexico", "méxico", "latam", "latinoamerica", "south america",
]

# Países claramente ajenos: si aparecen y el objetivo es de otro sitio, es señal.
OTHER_COUNTRIES = [
    "spain", "españa", "usa", "united states", "germany", "alemania",
    "france", "francia", "uk", "england", "china", "japan", "india",
    "canada", "australia",
]


def is_same_region(location: str, country: str) -> bool:
    """True si ubicación y país objetivo están ambos en Latinoamérica."""
    location, country = (location or "").lower(), (country or "").lower()
    return any(c in location for c in LATAM) and any(c in country for c in LATAM)


def different_country(location: str, expected_country: str) -> Optional[str]:
    """Devuelve el país ajeno mencionado en `location`, o None.

    Ignora el caso en que el país mencionado ES el esperado.
    """
    location, expected_country = (location or "").lower(), (expected_country or "").lower()
    for other in OTHER_COUNTRIES:
        if other in location and other not in expected_country:
            return other
    return None


def homonym_warning(text: str, seed_country: str) -> Optional[str]:
    """Aviso legible si `text` sugiere un país distinto al del objetivo, o None."""
    if not seed_country:
        return None
    other = different_country(text, seed_country)
    if other:
        return f"posible homónimo: menciona «{other}» pero el objetivo es de {seed_country}"
    return None
