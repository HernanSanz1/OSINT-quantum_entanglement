"""Datos geográficos para las señales de homónimo: países de Latinoamérica y ciudades sin ambigüedad.

Solo ciudades que no se confunden con apellidos, nombres propios, palabras comunes ni con ciudades de
otro país. Se excluyen a propósito, entre otras: Mendoza, Rosario, Salta, Zamora, Ibarra, Quevedo, Durán,
Salinas, Pereira, Trujillo, Villavicencio, Veracruz, Hermosillo, Concepción, Orlando, Roma, París, Sevilla,
Granada, Porto (apellidos o nombres) y Valencia, Córdoba, León, Mérida, Santiago, Sucre, La Paz, Cuenca,
Guadalajara, Barcelona (existen en más de un país). Los nombres van sin tildes y en minúsculas; en el texto
solo cuentan si aparecen con mayúscula inicial.
"""
from typing import Dict, Set

# código de país (también subdominio de LinkedIn y extensión .xx) → nombre en minúsculas sin tildes
COUNTRY_BY_CODE: Dict[str, str] = {
    "ec": "ecuador", "co": "colombia", "pe": "peru", "mx": "mexico", "cl": "chile", "ar": "argentina",
    "bo": "bolivia", "ve": "venezuela", "uy": "uruguay", "py": "paraguay", "es": "espana", "br": "brasil",
    "us": "estados unidos", "uk": "reino unido", "de": "alemania", "fr": "francia", "it": "italia",
    "pt": "portugal", "ca": "canada", "au": "australia", "in": "india", "cn": "china", "jp": "japon", "ru": "rusia",
}

# países latinoamericanos hispanohablantes: nombre normalizado → código
LATAM_COUNTRIES: Dict[str, str] = {
    "ecuador": "ec", "colombia": "co", "peru": "pe", "mexico": "mx", "chile": "cl", "argentina": "ar",
    "bolivia": "bo", "venezuela": "ve", "uruguay": "uy", "paraguay": "py",
}

# nombres alternativos de un país → su código
COUNTRY_ALIASES: Dict[str, str] = {
    "espana": "es", "spain": "es", "estados unidos": "us", "united states": "us", "usa": "us",
    "brasil": "br", "brazil": "br",
}

LATAM_CITIES: Dict[str, Set[str]] = {
    "ec": {"quito", "guayaquil", "loja", "ambato", "manta", "portoviejo", "machala", "esmeraldas", "riobamba",
           "latacunga", "tulcan", "azogues", "puyo", "macas", "samborondon", "daule", "otavalo", "montecristi",
           "cayambe", "sangolqui", "cotacachi"},
    "co": {"bogota", "medellin", "cali", "barranquilla", "cartagena", "bucaramanga", "manizales", "cucuta",
           "ibague", "villavicencio de los llanos", "santa marta", "monteria", "neiva", "popayan", "tunja", "envigado"},
    "pe": {"lima", "arequipa", "chiclayo", "piura", "cusco", "cuzco", "iquitos", "huancayo", "tacna",
           "callao", "chimbote", "cajamarca", "ayacucho", "pucallpa"},
    "mx": {"ciudad de mexico", "cdmx", "monterrey", "puebla", "tijuana", "cancun", "queretaro",
           "chihuahua", "toluca", "culiacan", "aguascalientes", "oaxaca", "tlaquepaque"},
    "cl": {"valparaiso", "antofagasta", "vina del mar", "temuco", "rancagua", "iquique", "puerto montt"},
    "ar": {"buenos aires", "mar del plata", "la plata", "tucuman", "bariloche"},
    "bo": {"cochabamba", "el alto", "oruro", "tarija", "potosi"},
    "ve": {"caracas", "maracaibo", "barquisimeto", "maracay", "ciudad guayana"},
    "uy": {"montevideo", "punta del este", "paysandu"},
    "py": {"asuncion", "ciudad del este"},
}

# ciudades de fuera de Latinoamérica (señal más fuerte para un objetivo latinoamericano)
OTHER_CITIES: Dict[str, Set[str]] = {
    "es": {"madrid", "bilbao", "malaga", "zaragoza", "alicante"},
    "us": {"miami", "new york", "nueva york", "los angeles", "houston", "chicago", "san francisco", "seattle", "boston",
           "washington dc", "las vegas", "dallas", "atlanta", "san diego"},
    "uk": {"london", "londres", "manchester", "liverpool", "birmingham"},
    "de": {"berlin", "munich", "frankfurt", "hamburg"},
    "fr": {"lyon", "marseille"},
    "it": {"milan", "milano", "napoli"},
    "ca": {"toronto", "vancouver", "montreal"},
    "au": {"sydney", "melbourne"},
    "in": {"bangalore", "mumbai", "delhi", "hyderabad"},
    "pt": {"lisboa", "lisbon"},
}
