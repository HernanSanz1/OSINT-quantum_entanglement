"""Tipos de dato de un caso: detección automática y validación con mensajes claros.

Prueba real de usuario final (2026-10-13): "hola mundo" se guardaba como IP sin aviso y luego IP Reputation daba
"0 resultados" sin explicar por qué; una URL quedaba guardada como dominio y Link Shield se negaba a analizarla.
"""
import re
from typing import Optional

from .sanitizer import validate_domain, validate_ip

# (tipo guardado en la base de datos, texto en pantalla)
DATA_TYPES = [
    ("DOMAIN", "Dominio"), ("IP", "IP"), ("EMAIL", "Correo"), ("USERNAME", "Usuario"), ("PHONE", "Teléfono"),
    ("NAME", "Nombre"), ("URL", "URL"), ("COMPANY", "Empresa"), ("UNIVERSITY", "Universidad"), ("OTHER", "Otro"),
]
# Tipos que guarda el Perfilamiento y no se eligen a mano
_OTHER_LABELS = {"CONTEXT": "Contexto", "COUNTRY": "País", "LOCATION": "Ubicación", "NOTE": "Nota",
                 "OBSERVABLE": "Observable", "HASH": "Hash"}
TYPE_LABELS = {**{code: label for code, label in DATA_TYPES}, **_OTHER_LABELS}

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,20}$")


def detect_type(value: str) -> Optional[str]:
    """Tipo evidente por la forma del dato (URL, correo, IP, teléfono, dominio), o None si no está claro."""
    v = (value or "").strip()
    if re.match(r"^https?://", v, re.I):
        return "URL"
    if _EMAIL_RE.match(v):
        return "EMAIL"
    if validate_ip(v):
        return "IP"
    if _PHONE_RE.match(v) and sum(c.isdigit() for c in v) >= 7:
        return "PHONE"
    if validate_domain(v):
        return "DOMAIN"
    return None


def validation_error(field_type: str, value: str) -> str:
    """Mensaje para el usuario si el dato no encaja con su tipo; "" si es válido."""
    v = (value or "").strip()
    t = (field_type or "").upper()
    if not v:
        return "Escribe un valor."
    if t == "IP" and not validate_ip(v):
        return f"«{v}» no parece una dirección IP (ejemplo: 8.8.8.8)."
    if t == "EMAIL" and not _EMAIL_RE.match(v):
        return f"«{v}» no parece un correo (ejemplo: nombre@dominio.com)."
    if t == "URL" and not re.match(r"^https?://\S+\.\S+", v, re.I):
        return f"«{v}» no parece una URL: debe empezar por http:// o https://."
    if t == "DOMAIN":
        if re.match(r"^https?://", v, re.I):
            return f"«{v}» es una URL, no un dominio: elige el tipo URL o escribe solo el dominio (ejemplo.com)."
        if not validate_domain(v):
            return f"«{v}» no parece un dominio (ejemplo: ejemplo.com)."
    if t == "PHONE" and not (_PHONE_RE.match(v) and sum(c.isdigit() for c in v) >= 7):
        return f"«{v}» no parece un teléfono (ejemplo: +593 99 123 4567)."
    return ""
