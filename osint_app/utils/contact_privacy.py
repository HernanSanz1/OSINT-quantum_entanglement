"""Correos y teléfonos ocultos por defecto en lo que se lee (ficha, fragmentos, vista legible de Reportes).

Evaluación 4: la ficha de midudev mostraba su correo y su teléfono personales, y un fragmento de WebSearch el
teléfono de la página de Facebook de un deportista, sin aviso. El dato no se borra: sigue en el caso, en el JSON
técnico y en la ficha «con datos de contacto», que el analista pide a propósito cuando tiene una finalidad legítima.

    m•••@gmail.com          (primera letra del usuario y dominio completo: se sabe de qué tipo de correo se trata)
    (••)••••••23            (solo los dos últimos dígitos)
"""
import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Grupos de dígitos separados por espacio, guion o paréntesis; con o sin prefijo internacional. Sin puntos ni barras
# como separador: así "1.234.567 suscriptores" o "29/10/2026" no cuentan como teléfono.
PHONE_RE = re.compile(r"(?<![\w/.-])(?:\+\d{1,3}[\s-]?)?(?:\(\d{1,4}\)[\s-]?)?\d(?:[\s-]?\d){6,13}(?![\w/-])")
_YEAR = re.compile(r"(?:19|20)\d\d")
DOT = "•"


def mask_email(email: str) -> str:
    user, _, domain = email.partition("@")
    return f"{user[:1]}{DOT * 3}@{domain}"


def _is_phone(text: str) -> bool:
    digits = re.sub(r"\D", "", text)
    if not 9 <= len(digits) <= 15:
        return False
    groups = re.findall(r"\d+", text)
    # "1996 2000 2004 2008": una lista de años (Juegos Olímpicos), no un teléfono
    return not all(len(g) == 4 and _YEAR.fullmatch(g) for g in groups)


def mask_phone(phone: str) -> str:
    total = sum(ch.isdigit() for ch in phone)
    seen, out = 0, []
    for ch in phone:
        if ch.isdigit():
            seen += 1
            out.append(ch if seen > total - 2 else DOT)
        else:
            out.append(ch)
    return "".join(out)


def mask_contacts(text) -> str:
    """El texto con cada correo y teléfono enmascarado; lo demás, igual."""
    if not text:
        return text or ""
    text = EMAIL_RE.sub(lambda m: mask_email(m.group()), str(text))
    return PHONE_RE.sub(lambda m: mask_phone(m.group()) if _is_phone(m.group()) else m.group(), text)
