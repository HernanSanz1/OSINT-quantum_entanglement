"""Botón «Enviar» del boletín CTI: prepara un BORRADOR en el programa de correo del analista; no envía nada.

Decisión del 31-10-2026: SENTINEL lo usan empresas con correos y dominios distintos (Microsoft 365, Google Workspace,
servidores propios). Enviar desde SENTINEL obligaría a guardar contraseñas de correo de cada empresa y a configurar su
servidor, y un error de destinatario sería una fuga sin vuelta atrás. Por eso:

- El boletín va en un archivo .eml con la cabecera «X-Unsent: 1»: Outlook clásico, Correo de Windows o Thunderbird
  lo abren como un correo nuevo editable, desde la cuenta del analista (su dominio, su firma, sus reglas). Una persona
  revisa y pulsa Enviar. Si el equipo no tiene programa para los .eml (p. ej. solo el Outlook nuevo o correo web), se
  abre un correo nuevo con «mailto:» (destinatarios y asunto) y el boletín queda copiado para pegarlo con Ctrl+V.
- Los destinatarios de cada cliente se recuerdan en la carpeta de datos (solo direcciones, nunca contraseñas), para no
  mandar el boletín de un cliente a otro.
- Para el correo web (Gmail, Outlook en el navegador), «Copiar para pegar»: los estilos van dentro de cada etiqueta,
  porque al pegar se pierden los del bloque <style>.
"""
import json
import re
import sys
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import quote

from bs4 import BeautifulSoup

from .data_paths import cti_reports_dir, cti_store_dir

_ADDRESS = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
_BLOCKS = ["p", "li", "ul", "ol", "div", "section", "header", "footer", "h1", "h2", "h3", "h4", "tr", "table"]
_BULLETIN = re.compile(r"_(\d{4})W(\d{2})(?:_([A-Z][A-Z0-9]+))?\.html$|_(\d{4})(\d{2})(\d{2})(?:_([A-Z][A-Z0-9]+))?\.html$")


def recipients_file() -> Path:
    return cti_store_dir() / "destinatarios.json"


def parse_addresses(text: str) -> Tuple[List[str], List[str]]:
    """(válidas, no válidas) de una lista separada por comas, punto y coma o espacios. Sin repetir."""
    valid, invalid = [], []
    for raw in re.split(r"[,;\s]+", text or ""):
        address = raw.strip().strip("<>")
        if not address:
            continue
        target = valid if _ADDRESS.match(address) else invalid
        if address.lower() not in (a.lower() for a in target):
            target.append(address)
    return valid, invalid


def load_recipients() -> Dict[str, List[str]]:
    try:
        data = json.loads(recipients_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(k): [str(a) for a in v] for k, v in data.items() if isinstance(v, list)} if isinstance(data, dict) else {}


def save_recipients(client: str, addresses: List[str]) -> None:
    data = load_recipients()
    data[client] = list(addresses)
    path = recipients_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def other_client_addresses(client: str, addresses: List[str]) -> Dict[str, str]:
    """{dirección: otro cliente} de las direcciones guardadas para OTRO cliente: posible boletín cruzado."""
    found = {}
    for other, saved in load_recipients().items():
        if other == client:
            continue
        lowered = {a.lower() for a in saved}
        for address in addresses:
            if address.lower() in lowered:
                found.setdefault(address, other)
    return found


def bulletin_client(path) -> str:
    """Cliente del boletín según su nombre (AltelThreatIntell_2026W44_XTRIM.html → XTRIM); sin sufijo, GLOBAL."""
    match = _BULLETIN.search(Path(path).name)
    if not match:
        return "GLOBAL"
    return match.group(3) or match.group(7) or "GLOBAL"


def bulletin_subject(path) -> str:
    """«Boletín de ciberamenazas: semana 44 de 2026 (XTRIM)» o «… del 29-10-2026» si es de un día.

    Sin rayas (—): Python parte el asunto codificado justo ahí y al leerlo salía con un espacio de más.
    """
    match = _BULLETIN.search(Path(path).name)
    subject = "Boletín de ciberamenazas"
    if match and match.group(1):
        subject += f": semana {int(match.group(2))} de {match.group(1)}"
    elif match:
        subject += f" del {match.group(6)}-{match.group(5)}-{match.group(4)}"
    client = bulletin_client(path)
    return subject + (f" ({client})" if client != "GLOBAL" else "")


def _rules(css: str) -> List[Tuple[str, str]]:
    """[(selector, declaraciones)] de las reglas que se pueden copiar a una etiqueta (sin :hover, ::before ni *)."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    rules = []
    for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        declarations = "; ".join(d.strip() for d in body.split(";") if d.strip())
        for selector in selectors.split(","):
            selector = selector.strip()
            if selector and ":" not in selector and "*" not in selector and declarations:
                rules.append((selector, declarations))
    return rules


def email_html(page: str) -> str:
    """El boletín con los estilos dentro de cada etiqueta, envuelto en un <div> con los del <body>: para el cuerpo
    del correo y para el portapapeles."""
    soup = BeautifulSoup(page, "html.parser")
    rules = []
    for style in soup.find_all("style"):
        rules += _rules(style.get_text())
        style.decompose()
    body = soup.body or soup
    wrapper, added = "", {}
    for selector, declarations in rules:
        if selector == "body":
            wrapper += declarations + "; "
            continue
        for tag in body.select(selector):
            added.setdefault(id(tag), [tag, ""])[1] += declarations + "; "
    for tag, declarations in added.values():
        # Lo que la etiqueta ya traía escrito va al final: manda sobre la hoja de estilos, como en el navegador
        tag["style"] = (declarations + tag.get("style", "")).strip()
    inner = "".join(str(child) for child in body.children)
    return f'<div style="{wrapper.strip()}">{inner}</div>'


def plain_text(page: str) -> str:
    """Versión en texto del boletín (para programas que no muestran HTML)."""
    soup = BeautifulSoup(page, "html.parser")
    for tag in soup.find_all(["style", "script", "title"]):
        tag.decompose()
    for link in soup.find_all("a", href=True):
        if link["href"].startswith("http"):
            link.insert_before(" ")          # «…CVE-2026-110936.Leer Más» salía pegado
            link.append(f" ({link['href']})")
    # Saltos de línea solo entre bloques: con get_text("\n") cada negrita o enlace partía la frase
    for tag in soup.find_all(_BLOCKS):
        tag.insert_before("\n")
        tag.append("\n")
    for br in soup.find_all("br"):
        br.replace_with("\n")
    lines = (re.sub(r"[ \t\r\f\v]+", " ", line).strip() for line in soup.get_text().split("\n"))
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip() + "\n"


def build_eml(page: str, subject: str, to: List[str]) -> bytes:
    """Correo sin enviar (X-Unsent: 1): el programa de correo lo abre como borrador editable."""
    message = EmailMessage(policy=SMTP)
    message["Subject"] = subject
    if to:
        message["To"] = ", ".join(to)
    message["X-Unsent"] = "1"
    message.set_content(plain_text(page))
    message.add_alternative(f"<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body>{email_html(page)}"
                            "</body></html>", subtype="html")
    return message.as_bytes()


def eml_handler() -> str:
    """Programa que abre los .eml en este equipo ("" si no hay ninguno elegido).

    Probado el 31-10-2026 en el equipo del usuario: los .eml no tenían programa (Windows mostraba «Elegir una
    aplicación») y el correo era el Outlook nuevo, que no abre un .eml como borrador editable.
    """
    if sys.platform != "win32":
        return ""
    import ctypes
    from ctypes import wintypes
    buffer, size = ctypes.create_unicode_buffer(1024), wintypes.DWORD(1024)
    # ASSOCSTR_EXECUTABLE = 2
    if ctypes.windll.shlwapi.AssocQueryStringW(0, 2, ".eml", None, buffer, ctypes.byref(size)) != 0:
        return ""
    exe = buffer.value
    return "" if not exe or Path(exe).name.lower() == "openwith.exe" or not Path(exe).exists() else exe


def mailto_url(to: List[str], subject: str) -> str:
    """Enlace mailto: con destinatarios y asunto: abre un correo nuevo en el programa de correo predeterminado."""
    return f"mailto:{','.join(quote(a, safe='@') for a in to)}?subject={quote(subject)}"


# Correo en el navegador (31-10-2026: en el equipo del usuario el Outlook nuevo no tenía cuenta; el correo era web)
WEBMAIL = {
    "gmail": ("Gmail", "https://mail.google.com/mail/?view=cm&fs=1&to={to}&su={subject}"),
    "outlook": ("Outlook web (Microsoft 365)", "https://outlook.office.com/mail/deeplink/compose?to={to}&subject={subject}"),
}


def webmail_url(service: str, to: List[str], subject: str) -> str:
    """Enlace que abre un correo nuevo en el correo web con destinatarios y asunto (el cuerpo se pega)."""
    template = WEBMAIL[service][1]
    return template.format(to=quote(",".join(to), safe="@,"), subject=quote(subject))


def write_draft(bulletin, to: List[str]) -> Path:
    """Escribe el borrador .eml del boletín en <datos>/cti/boletines/borradores y devuelve su ruta."""
    bulletin = Path(bulletin)
    folder = cti_reports_dir() / "borradores"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"{bulletin.stem}.eml"
    target.write_bytes(build_eml(bulletin.read_text(encoding="utf-8"), bulletin_subject(bulletin), to))
    return target
