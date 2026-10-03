"""Guardar claves de API desde la consola, sin que la clave aparezca en pantalla ni en el historial.

    python -m osint_app.main --keys               # qué claves están configuradas (nunca muestra su valor)
    python -m osint_app.main --set-key GitHub     # pide la clave oculta y la guarda en el baúl cifrado

La clave se escribe cuando el programa la pide (no como argumento del comando, porque quedaría en el historial de la
consola) y no se muestra al escribirla.
"""
import getpass
from typing import Callable, Optional

from .secret_vault import _ENV_MAP, vault as default_vault


def known_names():
    return list(_ENV_MAP.keys())


def resolve_name(name: str) -> Optional[str]:
    """El nombre canónico de una clave sin importar mayúsculas ('github' → 'GitHub'), o None si no existe."""
    wanted = (name or "").strip().lower()
    return next((n for n in _ENV_MAP if n.lower() == wanted), None)


def set_key_interactive(name: str, ask: Callable[[str], str] = None, say: Callable[[str], None] = print, v=None) -> int:
    """Pide la clave oculta y la guarda. Devuelve el código de salida: 0 ok, 1 cancelado, 2 nombre desconocido."""
    v = v or default_vault
    ask = ask or getpass.getpass
    canonical = resolve_name(name)
    if not canonical:
        say(f"No conozco la clave '{name}'. Las disponibles son: {', '.join(known_names())}")
        return 2
    value = (ask(f"Pega la clave de {canonical} y pulsa Enter (no se mostrará): ") or "").strip()
    if not value:
        say("No se escribió ninguna clave: no se guardó nada.")
        return 1
    v.set(canonical, value)
    say(f"Clave de {canonical} guardada.")
    if _ENV_MAP[canonical] and v.get(canonical) != value:
        say(f"Aviso: la variable de entorno {_ENV_MAP[canonical]} está definida y tiene prioridad sobre la clave guardada.")
    return 0


def show_keys(say: Callable[[str], None] = print, v=None) -> int:
    """Lista qué claves están configuradas, sin mostrar nunca su valor."""
    v = v or default_vault
    say("Claves de API (solo se indica si están configuradas):")
    for name, state in v.status_report().items():
        say(f"  {name:<10} {state}")
    return 0
