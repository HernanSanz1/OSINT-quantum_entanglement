"""Cómo lanzar las herramientas de Python instaladas con pip (Maigret, Sherlock, Holehe…) sin su lanzador .exe.

pip crea para cada herramienta un pequeño programa `env\\Scripts\\<herramienta>.exe` sin firma digital. Windows 11
con Smart App Control (o una directiva de Control de aplicaciones) lo bloquea según la "reputación" que le da la
nube de Microsoft: a veces arranca y a veces no (WinError 4551). Visto en real el 14-10-2026: 18 bloqueos de
`maigret.exe` en el registro CodeIntegrity, y Maigret daba 0 resultados en todos los perfiles.

Aquí se lanza la misma función que llamaría ese .exe (su "entry point" de pip), pero a través del Python que ya
ejecuta SENTINEL, que sí está firmado.
"""
import importlib.util
import shutil
import sys
from importlib.metadata import entry_points
from typing import List

# Códigos de Windows para "una directiva bloqueó este programa"
_BLOCKED_WINERRORS = {
    4551: "Smart App Control o una directiva de Control de aplicaciones",   # ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION
    1260: "una directiva de grupo",                                          # ERROR_ACCESS_DISABLED_BY_POLICY
    225: "el antivirus",                                                     # ERROR_VIRUS_INFECTED
}


def _entry_point_command(name: str) -> List[str]:
    try:
        candidates = list(entry_points(group="console_scripts", name=name))
    except Exception:
        return []
    for ep in candidates:
        module, _, attr = ep.value.partition(":")
        module, attr = module.strip(), attr.split("[")[0].strip()      # "paquete.modulo:funcion [extra]"
        if not module or not attr or importlib.util.find_spec(module.split(".")[0]) is None:
            continue
        code = (f"import importlib, sys\n"
                f"sys.argv[0] = {name!r}\n"
                f"target = importlib.import_module({module!r})\n"
                f"for part in {attr.split('.')!r}:\n"
                f"    target = getattr(target, part)\n"
                f"sys.exit(target())")
        return [sys.executable, "-c", code]
    return []


def pip_tool_command(name: str) -> List[str]:
    """Orden para ejecutar la herramienta `name` (a la que se añaden sus argumentos), o [] si no está instalada.

    Primero, la herramienta instalada en el Python de SENTINEL, lanzada con ese Python; si no, el programa que haya
    en el PATH (instalada aparte, por ejemplo con pipx).
    """
    command = _entry_point_command(name)
    if command:
        return command
    found = shutil.which(name)
    return [found] if found else []


def blocked_by_windows(label: str, error: OSError) -> str:
    """Explicación sencilla si Windows impidió abrir el programa; "" si el error es otro."""
    who = _BLOCKED_WINERRORS.get(getattr(error, "winerror", None))
    if not who:
        return ""
    return (f"❌ {label}: Windows ({who}) bloqueó el programa porque no tiene firma digital. No es un fallo de "
            f"SENTINEL ni de tu conexión; las demás herramientas siguen funcionando. Si quieres usarla, pide a quien "
            f"administre el equipo que permita ese programa.")
