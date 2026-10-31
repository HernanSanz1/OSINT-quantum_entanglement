"""Comprobación de la instalación (`python -m osint_app.main --setup`): una lista de pasos con su estado.

Primera versión del asistente de instalación: SOLO MIRA, no instala nada ni pide claves. Para cada paso dice si
está listo y, si no, la orden exacta o el enlace para hacerlo. Los pasos salen de lo que se configuró a mano en el
equipo del usuario (Python y su entorno, dependencias, token de GitHub, Docker y SearXNG, copias de seguridad…).

Estados: True = listo · False = necesario y falta · None = opcional (funciona sin ello).
"""
import importlib.metadata
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

ROOT = Path(__file__).resolve().parents[2]
PY = r"env\Scripts\python.exe" if sys.platform == "win32" else "env/bin/python"
OPTIONAL_PACKAGES = {"sherlock-project": "Sherlock", "maigret": "Maigret", "holehe": "Holehe",
                     "instaloader": "Instaloader"}


@dataclass
class Step:
    title: str
    ok: Optional[bool]
    detail: str = ""
    action: str = ""


def _required_packages() -> List[str]:
    names = []
    for line in (ROOT / "osint_app" / "requirements.txt").read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*(?:[<>=!~].*)?$", line.split("#")[0])
        if match:
            names.append(match.group(1))
    return names


def _installed(name: str) -> bool:
    try:
        importlib.metadata.version(name)
        return True
    except importlib.metadata.PackageNotFoundError:
        return False


def check_python() -> Step:
    version = ".".join(map(str, sys.version_info[:3]))
    ok = sys.version_info >= (3, 12)
    return Step("Python 3.12 o más nuevo", ok, f"Python {version}",
                "" if ok else "Instala Python 3.12 desde https://www.python.org/downloads/")


def check_env() -> Step:
    in_project = Path(sys.prefix).resolve() == (ROOT / "env").resolve()
    return Step("Entorno de Python del proyecto (carpeta env)", in_project, sys.prefix,
                "" if in_project else f"Crea el entorno con «py -3.12 -m venv env» y usa siempre {PY}")


def check_packages() -> Step:
    missing = [n for n in _required_packages() if not _installed(n)]
    return Step("Dependencias de requirements.txt", not missing,
                "todas instaladas" if not missing else "faltan: " + ", ".join(missing),
                "" if not missing else f"{PY} -m pip install -r osint_app\\requirements.txt")


def check_optional_tools() -> Step:
    missing = [label for pkg, label in OPTIONAL_PACKAGES.items() if not _installed(pkg)]
    present = [label for pkg, label in OPTIONAL_PACKAGES.items() if _installed(pkg)]
    return Step("Buscadores de usuarios (Sherlock, Maigret, Holehe, Instaloader)", True if not missing else None,
                ("instalados: " + ", ".join(present)) if present else "ninguno instalado",
                "" if not missing else f"Opcional: {PY} -m pip install " +
                " ".join(p for p, label in OPTIONAL_PACKAGES.items() if label in missing))


def check_key(name: str, why: str, how: str, required: bool = False) -> Step:
    from .secret_vault import vault
    ok = bool(vault.get(name))
    return Step(f"Clave de {name}: {why}", True if ok else (False if required else None),
                "guardada" if ok else "sin configurar", "" if ok else how)


def _docker() -> str:
    found = shutil.which("docker")
    if found:
        return found
    if sys.platform == "win32":
        import os
        candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker/Docker/resources/bin/docker.exe"
        if candidate.exists():
            return str(candidate)
    return ""


def check_docker(run: Callable = subprocess.run) -> Step:
    exe = _docker()
    if not exe:
        return Step("Docker Desktop (para tu buscador propio SearXNG)", None, "no instalado",
                    "Opcional: instala Docker Desktop (https://www.docker.com/products/docker-desktop/) y ábrelo")
    try:
        result = run([exe, "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=20,
                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        running = result.returncode == 0 and bool((result.stdout or "").strip())
    except (OSError, subprocess.TimeoutExpired):
        running = False
    return Step("Docker Desktop (para tu buscador propio SearXNG)", True if running else None,
                "funcionando" if running else "instalado pero apagado",
                "" if running else "Abre Docker Desktop y espera a que diga «Engine running»")


def check_searxng(get: Optional[Callable] = None) -> Step:
    from .secret_vault import vault
    url = (vault.get("SearXNG") or "").rstrip("/")
    how = f"Opcional (recomendado): con Docker abierto, {PY} scripts\\searxng_local.py start"
    if not url:
        return Step("Buscador propio SearXNG", None, "no configurado", how)
    try:
        import requests
        resp = (get or requests.get)(f"{url}/search", params={"q": "test", "format": "json"}, timeout=10)
        ok = resp.status_code == 200
    except Exception:            # noqa: BLE001 — cualquier fallo de red es "no responde"
        ok = False
    return Step("Buscador propio SearXNG", True if ok else None, f"{url} " + ("responde" if ok else "no responde"),
                "" if ok else how)


def check_data_folder() -> Step:
    from .data_paths import data_dir, disk_encryption_warning, synced_warning
    folder = data_dir()
    warnings = [w for w in (synced_warning(folder), disk_encryption_warning(folder)) if w]
    return Step("Carpeta de datos protegida (fuera de la nube, disco cifrado)", not warnings, str(folder),
                " ".join(warnings))


def check_backup(now=None) -> Step:
    import datetime
    from .backup import backup_time, last_auto_backup
    last = last_auto_backup()
    now = now or datetime.datetime.now()
    if last is None:
        return Step("Copia de seguridad de los casos", None, "todavía no hay ninguna",
                    "Se hace sola al abrir SENTINEL; para una en un USB: pestaña Casos → «Copia de seguridad…»")
    age = now - backup_time(last)
    ok = age < datetime.timedelta(days=2)
    return Step("Copia de seguridad de los casos", ok, f"última: {backup_time(last):%Y-%m-%d %H:%M}",
                "" if ok else "Abre SENTINEL (hace la copia diaria) o usa «Copia de seguridad…» en la pestaña Casos")


def check_smart_app_control() -> Step:
    """Smart App Control de Windows 11 puede bloquear programas sin firma (subfinder.exe). Solo informa."""
    if sys.platform != "win32":
        return Step("Control inteligente de aplicaciones de Windows", True, "no aplica en este sistema")
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\CI\Policy") as key:
            state = winreg.QueryValueEx(key, "VerifiedAndReputablePolicyState")[0]
    except OSError:
        return Step("Control inteligente de aplicaciones de Windows", True, "no disponible en este Windows")
    label = {0: "desactivado", 1: "activado", 2: "en evaluación"}.get(state, f"estado {state}")
    return Step("Control inteligente de aplicaciones de Windows", True if state == 0 else None, label,
                "" if state == 0 else "Puede bloquear programas sin firma (p. ej. subfinder.exe). Usa siempre "
                                      f"{PY}: así SENTINEL funciona aunque esté activado.")


def run_checks() -> List[Step]:
    return [
        check_python(), check_env(), check_packages(),
        check_key("GitHub", "sube el límite de búsquedas en GitHub",
                  "Crea un token en https://github.com/settings/personal-access-tokens/new (repositorios públicos, "
                  f"sin permisos, 90 días) y guárdalo con: {PY} -m osint_app.main --set-key GitHub"),
        check_docker(), check_searxng(), check_optional_tools(),
        check_key("Hunter.io", "correos de un dominio", f"Opcional: {PY} -m osint_app.main --set-key Hunter.io"),
        check_key("BraveSearch", "buscador de respaldo", "Opcional: crea la clave gratuita en "
                  f"https://brave.com/search/api/ y guárdala con: {PY} -m osint_app.main --set-key BraveSearch"),
        check_data_folder(), check_backup(), check_smart_app_control(),
    ]


def render(steps: List[Step]) -> str:
    icon = {True: "✅", False: "❌", None: "⬜"}
    lines = ["SENTINEL — comprobación de la instalación (no cambia nada)", ""]
    for n, step in enumerate(steps, 1):
        lines.append(f"{n:2}. {icon[step.ok]} {step.title}: {step.detail}")
        if step.action:
            lines.append(f"      → {step.action}")
    missing = [s for s in steps if s.ok is False]
    lines.append("")
    if missing:
        lines.append(f"Falta lo necesario en {len(missing)} paso(s). Empieza por: {missing[0].title}.")
    else:
        lines.append("Todo lo necesario está listo. Los pasos ⬜ son opcionales: mejoran resultados o seguridad.")
    return "\n".join(lines)
