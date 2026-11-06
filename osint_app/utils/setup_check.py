"""Comprobación e instalación guiada (`python -m osint_app.main --setup`): una lista de pasos con su estado.

La revisión SOLO MIRA: para cada paso dice si está listo y, si no, la orden exacta o el enlace para hacerlo. Los
pasos salen de lo que se configuró a mano en el equipo del usuario (Python y su entorno, dependencias, token de
GitHub, Docker y SearXNG, copias de seguridad…).

Segunda versión (05-11-2026, run_interactive): después de la revisión, si se ejecuta en una consola, ofrece arreglar
lo que se puede arreglar sin permisos de administrador (instalar dependencias, guardar claves, abrir Docker, crear
SearXNG, hacer la primera copia), preguntando antes de CADA paso. Lo demás (Python, el entorno, cifrar el disco,
Smart App Control) solo se explica: son decisiones del usuario o necesitan administrador.

Estados: True = listo · False = necesario y falta · None = opcional (funciona sin ello).
"""
import importlib.metadata
import re
import shutil
import subprocess
import sys
import time
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
    fix: Optional[Callable[[], str]] = None     # lo que el asistente puede hacer (con permiso); devuelve un resumen
    fix_label: str = ""                         # qué hará, en una frase


def _run_visible(cmd: List[str], run: Callable = subprocess.run) -> None:
    """Ejecuta una orden mostrando su salida (pip y Docker tardan: se ve que avanza). Falla si no termina bien."""
    result = run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        raise RuntimeError(f"la orden terminó con error ({result.returncode})")


def _pip_install(args: List[str], run: Callable = subprocess.run) -> str:
    _run_visible([sys.executable, "-m", "pip", "install", *args], run)
    return "instalado"


def _ask_key(name: str) -> str:
    from .key_cli import set_key_interactive
    code = set_key_interactive(name)
    return "guardada" if code == 0 else "no se guardó nada"


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
                "" if not missing else f"{PY} -m pip install -r osint_app\\requirements.txt",
                fix=(lambda: _pip_install(["-r", str(ROOT / "osint_app" / "requirements.txt")])) if missing else None,
                fix_label="instalar con pip lo que falta (" + ", ".join(missing) + ")")


def check_optional_tools() -> Step:
    missing = [label for pkg, label in OPTIONAL_PACKAGES.items() if not _installed(pkg)]
    present = [label for pkg, label in OPTIONAL_PACKAGES.items() if _installed(pkg)]
    packages = [p for p, label in OPTIONAL_PACKAGES.items() if label in missing]
    return Step("Buscadores de usuarios (Sherlock, Maigret, Holehe, Instaloader)", True if not missing else None,
                ("instalados: " + ", ".join(present)) if present else "ninguno instalado",
                "" if not missing else f"Opcional: {PY} -m pip install " + " ".join(packages),
                fix=(lambda: _pip_install(packages)) if missing else None,
                fix_label="instalar con pip " + ", ".join(missing))


def check_key(name: str, why: str, how: str, required: bool = False) -> Step:
    from .secret_vault import vault
    ok = bool(vault.get(name))
    return Step(f"Clave de {name}: {why}", True if ok else (False if required else None),
                "guardada" if ok else "sin configurar", "" if ok else how,
                fix=None if ok else (lambda: _ask_key(name)),
                fix_label=f"pegar ahora tu clave de {name} (no se mostrará; se guarda cifrada)")


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


def _docker_desktop() -> str:
    """El programa Docker Desktop de Windows, para abrirlo si está apagado ("" si no está instalado)."""
    if sys.platform != "win32":
        return ""
    import os
    candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker/Docker/Docker Desktop.exe"
    return str(candidate) if candidate.exists() else ""


def _docker_running(exe: str = "", run: Callable = subprocess.run) -> bool:
    exe = exe or _docker()
    if not exe:
        return False
    try:
        result = run([exe, "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=20,
                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.returncode == 0 and bool((result.stdout or "").strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def _start_docker(desktop: str, exe: str, run: Callable = subprocess.run, wait: int = 180,
                  sleep: Callable = time.sleep) -> str:
    """Abre Docker Desktop y espera a que su motor responda."""
    subprocess.Popen([desktop])          # noqa: S603 — el programa instalado de Docker, ruta fija
    for _ in range(wait // 5):
        sleep(5)
        if _docker_running(exe, run):
            return "Docker funcionando"
    raise RuntimeError("Docker no arrancó en 3 minutos: ábrelo a mano y espera a que diga «Engine running»")


SEARXNG_FIX_LABEL = "crear y arrancar tu SearXNG en Docker (la primera vez descarga la imagen, unos minutos)"


def _searxng_fix() -> Optional[Callable[[], str]]:
    """Arreglo de SearXNG: solo con Docker funcionando (si no, el paso de Docker va antes)."""
    if not _docker_running():
        return None

    def fix() -> str:
        _run_visible([sys.executable, str(ROOT / "scripts" / "searxng_local.py"), "start"])
        return "creado y conectado con SENTINEL"
    return fix


def _backup_now() -> str:
    from .backup import backups_dir, make_backup
    made = make_backup(backups_dir())            # la misma carpeta privada que la copia diaria
    return f"copia guardada: {made.name}"


def check_docker(run: Callable = subprocess.run) -> Step:
    exe = _docker()
    if not exe:
        return Step("Docker Desktop (para tu buscador propio SearXNG)", None, "no instalado",
                    "Opcional: instala Docker Desktop (https://www.docker.com/products/docker-desktop/) y ábrelo")
    running = _docker_running(exe, run)
    desktop = _docker_desktop()
    return Step("Docker Desktop (para tu buscador propio SearXNG)", True if running else None,
                "funcionando" if running else "instalado pero apagado",
                "" if running else "Abre Docker Desktop y espera a que diga «Engine running»",
                fix=None if running or not desktop else (lambda: _start_docker(desktop, exe, run)),
                fix_label="abrir Docker Desktop y esperar a que arranque (hasta 3 minutos)")


def check_searxng(get: Optional[Callable] = None) -> Step:
    from .secret_vault import vault
    url = (vault.get("SearXNG") or "").rstrip("/")
    how = f"Opcional (recomendado): con Docker abierto, {PY} scripts\\searxng_local.py start"
    if not url:
        return Step("Buscador propio SearXNG", None, "no configurado", how, fix=_searxng_fix(),
                    fix_label=SEARXNG_FIX_LABEL)
    try:
        import requests
        resp = (get or requests.get)(f"{url}/search", params={"q": "test", "format": "json"}, timeout=10)
        ok = resp.status_code == 200
    except Exception:            # noqa: BLE001 — cualquier fallo de red es "no responde"
        ok = False
    return Step("Buscador propio SearXNG", True if ok else None, f"{url} " + ("responde" if ok else "no responde"),
                "" if ok else how, fix=None if ok else _searxng_fix(), fix_label=SEARXNG_FIX_LABEL)


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
                    "Se hace sola al abrir SENTINEL; para una en un USB: pestaña Casos → «Copia de seguridad…»",
                    fix=_backup_now, fix_label="hacer ahora la primera copia (en la carpeta de copias, privada)")
    age = now - backup_time(last)
    ok = age < datetime.timedelta(days=2)
    return Step("Copia de seguridad de los casos", ok, f"última: {backup_time(last):%Y-%m-%d %H:%M}",
                "" if ok else "Abre SENTINEL (hace la copia diaria) o usa «Copia de seguridad…» en la pestaña Casos",
                fix=None if ok else _backup_now, fix_label="hacer ahora una copia nueva (se guardan las 7 últimas)")


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


def checks() -> List[Callable[[], Step]]:
    """Las comprobaciones en orden (Docker antes que SearXNG: el asistente puede abrirlo y luego crear SearXNG)."""
    return [
        check_python, check_env, check_packages,
        lambda: check_key("GitHub", "sube el límite de búsquedas en GitHub",
                          "Crea un token en https://github.com/settings/personal-access-tokens/new (repositorios "
                          f"públicos, sin permisos, 90 días) y guárdalo con: {PY} -m osint_app.main --set-key GitHub"),
        check_docker, check_searxng, check_optional_tools,
        lambda: check_key("Hunter.io", "correos de un dominio", f"Opcional: {PY} -m osint_app.main --set-key Hunter.io"),
        lambda: check_key("BraveSearch", "buscador de respaldo", "Opcional: crea la clave gratuita en https://brave.com/"
                          f"search/api/ y guárdala con: {PY} -m osint_app.main --set-key BraveSearch"),
        lambda: check_key("abuse.ch", "URLhaus (IP o enlace que reparte malware)", "Opcional: crea la clave gratuita en "
                          f"https://auth.abuse.ch/ y guárdala con: {PY} -m osint_app.main --set-key abuse.ch"),
        check_data_folder, check_backup, check_smart_app_control,
    ]


def run_checks() -> List[Step]:
    return [check() for check in checks()]


YES = {"s", "si", "sí", "y", "yes"}


def ask_console(question: str) -> str:
    """input() que toma «sin respuesta» como «no». En Windows, NUL también parece una consola (isatty), y con la
    entrada redirigida input() acababa en EOFError (prueba real del 05-11-2026)."""
    try:
        return input(question)
    except EOFError:
        print()
        return ""
ICON = {True: "✅", False: "❌", None: "⬜"}


def run_interactive(steps: List[Step], ask: Callable[[str], str] = ask_console, say: Callable[[str], None] = print,
                    check_list: Optional[List[Callable[[], Step]]] = None) -> dict:
    """Ofrece arreglar, uno por uno y preguntando antes, los pasos que no están listos y tienen arreglo.

    Cada paso se vuelve a comprobar justo antes de ofrecerlo (si se acaba de abrir Docker, SearXNG ya se puede crear)
    y después de arreglarlo, para decir si quedó listo. Devuelve cuántos se arreglaron, se saltaron o fallaron.
    """
    check_list = check_list or checks()
    fixable = [s for s in steps if s.ok is not True and s.fix]
    result = {"arreglados": 0, "saltados": 0, "fallidos": 0}
    if not fixable:
        return result
    answer = ask(f"\nPuedo arreglar {len(fixable)} paso(s) ahora, uno por uno y preguntándote antes de cada uno. "
                 "¿Empezamos? (s/N): ")
    if answer.strip().lower() not in YES:
        say("No he cambiado nada.")
        return result
    for check in check_list:
        step = check()
        if step.ok is True or not step.fix:
            continue
        say(f"\n{ICON[step.ok]} {step.title}: {step.detail}")
        if ask(f"   Puedo {step.fix_label}. ¿Lo hago? (s/N): ").strip().lower() not in YES:
            result["saltados"] += 1
            continue
        try:
            done = step.fix()
        except Exception as e:           # noqa: BLE001 — el error se explica y se sigue con el resto
            say(f"   ❌ No se pudo: {e}")
            result["fallidos"] += 1
            continue
        after = check()
        say(f"   {ICON[after.ok]} {after.title}: {after.detail} ({done})")
        result["arreglados" if after.ok is True else "fallidos"] += 1
    say(f"\nListo: {result['arreglados']} arreglado(s), {result['saltados']} saltado(s), {result['fallidos']} sin "
        "completar. Vuelve a ejecutar --setup cuando quieras para revisar.")
    return result


def render(steps: List[Step]) -> str:
    lines = ["SENTINEL — comprobación de la instalación (no cambia nada)", ""]
    for n, step in enumerate(steps, 1):
        lines.append(f"{n:2}. {ICON[step.ok]} {step.title}: {step.detail}")
        if step.action:
            lines.append(f"      → {step.action}")
    missing = [s for s in steps if s.ok is False]
    lines.append("")
    if missing:
        lines.append(f"Falta lo necesario en {len(missing)} paso(s). Empieza por: {missing[0].title}.")
    else:
        lines.append("Todo lo necesario está listo. Los pasos ⬜ son opcionales: mejoran resultados o seguridad.")
    return "\n".join(lines)
