#!/usr/bin/env python3
"""SearXNG personal con Docker para SENTINEL: crear, arrancar, parar, comprobar y conectar.

Uso:
    python scripts/searxng_local.py start    # crea la configuración (si falta), arranca y conecta con SENTINEL
    python scripts/searxng_local.py status   # ¿está funcionando?
    python scripts/searxng_local.py test     # búsqueda real de prueba
    python scripts/searxng_local.py stop     # lo detiene (no borra nada)
    python scripts/searxng_local.py remove   # borra el contenedor (la configuración se conserva)

Requisitos: Docker (en Windows, Docker Desktop abierto). El servicio solo escucha en 127.0.0.1 (este equipo).
La configuración se guarda en la carpeta de datos de SENTINEL de CADA usuario, con su propia clave secreta;
la plantilla del proyecto (deploy/searxng/settings.yml) no tiene secretos. Pensado para reutilizarse en el
futuro asistente de instalación (--setup).
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from osint_app.utils.data_paths import data_dir  # noqa: E402

CONTAINER = "sentinel-searxng"
IMAGE = "docker.io/searxng/searxng:latest"
PORT = 8888
URL = f"http://127.0.0.1:{PORT}"
TEMPLATE = ROOT / "deploy" / "searxng" / "settings.yml"


def config_dir() -> Path:
    return data_dir() / "searxng"


def docker() -> str:
    """Ruta de docker (en Windows Docker Desktop no siempre está en el PATH de procesos ya abiertos)."""
    found = shutil.which("docker")
    if found:
        return found
    for candidate in (Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker/Docker/resources/bin/docker.exe",):
        if candidate.is_file():
            return str(candidate)
    sys.exit("❌ No encuentro Docker. Instala Docker Desktop y ábrelo (debe decir 'Engine running').")


def run(*args, check=True, capture=True):
    exe = docker()
    # Los ayudantes de Docker (docker-credential-desktop) están junto a docker.exe; si esa carpeta no está en el
    # PATH (ventanas abiertas antes de instalar Docker Desktop), la descarga de la imagen falla (visto en real)
    env = {**os.environ, "PATH": str(Path(exe).parent) + os.pathsep + os.environ.get("PATH", "")}
    result = subprocess.run([exe, *args], capture_output=capture, text=True, encoding="utf-8", errors="replace", env=env)
    if check and result.returncode != 0:
        sys.exit(f"❌ docker {' '.join(args[:2])} falló: {(result.stderr or result.stdout).strip()[:300]}")
    return result


def ensure_config() -> Path:
    folder = config_dir()
    (folder / "config").mkdir(parents=True, exist_ok=True)
    (folder / "data").mkdir(parents=True, exist_ok=True)
    settings = folder / "config" / "settings.yml"
    if not settings.exists():
        text = TEMPLATE.read_text(encoding="utf-8").replace("__SECRET__", secrets.token_hex(32))
        settings.write_text(text, encoding="utf-8")
        print(f"🆕 Configuración creada en {settings} (con clave secreta propia)")
    return folder


def container_state() -> str:
    result = run("inspect", "-f", "{{.State.Status}}", CONTAINER, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def search(query: str, timeout: int = 20) -> dict:
    url = f"{URL}/search?" + urllib.parse.urlencode({"q": query, "format": "json"})
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "SENTINEL-OSINT/2.0"}),
                                timeout=timeout) as resp:
        return json.load(resp)


def wait_ready(seconds: int = 60) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        try:
            search("test", timeout=5)
            return True
        except Exception:
            time.sleep(2)
    return False


def connect_sentinel() -> None:
    """Guarda la URL en el baúl de SENTINEL (clave 'SearXNG'): no es un secreto, solo la dirección local."""
    from osint_app.utils.secret_vault import vault
    vault.set("SearXNG", URL)
    print(f"🔗 SENTINEL usará SearXNG en {URL}")


def start() -> None:
    folder = ensure_config()
    state = container_state()
    if state == "running":
        print("✅ SearXNG ya estaba funcionando")
    elif state:
        run("start", CONTAINER)
        print("▶️ SearXNG arrancado")
    else:
        print("⬇️ Descargando y creando SearXNG (la primera vez tarda un poco)…")
        run("run", "-d", "--name", CONTAINER, "--restart", "unless-stopped",
            "-p", f"127.0.0.1:{PORT}:8080",
            "-v", f"{folder / 'config'}:/etc/searxng",
            "-v", f"{folder / 'data'}:/var/cache/searxng",
            IMAGE, capture=True)
    if not wait_ready():
        logs = run("logs", "--tail", "20", CONTAINER, check=False)
        sys.exit("❌ SearXNG no respondió a tiempo. Últimos mensajes:\n" + (logs.stdout + logs.stderr)[-1500:])
    connect_sentinel()
    test()


def status() -> None:
    state = container_state() or "no creado"
    print(f"Contenedor {CONTAINER}: {state}")
    if state == "running":
        print("Respuesta:", "✅ responde" if wait_ready(10) else "❌ no responde")


def test() -> None:
    data = search('"Jefferson Pérez" atleta Ecuador')
    results = data.get("results", [])
    engines = sorted({e for r in results for e in r.get("engines", [])})
    print(f"🔎 Prueba real: {len(results)} resultados · motores que respondieron: {', '.join(engines) or 'ninguno'}")
    for r in results[:5]:
        print("   -", r.get("title", "")[:70], "|", r.get("url", "")[:60])
    if data.get("unresponsive_engines"):
        print("   Motores que no respondieron:", ", ".join(e[0] for e in data["unresponsive_engines"]))


def stop() -> None:
    run("stop", CONTAINER, check=False)
    print("⏹️ SearXNG detenido (vuelve a arrancarlo con: start)")


def remove() -> None:
    run("rm", "-f", CONTAINER, check=False)
    print(f"🗑️ Contenedor borrado. La configuración sigue en {config_dir()}")


if __name__ == "__main__":
    actions = {"start": start, "status": status, "test": test, "stop": stop, "remove": remove}
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    if action not in actions:
        sys.exit(__doc__)
    actions[action]()
