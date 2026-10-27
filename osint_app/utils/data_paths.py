"""Dónde se guardan los datos de los casos, y que no queden en una carpeta sincronizada con la nube.

Los casos contienen datos personales de terceros. Antes se guardaban dentro de la carpeta del proyecto, que en
muchos equipos está en OneDrive (sincroniza con la nube de Microsoft). Ahora van a una carpeta propia del usuario
del sistema (en Windows, %LOCALAPPDATA%\\SENTINEL). Se puede cambiar con la variable de entorno SENTINEL_DATA_DIR.
"""
import logging
import os
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

APP_NAME = "SENTINEL"
DB_NAME = "osint_v2.db"

# nombre de carpeta (en minúsculas, por prefijo) → servicio de sincronización
_SYNC_FOLDERS = (
    ("onedrive", "OneDrive"), ("dropbox", "Dropbox"), ("google drive", "Google Drive"), ("googledrive", "Google Drive"),
    ("icloud", "iCloud"), ("mobile documents", "iCloud"), ("com~apple~clouddocs", "iCloud"), ("pcloud", "pCloud"), ("nextcloud", "Nextcloud"), ("box sync", "Box"), ("mega", "MEGA"),
)


# Para comprobar que la copia tiene las mismas filas que el original
_COUNT_QUERIES = (
    ("cases", "SELECT COUNT(*) FROM cases"),
    ("target_data", "SELECT COUNT(*) FROM target_data"),
    ("tool_reports", "SELECT COUNT(*) FROM tool_reports"),
)


def data_dir() -> Path:
    override = os.environ.get("SENTINEL_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / APP_NAME.lower()


def legacy_db_path() -> Path:
    """Dónde guardaba la base la versión anterior: dentro de la carpeta del proyecto."""
    return Path(__file__).resolve().parent.parent / "data" / DB_NAME


def synced_folder(path) -> str:
    """Nombre del servicio de nube que sincroniza `path` ('OneDrive', 'Dropbox'…), o '' si no está sincronizada."""
    try:
        resolved = Path(path).resolve()
    except OSError:
        return ""
    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        root = os.environ.get(var)
        if root and str(resolved).lower().startswith(str(Path(root).resolve()).lower()):
            return "OneDrive"
    for part in resolved.parts:
        low = part.lower()
        for prefix, name in _SYNC_FOLDERS:
            if low == prefix or low.startswith(prefix + " ") or low.startswith(prefix + "-") or (prefix == "onedrive" and low.startswith("onedrive")):
                return name
    return ""


def synced_warning(path=None) -> str:
    """Aviso para el usuario si los datos están en una carpeta sincronizada con la nube; '' si no."""
    path = Path(path) if path else data_dir()
    provider = synced_folder(path)
    if not provider:
        return ""
    return (f"Tus casos están en una carpeta sincronizada con {provider} ({path}). Los datos personales de los casos "
            f"se subirían a la nube. Mueve la carpeta de datos fuera de {provider} o define SENTINEL_DATA_DIR.")


def migrate_legacy_db(new_path: Path, legacy: Optional[Path] = None) -> str:
    """Copia la base antigua al sitio nuevo, una sola vez. Nunca borra ni mueve la original.

    Devuelve 'copiada' si copió, '' si no había nada que hacer. Lanza OSError/sqlite3.Error si falla: quien llama
    debe seguir usando la base antigua en ese caso (jamás arrancar con una base vacía creyendo que se perdieron los casos).
    """
    legacy = legacy or legacy_db_path()
    new_path = Path(new_path)
    if new_path.exists() or not legacy.exists():
        return ""
    if legacy.resolve() == new_path.resolve():
        return ""
    new_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = new_path.with_name(new_path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    src = sqlite3.connect(f"file:{legacy.as_posix()}?mode=ro", uri=True)
    dst = sqlite3.connect(tmp)
    try:
        src.backup(dst)                         # copia consistente aunque la base esté en uso
        for table, query in _COUNT_QUERIES:
            try:
                a = src.execute(query).fetchone()[0]
            except sqlite3.Error:
                continue                        # la tabla no existía en una base muy antigua
            b = dst.execute(query).fetchone()[0]
            if a != b:
                raise sqlite3.DatabaseError(f"la copia no coincide en {table}: {a} filas en el original, {b} en la copia")
    finally:
        src.close()
        dst.close()
    os.replace(tmp, new_path)
    return "copiada"


def resolve_db_path() -> Path:
    """Ruta de la base de casos a usar. La nueva; si no se pudo copiar la antigua, sigue con la antigua (sin perder datos)."""
    new_path = data_dir() / DB_NAME
    try:
        if migrate_legacy_db(new_path) == "copiada":
            logger.info(f"Base de casos copiada a {new_path}. La original en {legacy_db_path()} NO se tocó: "
                        "bórrala cuando confirmes que todo está bien.")
    except (OSError, sqlite3.Error) as e:
        legacy = legacy_db_path()
        logger.error(f"No se pudo copiar la base de casos a {new_path} ({type(e).__name__}: {e}). "
                     f"Se sigue usando la original en {legacy}.")
        if legacy.exists() and not new_path.exists():
            return legacy
    return new_path


# ── Noticias y vulnerabilidades del módulo CTI ───────────────────────────────────────────────────────────────────────
# Antes se guardaban dentro del proyecto (sentinel_unified/modules/cti/store) y git las vigilaba como si fueran código:
# cada recolección ensuciaba el repositorio, un "git pull" chocaba con los datos de cada usuario y los dossiers por
# cliente viajaban con el código. Ahora van a la carpeta de datos del usuario, junto a la base de casos.
CTI_ITEMS = "items.jsonl"


def legacy_cti_store() -> Path:
    """Dónde guardaba las noticias CTI la versión anterior: dentro de la carpeta del proyecto."""
    return Path(__file__).resolve().parent.parent.parent / "sentinel_unified" / "modules" / "cti" / "store"


def legacy_cti_reports() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "sentinel_unified" / "modules" / "reports" / "cti-altel"


def cti_store_dir() -> Path:
    return data_dir() / "cti"


def cti_reports_dir() -> Path:
    """Boletines HTML generados a partir de los dossiers."""
    return cti_store_dir() / "boletines"


def active_cti_store() -> Path:
    """Carpeta CTI a usar: la nueva; la antigua solo si la nueva aún no tiene noticias (copia no hecha o fallida)."""
    new_dir = cti_store_dir()
    legacy = legacy_cti_store()
    if not (new_dir / CTI_ITEMS).exists() and (legacy / CTI_ITEMS).exists():
        return legacy
    return new_dir


def _copy_checked(src: Path, dst: Path) -> None:
    tmp = dst.with_name(dst.name + ".tmp")
    tmp.unlink(missing_ok=True)
    shutil.copy2(src, tmp)
    if tmp.stat().st_size != src.stat().st_size:
        tmp.unlink(missing_ok=True)
        raise OSError(f"la copia de {src.name} no tiene el mismo tamaño que el original")
    os.replace(tmp, dst)


def migrate_legacy_cti_store(new_dir: Optional[Path] = None, legacy: Optional[Path] = None,
                             legacy_reports: Optional[Path] = None) -> int:
    """Copia las noticias CTI antiguas (y sus boletines) a la carpeta nueva, una sola vez. Nunca borra ni mueve nada.

    Devuelve cuántos archivos copió (0 si no había nada que hacer). items.jsonl se copia el último: si existe en la
    carpeta nueva es que la copia terminó entera. Lanza OSError si falla (se sigue leyendo la carpeta antigua).
    """
    new_dir = Path(new_dir) if new_dir else cti_store_dir()
    legacy = Path(legacy) if legacy else legacy_cti_store()
    legacy_reports = Path(legacy_reports) if legacy_reports else legacy_cti_reports()
    if (new_dir / CTI_ITEMS).exists() or not (legacy / CTI_ITEMS).exists():
        return 0
    if legacy.resolve() == new_dir.resolve():
        return 0
    new_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    if legacy_reports.is_dir():
        reports = new_dir / "boletines"
        reports.mkdir(exist_ok=True)
        for src in legacy_reports.iterdir():
            if src.is_file() and not (reports / src.name).exists():
                _copy_checked(src, reports / src.name)
                copied += 1
    for src in sorted((f for f in legacy.iterdir() if f.is_file()), key=lambda f: f.name == CTI_ITEMS):
        if src.name.endswith(".tmp") or (new_dir / src.name).exists():
            continue
        _copy_checked(src, new_dir / src.name)
        copied += 1
    return copied


def prepare_cti_store() -> Path:
    """Al arrancar: copia las noticias antiguas si hace falta y devuelve la carpeta CTI que se va a usar."""
    try:
        copied = migrate_legacy_cti_store()
        if copied:
            logger.info(f"Noticias CTI copiadas a {cti_store_dir()} ({copied} archivos). La carpeta antigua "
                        f"{legacy_cti_store()} NO se tocó: bórrala cuando confirmes que todo está bien.")
    except OSError as e:
        logger.error(f"No se pudieron copiar las noticias CTI a {cti_store_dir()} ({type(e).__name__}: {e}). "
                     f"Se sigue usando {legacy_cti_store()}.")
    return active_cti_store()


# ── Fichas, informes y exportaciones: carpeta privada ────────────────────────────────────────────────────────────────
# Antes iban a Descargas: se acumulaban, cualquier otra cuenta de Windows del equipo podía leerlas y en algunos equipos
# Descargas se sincroniza con la nube. Llevan datos personales de terceros (LOPDP).
REPORTS_DIR_NAME = "informes"
_PRIVATE_MARK = ".carpeta_privada"
_disk_encryption_cache: dict = {}


def reports_dir() -> Path:
    return data_dir() / REPORTS_DIR_NAME


def make_private(path: Path) -> bool:
    """Deja `path` legible solo por la cuenta actual (y el sistema). True si quedó restringida.

    Windows: se quita la herencia de permisos y se da control total solo al usuario y a SYSTEM (icacls). Funciona
    también en Windows Home. Linux/Mac: permisos 700.
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if (path / _PRIVATE_MARK).exists():
        return True
    try:
        if sys.platform == "win32":
            import subprocess
            user = os.environ.get("USERNAME") or ""
            domain = os.environ.get("USERDOMAIN") or ""
            account = domain + "\\" + user if domain and user else user
            if not account:
                return False
            # Primero /reset: borra los permisos PROPIOS que ya tuviera la carpeta (visto en el Windows de GitHub:
            # "Administrators" y "OWNER RIGHTS" sobrevivían a /inheritance:r, que solo quita los heredados)
            for args in (["/reset"],
                         ["/inheritance:r", "/grant:r", f"{account}:(OI)(CI)F",
                          "/grant:r", "*S-1-5-18:(OI)(CI)F"]):         # S-1-5-18 = SYSTEM (copias, indexado)
                result = subprocess.run(["icacls", str(path), *args], capture_output=True, text=True, timeout=30,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                if result.returncode != 0:
                    logger.warning(f"No se pudo restringir {path}: {result.stdout.strip()} {result.stderr.strip()}")
                    return False
        else:
            os.chmod(path, 0o700)
        (path / _PRIVATE_MARK).write_text("Carpeta solo para tu usuario (la crea SENTINEL).\n", encoding="utf-8")
        return True
    except (OSError, ValueError) as e:
        logger.warning(f"No se pudo restringir {path}: {type(e).__name__}: {e}")
        return False


def private_reports_dir() -> Path:
    """Carpeta de informes, creada y restringida a tu usuario si aún no lo estaba."""
    folder = reports_dir()
    make_private(folder)
    return folder


def disk_encryption(path=None) -> str:
    """"on", "off" o "unknown": si la unidad donde están los datos tiene BitLocker / Cifrado de dispositivo.

    Se consulta sin permisos de administrador (propiedad System.Volume.BitLockerProtection del Explorador).
    En otros sistemas, "unknown".
    """
    if sys.platform != "win32":
        return "unknown"
    drive = (Path(path) if path else data_dir()).resolve().drive or "C:"
    if drive in _disk_encryption_cache:
        return _disk_encryption_cache[drive]
    state = "unknown"
    try:
        import subprocess
        script = (f"(New-Object -ComObject Shell.Application).NameSpace('{drive}" + "\\" + "').Self"
                  ".ExtendedProperty('System.Volume.BitLockerProtection')")
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                             capture_output=True, text=True, timeout=15,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.strip()
        # 1 protegido, 3 cifrando, 6 protegido y bloqueado; 2 sin cifrar, 4 descifrando, 5 suspendido
        state = {"1": "on", "3": "on", "6": "on", "2": "off", "4": "off", "5": "off"}.get(out, "unknown")
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    _disk_encryption_cache[drive] = state
    return state


def disk_encryption_warning(path=None) -> str:
    """Aviso para el usuario si el disco de los datos no está cifrado; "" si lo está o no se sabe."""
    if disk_encryption(path) != "off":
        return ""
    return ("Tu disco no está cifrado: si pierdes o te roban el equipo, los casos y fichas (datos personales) se "
            "podrían leer. Activa «Cifrado de dispositivo» o BitLocker en Configuración → Privacidad y seguridad.")
