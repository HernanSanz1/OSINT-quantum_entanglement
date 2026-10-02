"""Dónde se guardan los datos de los casos, y que no queden en una carpeta sincronizada con la nube.

Los casos contienen datos personales de terceros. Antes se guardaban dentro de la carpeta del proyecto, que en
muchos equipos está en OneDrive (sincroniza con la nube de Microsoft). Ahora van a una carpeta propia del usuario
del sistema (en Windows, %LOCALAPPDATA%\\SENTINEL). Se puede cambiar con la variable de entorno SENTINEL_DATA_DIR.
"""
import logging
import os
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
