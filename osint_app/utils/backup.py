"""Copias de seguridad de los datos de SENTINEL: casos, informes y noticias CTI en un solo .zip.

Antes nada se respaldaba: la carpeta de datos (%LOCALAPPDATA%\\SENTINEL) no entra en las copias de OneDrive y un
disco dañado, una base corrupta o un caso borrado por error se perdían sin remedio.

- Copia automática: una al día al abrir SENTINEL, en <datos>/copias (solo tu usuario), se guardan las 7 últimas.
- Copia manual: botón «Copia de seguridad…» de la pestaña Casos o `--backup CARPETA`, donde elijas (un USB, otro
  disco).
- Restaurar: `--restore ARCHIVO.zip` con SENTINEL cerrado; antes guarda una copia del estado actual.

Las claves de API NO van en la copia: están cifradas para tu usuario de Windows y se vuelven a guardar a mano.
"""
import datetime
import logging
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from typing import List, Optional

from .data_paths import DB_NAME, data_dir, make_private

logger = logging.getLogger(__name__)

AUTO_KEEP = 7
AUTO_EVERY = datetime.timedelta(hours=24)
FOLDERS = ("informes", "cti")                    # además de la base de casos
_SKIP_NAMES = {".carpeta_privada"}               # la marca de carpeta privada no debe viajar a otro equipo
PREFIX = "SENTINEL_copia_"
README = """Copia de seguridad de SENTINEL ({when})

Contiene: la base de casos ({db}), los informes y fichas (informes/) y las noticias y boletines CTI (cti/).
Tiene DATOS PERSONALES de terceros: guárdala en un lugar seguro y trátala según la LOPDP.
No contiene las claves de API: vuelve a guardarlas en el equipo nuevo («🔑 Guardar clave» o --set-key).

Para restaurarla, con SENTINEL cerrado, en la carpeta del proyecto:
    env\\Scripts\\python.exe -m osint_app.main --restore "RUTA\\DE\\ESTE\\ARCHIVO.zip"
Antes de reemplazar nada se guarda una copia de lo que haya ahora.
"""


def backups_dir() -> Path:
    """Carpeta de las copias automáticas, solo para tu usuario."""
    folder = data_dir() / "copias"
    make_private(folder)
    return folder


def _db_path() -> Path:
    from ..db.feedback_db import DB_PATH
    return Path(DB_PATH)


def make_backup(dest_dir, db_path: Optional[Path] = None, now: Optional[datetime.datetime] = None,
                suffix: str = "") -> Path:
    """Crea la copia en `dest_dir` y devuelve la ruta del .zip.

    La base se copia con la API de copia de SQLite, que da un estado coherente aunque SENTINEL la esté usando. El zip
    se escribe con otro nombre y se renombra al final: una copia cortada a medias nunca parece buena.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    now = now or datetime.datetime.now()
    db_path = Path(db_path) if db_path else _db_path()
    target = dest / f"{PREFIX}{now.strftime('%Y%m%d_%H%M%S')}{suffix}.zip"
    partial = target.with_suffix(".zip.parcial")
    root = data_dir()
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / DB_NAME
        if db_path.exists():
            src, dst = sqlite3.connect(db_path), sqlite3.connect(snapshot)
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
        with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED) as zf:
            if snapshot.exists():
                zf.write(snapshot, DB_NAME)
            for folder in FOLDERS:
                base = root / folder
                for path in sorted(base.rglob("*")) if base.is_dir() else []:
                    if path.is_file() and path.name not in _SKIP_NAMES:
                        zf.write(path, path.relative_to(root).as_posix())
            zf.writestr("LEEME.txt", README.format(when=now.strftime("%Y-%m-%d %H:%M"), db=DB_NAME))
    partial.replace(target)
    return target


def _copies(folder: Path) -> List[Path]:
    return sorted(folder.glob(f"{PREFIX}*.zip"))


def backup_time(path: Path) -> datetime.datetime:
    """Cuándo se hizo una copia, según su nombre (SENTINEL_copia_20261031_110227…); si no, la fecha del archivo."""
    try:
        return datetime.datetime.strptime(path.name[len(PREFIX):len(PREFIX) + 15], "%Y%m%d_%H%M%S")
    except ValueError:
        return datetime.datetime.fromtimestamp(path.stat().st_mtime)


def last_auto_backup() -> Optional[Path]:
    copies = _copies(data_dir() / "copias")
    return copies[-1] if copies else None


def auto_backup(now: Optional[datetime.datetime] = None) -> Optional[Path]:
    """Copia diaria en <datos>/copias si la última tiene más de un día; conserva las AUTO_KEEP más recientes.

    None si no hacía falta. Nunca lanza excepción: una copia fallida no debe impedir abrir SENTINEL.
    """
    now = now or datetime.datetime.now()
    try:
        folder = backups_dir()
        for partial in folder.glob("*.zip.parcial"):     # copia cortada al cerrar SENTINEL a medias
            partial.unlink(missing_ok=True)
        copies = _copies(folder)
        if copies and now - backup_time(copies[-1]) < AUTO_EVERY:
            return None
        made = make_backup(folder, now=now)
        for old in _copies(folder)[:-AUTO_KEEP]:
            old.unlink(missing_ok=True)
        return made
    except Exception as e:                       # noqa: BLE001 — se registra y SENTINEL sigue
        logger.warning(f"No se pudo hacer la copia de seguridad automática: {type(e).__name__}: {e}")
        return None


def _safe_members(zf: zipfile.ZipFile) -> List[zipfile.ZipInfo]:
    """Solo lo que una copia de SENTINEL puede traer; nada fuera de la carpeta de datos ("../", rutas absolutas)."""
    allowed = []
    for info in zf.infolist():
        name = info.filename
        parts = Path(name).parts
        if info.is_dir() or name.startswith(("/", "\\")) or ".." in parts or ":" in name:
            continue
        if name == DB_NAME or (parts and parts[0] in FOLDERS):
            allowed.append(info)
    return allowed


def restore_backup(archive, now: Optional[datetime.datetime] = None) -> Path:
    """Restaura una copia sobre la carpeta de datos (con SENTINEL cerrado). Devuelve la copia del estado anterior.

    Antes de tocar nada guarda lo que hay ahora en <datos>/copias (sufijo "_antes_de_restaurar"). Si el zip no es
    una copia de SENTINEL (no trae la base de casos), no se toca nada.
    """
    archive = Path(archive)
    with zipfile.ZipFile(archive) as zf:
        members = _safe_members(zf)
        if not any(m.filename == DB_NAME for m in members):
            raise ValueError(f"{archive.name} no es una copia de SENTINEL (no trae {DB_NAME}).")
        with zf.open(DB_NAME) as fh, tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / DB_NAME
            probe.write_bytes(fh.read())
            conn = sqlite3.connect(probe)
            try:
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError(f"La base de casos de {archive.name} está dañada: no se restaura.")
            finally:
                conn.close()
        previous = make_backup(backups_dir(), now=now, suffix="_antes_de_restaurar")
        root = data_dir()
        for info in members:
            target = root / Path(info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src:
                target.write_bytes(src.read())
    make_private(root / "informes")
    return previous
