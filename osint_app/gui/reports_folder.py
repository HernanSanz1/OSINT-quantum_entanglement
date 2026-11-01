"""Dónde guarda la interfaz las fichas, informes y exportaciones: la carpeta privada de informes.

Antes iban a Descargas (legibles por cualquier cuenta del equipo y, a veces, sincronizadas con la nube). Llevan datos
personales de terceros (LOPDP).
"""
import logging
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices

from ..utils.data_paths import disk_encryption_warning, private_reports_dir, synced_warning

logger = logging.getLogger(__name__)
_warned = False


def reports_folder(app=None) -> Path:
    """La carpeta privada de informes. La primera vez de la sesión avisa si el disco no está cifrado o se sincroniza."""
    global _warned
    folder = private_reports_dir()
    if not _warned:
        _warned = True
        message = disk_encryption_warning(folder) or synced_warning(folder)
        if message:
            logger.warning(message)
            if app is not None and hasattr(app, "toast"):
                app.toast.show(message, kind="warning")
    return folder


def open_reports_folder() -> Path:
    """Abre la carpeta de informes en el Explorador."""
    folder = private_reports_dir()
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))
    return folder


def show_in_folder(path) -> None:
    """Abre en el Explorador la carpeta del archivo, con el archivo ya seleccionado."""
    path = Path(path)
    if sys.platform == "win32" and path.exists():
        subprocess.Popen(["explorer", f"/select,{path}"])
    else:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))


def saved_message(path, what: str) -> tuple:
    """(texto, tipo) del aviso tras guardar. La carpeta de informes está oculta (AppData): el aviso dice dónde quedó
    el archivo (evaluación 4: «no encontraba las fichas»). Si se eligió una carpeta que va a la nube, lo advierte."""
    path = Path(path)
    if synced_warning(path.parent):
        return f"{what} guardada en {path.name}, pero esa carpeta se sube a la nube (datos personales)", "warning"
    private = path.parent.resolve() == private_reports_dir().resolve()
    place = "tu carpeta privada de informes" if private else str(path.parent)
    return f"{what} guardada en {place}", "success"


def announce_saved(app, path, what: str) -> None:
    """Aviso con el botón «📂 Abrir carpeta», que muestra el archivo en el Explorador."""
    text, kind = saved_message(path, what)
    app.toast.show(text, kind=kind, action=("📂 Abrir carpeta", lambda: show_in_folder(path)))
