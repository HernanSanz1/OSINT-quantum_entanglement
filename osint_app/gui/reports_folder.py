"""Dónde guarda la interfaz las fichas, informes y exportaciones: la carpeta privada de informes.

Antes iban a Descargas (legibles por cualquier cuenta del equipo y, a veces, sincronizadas con la nube). Llevan datos
personales de terceros (LOPDP).
"""
import logging
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
