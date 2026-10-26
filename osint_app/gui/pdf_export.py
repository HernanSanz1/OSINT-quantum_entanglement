"""Guardar una página HTML como PDF con el motor web de Qt (Chromium): la ficha sale igual que en el navegador.

Viene con PySide6 (QtWebEngine), así que no hay que instalar nada ni depender de un navegador concreto.
"""
from typing import Callable

from PySide6.QtCore import QMarginsF, QUrl
from PySide6.QtGui import QPageLayout, QPageSize
from PySide6.QtWebEngineCore import QWebEnginePage


def save_html_as_pdf(html: str, path: str, on_done: Callable[[bool, str], None], parent=None) -> QWebEnginePage:
    """Carga `html` y lo imprime en `path` (A4). Es asíncrono: al terminar llama a on_done(éxito, ruta).

    Devuelve la página: quien llama debe guardar la referencia hasta on_done (si no, Python la libera antes).
    """
    page = QWebEnginePage(parent)
    layout = QPageLayout(QPageSize(QPageSize.A4), QPageLayout.Portrait, QMarginsF(12, 12, 12, 12),
                         QPageLayout.Millimeter)

    def loaded(ok: bool):
        if ok:
            page.printToPdf(path, layout)
        else:
            on_done(False, path)

    def finished(file_path: str, success: bool):
        on_done(success, file_path)
        page.deleteLater()

    page.loadFinished.connect(loaded)
    page.pdfPrintingFinished.connect(finished)
    page.setHtml(html, QUrl("about:blank"))          # sin dirección base: la ficha no carga nada de internet
    return page
