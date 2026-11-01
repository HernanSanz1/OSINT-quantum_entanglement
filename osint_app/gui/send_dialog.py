"""Ventana del botón «📧 Enviar» de la pestaña CTI: a quién va el boletín y cómo sale (ver utils/mail_draft.py).

SENTINEL no envía nada: abre un borrador en el programa de correo del analista o copia el boletín para pegarlo.
"""
import os
from pathlib import Path

from PySide6.QtCore import QMimeData, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QHBoxLayout, QLabel, QLineEdit, QMenu,
                               QMessageBox, QPushButton, QVBoxLayout)

from ..utils import mail_draft


def open_draft(bulletin: Path, to: list) -> str:
    """Abre el boletín como correo nuevo. Devuelve "eml:<ruta>" o "mailto" según cómo se abrió.

    Con un programa para los .eml (Outlook clásico, Correo de Windows, Thunderbird), borrador completo. Sin él (solo
    el Outlook nuevo o correo web), correo nuevo con destinatarios y asunto, y el boletín copiado para pegarlo.
    """
    if mail_draft.eml_handler():
        draft = mail_draft.write_draft(bulletin, to)
        os.startfile(str(draft))              # noqa: S606 — archivo propio, recién escrito
        return f"eml:{draft}"
    copy_bulletin(Path(bulletin).read_text(encoding="utf-8"))
    if not QDesktopServices.openUrl(QUrl(mail_draft.mailto_url(to, mail_draft.bulletin_subject(bulletin)))):
        raise OSError("no hay ningún programa de correo para los enlaces mailto:")
    return "mailto"


def copy_bulletin(page: str) -> None:
    """Copia el boletín con formato (y en texto, para donde no se admita) al portapapeles."""
    mime = QMimeData()
    mime.setHtml(mail_draft.email_html(page))
    mime.setText(mail_draft.plain_text(page))
    QApplication.clipboard().setMimeData(mime)


class SendDialog(QDialog):
    """Destinatarios del cliente (rellenos con los recordados) y dos salidas: borrador o copiar."""

    def __init__(self, parent, bulletin: Path):
        super().__init__(parent)
        self.bulletin = Path(bulletin)
        self.client = mail_draft.bulletin_client(self.bulletin)
        self.subject = mail_draft.bulletin_subject(self.bulletin)
        self.choice = ""
        self.addresses = []
        self.setWindowTitle("Enviar el boletín por correo")
        self.setMinimumWidth(560)

        layout = QVBoxLayout(self)
        info = QLabel(f"<b>Boletín:</b> {self.bulletin.name}<br><b>Cliente:</b> {self.client}<br>"
                      f"<b>Asunto:</b> {self.subject}")
        layout.addWidget(info)
        layout.addWidget(QLabel("Para (separa las direcciones con comas):"))
        self.input_to = QLineEdit(", ".join(mail_draft.load_recipients().get(self.client, [])))
        self.input_to.setPlaceholderText("soc@cliente.com, seguridad@cliente.com")
        layout.addWidget(self.input_to)
        self.check_remember = QCheckBox(f"Recordar estas direcciones para {self.client}")
        self.check_remember.setChecked(True)
        layout.addWidget(self.check_remember)
        how = ("se abre como correo nuevo en tu programa de correo" if mail_draft.eml_handler() else
               "se abre un correo nuevo con los destinatarios y el asunto, y el boletín queda copiado: pégalo en el "
               "cuerpo con Ctrl+V")
        note = QLabel(f"SENTINEL no envía nada. «Abrir borrador»: {how}. Lo revisas y pulsas Enviar.<br>"
                      "¿Usas el correo en el navegador? «Copiar para pegar» abre Gmail u Outlook web con los "
                      "destinatarios y el asunto; pega el boletín con Ctrl+V.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #8A9AA9;")
        layout.addWidget(note)

        buttons = QHBoxLayout()
        self.btn_draft = QPushButton("📧  Abrir borrador")
        self.btn_draft.setObjectName("btnPrimary")
        self.btn_draft.clicked.connect(lambda: self._finish("draft"))
        # Copiar y, si se quiere, abrir el correo web con destinatarios y asunto ya puestos
        self.btn_copy = QPushButton("📋  Copiar para pegar ▾")
        copy_menu = QMenu(self.btn_copy)
        for service, (label, _url) in mail_draft.WEBMAIL.items():
            copy_menu.addAction(f"Copiar y abrir {label}", lambda s=service: self._finish(f"web:{s}"))
        copy_menu.addAction("Solo copiar", lambda: self._finish("copy"))
        self.btn_copy.setMenu(copy_menu)
        btn_cancel = QPushButton("Cancelar")
        btn_cancel.clicked.connect(self.reject)
        buttons.addWidget(self.btn_draft)
        buttons.addWidget(self.btn_copy)
        buttons.addStretch()
        buttons.addWidget(btn_cancel)
        layout.addLayout(buttons)

    def _finish(self, choice: str):
        valid, invalid = mail_draft.parse_addresses(self.input_to.text())
        if invalid:
            QMessageBox.warning(self, "Direcciones no válidas", "Revisa estas direcciones: " + ", ".join(invalid))
            return
        # Un boletín de un cliente no debe llegar a otro: avisar si alguna dirección está guardada para otro cliente
        crossed = mail_draft.other_client_addresses(self.client, valid)
        if crossed:
            detail = "\n".join(f"• {address} (de {other})" for address, other in crossed.items())
            answer = QMessageBox.question(
                self, "¿Destinatario de otro cliente?",
                f"Este es el boletín de {self.client}, pero estas direcciones están guardadas para otro cliente:\n\n"
                f"{detail}\n\n¿Seguro que quieres usarlas?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
        if self.check_remember.isChecked():
            mail_draft.save_recipients(self.client, valid)
        self.addresses, self.choice = valid, choice
        self.accept()
