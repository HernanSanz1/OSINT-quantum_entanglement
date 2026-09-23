"""
CTI Tab — Threat Intelligence integrado.
Recoleccion de feeds, dossiers por cliente, boletines HTML.
"""
import os
import json
import subprocess
import threading
from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTableWidget, QTableWidgetItem, QPlainTextEdit,
    QProgressBar, QFrame, QSplitter, QHeaderView, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor

from .components import SentinelModal


# Rutas del modulo CTI
CTI_BASE = Path(__file__).parent.parent.parent / "sentinel_unified" / "modules" / "cti"
CTI_STORE = Path(__file__).parent.parent / "data"


class HarvestThread(QThread):
    """Thread para ejecutar harvest.py"""
    progress = Signal(str)
    finished_ok = Signal(dict)
    error = Signal(str)

    def __init__(self, cti_path):
        super().__init__()
        self.cti_path = cti_path

    def run(self):
        try:
            harvest_py = self.cti_path / "harvest.py"
            if not harvest_py.exists():
                self.error.emit(f"No existe {harvest_py}")
                return

            self.progress.emit("Iniciando recoleccion de feeds CTI...")

            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.cti_path) + ":" + env.get("PYTHONPATH", "")
            result = subprocess.run(
                ["python3", str(harvest_py), "--dry-run"],
                capture_output=True,
                text=True,
                cwd=str(self.cti_path),
                env=env,
                timeout=120
            )

            if result.returncode == 0:
                self.progress.emit(result.stdout)
                self.finished_ok.emit({"output": result.stdout})
            else:
                self.error.emit(result.stderr or "Error desconocido")

        except subprocess.TimeoutExpired:
            self.error.emit("Timeout: la recoleccion tardo mas de 2 minutos")
        except Exception as e:
            self.error.emit(str(e))


class DossierThread(QThread):
    """Thread para ejecutar dossier.py"""
    progress = Signal(str)
    finished_ok = Signal(str)
    error = Signal(str)

    def __init__(self, cti_path, client="", fecha=""):
        super().__init__()
        self.cti_path = cti_path
        self.client = client
        self.fecha = fecha

    def run(self):
        try:
            dossier_py = self.cti_path / "dossier.py"
            if not dossier_py.exists():
                self.error.emit(f"No existe {dossier_py}")
                return

            self.progress.emit(f"Generando dossier{' para ' + self.client if self.client else ''}...")

            args = ["python3", str(dossier_py), "--resumen"]
            if self.client and self.client != "GLOBAL":
                args.extend(["--cliente", self.client])
            if self.fecha:
                args.extend(["--fecha", self.fecha])

            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.cti_path) + ":" + env.get("PYTHONPATH", "")
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                cwd=str(self.cti_path),
                env=env,
                timeout=180
            )

            if result.returncode == 0:
                self.progress.emit(result.stdout)
                self.finished_ok.emit(result.stdout)
            else:
                self.error.emit(result.stderr or "Error generando dossier")

        except subprocess.TimeoutExpired:
            self.error.emit("Timeout: el dossier tardo mas de 3 minutos")
        except Exception as e:
            self.error.emit(str(e))


class RenderThread(QThread):
    """Thread para ejecutar render.py y abrir el HTML"""
    progress = Signal(str)
    finished_ok = Signal(str)  # Emite la ruta del HTML generado
    error = Signal(str)

    def __init__(self, cti_path):
        super().__init__()
        self.cti_path = cti_path

    def run(self):
        try:
            render_py = self.cti_path / "render.py"
            if not render_py.exists():
                self.error.emit(f"No existe {render_py}")
                return

            self.progress.emit("Renderizando HTML del boletin...")

            env = os.environ.copy()
            env["PYTHONPATH"] = str(self.cti_path) + ":" + env.get("PYTHONPATH", "")
            result = subprocess.run(
                ["python3", str(render_py)],
                capture_output=True,
                text=True,
                cwd=str(self.cti_path),
                env=env,
                timeout=120
            )

            if result.returncode == 0:
                # El output es la ruta del HTML generado
                html_path = result.stdout.strip().split('\n')[0]
                self.progress.emit(f"HTML generado: {html_path}")
                self.finished_ok.emit(html_path)
            else:
                self.error.emit(result.stderr or "Error renderizando HTML")

        except subprocess.TimeoutExpired:
            self.error.emit("Timeout: el render tardo mas de 2 minutos")
        except Exception as e:
            self.error.emit(str(e))


class CTITab(QWidget):
    """Tab de Threat Intelligence"""

    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setObjectName("panelMain")
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # ── Header ─────────────────────────────────────────────────────────────
        header = QHBoxLayout()

        lbl_title = QLabel("🛡  THREAT INTELLIGENCE")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #00d4ff;")
        header.addWidget(lbl_title)

        header.addStretch()

        # Cliente selector
        lbl_client = QLabel("Cliente:")
        lbl_client.setStyleSheet("color: #8A9AA9;")
        header.addWidget(lbl_client)

        self.combo_client = QComboBox()
        self.combo_client.addItems(["GLOBAL", "CER", "MAVESA", "XTRIM", "SERVIANDINA"])
        self.combo_client.setMinimumWidth(150)
        header.addWidget(self.combo_client)

        layout.addLayout(header)

        # ── Actions Bar ────────────────────────────────────────────────────────
        actions = QHBoxLayout()

        self.btn_harvest = QPushButton("📡  Recolectar Feeds")
        self.btn_harvest.setObjectName("btnPrimary")
        self.btn_harvest.clicked.connect(self._on_harvest)
        actions.addWidget(self.btn_harvest)

        self.btn_dossier = QPushButton("📋  Generar Dossier")
        self.btn_dossier.clicked.connect(self._on_dossier)
        actions.addWidget(self.btn_dossier)

        self.btn_render = QPushButton("🎨  Render HTML")
        self.btn_render.clicked.connect(self._on_render)
        actions.addWidget(self.btn_render)

        actions.addStretch()

        self.btn_validate = QPushButton("✅  Validar")
        self.btn_validate.clicked.connect(self._on_validate)
        actions.addWidget(self.btn_validate)

        self.btn_send = QPushButton("📧  Enviar")
        self.btn_send.setObjectName("btnSuccess")
        self.btn_send.clicked.connect(self._on_send)
        actions.addWidget(self.btn_send)

        layout.addLayout(actions)

        # ── Progress Bar ───────────────────────────────────────────────────────
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.hide()
        layout.addWidget(self.progress)

        # ── Main Content Splitter ──────────────────────────────────────────────
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter, 1)

        # Items Table
        table_frame = QFrame()
        table_frame.setObjectName("panelInner")
        table_layout = QVBoxLayout(table_frame)
        table_layout.setContentsMargins(8, 8, 8, 8)

        lbl_items = QLabel("📰  Items CTI Recientes")
        lbl_items.setStyleSheet("font-weight: bold; color: #00d4ff;")
        table_layout.addWidget(lbl_items)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Fuente", "Titulo", "CVEs", "Fecha", "Tags"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        table_layout.addWidget(self.table)

        splitter.addWidget(table_frame)

        # Log Area
        log_frame = QFrame()
        log_frame.setObjectName("panelInner")
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(8, 8, 8, 8)

        lbl_log = QLabel("📋  Log de Operaciones")
        lbl_log.setStyleSheet("font-weight: bold; color: #00d4ff;")
        log_layout.addWidget(lbl_log)

        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet(
            "background-color: #0c111d; color: #00ff66; "
            "font-family: monospace; font-size: 11px;"
        )
        log_layout.addWidget(self.log_area)

        splitter.addWidget(log_frame)
        splitter.setSizes([400, 200])

        # Status
        self.lbl_status = QLabel("Estado: Listo")
        self.lbl_status.setStyleSheet("color: #00ff66;")
        layout.addWidget(self.lbl_status)

        # Check if CTI module exists
        self._check_cti_module()

    def _check_cti_module(self):
        """Verificar que el modulo CTI este disponible"""
        if not CTI_BASE.exists():
            self.log_area.appendPlainText(
                "⚠️  Modulo CTI no encontrado en sentinel_unified/modules/cti\n"
                "   Algunas funciones no estaran disponibles.\n"
            )
            self.btn_harvest.setEnabled(False)
            self.btn_dossier.setEnabled(False)
            self.btn_render.setEnabled(False)
        else:
            self.log_area.appendPlainText(
                f"✅  Modulo CTI encontrado: {CTI_BASE}\n"
                f"   Archivos disponibles:\n"
            )
            for f in CTI_BASE.glob("*.py"):
                self.log_area.appendPlainText(f"   - {f.name}")
            self.log_area.appendPlainText("")

    def _log(self, msg):
        """Agregar mensaje al log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.appendPlainText(f"[{timestamp}] {msg}")
        # Scroll to bottom
        vsb = self.log_area.verticalScrollBar()
        vsb.setValue(vsb.maximum())

    def _set_busy(self, busy):
        """Toggle estado de carga"""
        self.btn_harvest.setEnabled(not busy)
        self.btn_dossier.setEnabled(not busy)
        self.btn_render.setEnabled(not busy)
        if busy:
            self.progress.setRange(0, 0)
            self.progress.show()
            self.lbl_status.setText("Estado: Procesando...")
            self.lbl_status.setStyleSheet("color: #ffaa00;")
        else:
            self.progress.hide()
            self.lbl_status.setText("Estado: Listo")
            self.lbl_status.setStyleSheet("color: #00ff66;")

    # ── Actions ────────────────────────────────────────────────────────────────

    def _on_harvest(self):
        """Ejecutar harvest.py"""
        self._set_busy(True)
        self._log("Iniciando recoleccion de feeds...")

        self.harvest_thread = HarvestThread(CTI_BASE)
        self.harvest_thread.progress.connect(self._log)
        self.harvest_thread.finished_ok.connect(self._on_harvest_done)
        self.harvest_thread.error.connect(self._on_error)
        self.harvest_thread.start()

    def _on_harvest_done(self, result):
        self._set_busy(False)
        self._log("✅ Recoleccion completada")
        self.app.toast.show("Feeds CTI recolectados", kind="success")
        self._load_items()

    def _on_dossier(self):
        """Ejecutar dossier.py"""
        client = self.combo_client.currentText()
        self._set_busy(True)
        self._log(f"Generando dossier para {client}...")

        self.dossier_thread = DossierThread(CTI_BASE, client)
        self.dossier_thread.progress.connect(self._log)
        self.dossier_thread.finished_ok.connect(self._on_dossier_done)
        self.dossier_thread.error.connect(self._on_error)
        self.dossier_thread.start()

    def _on_dossier_done(self, output):
        self._set_busy(False)
        self._log("✅ Dossier generado")
        self._log(output)
        self.app.toast.show("Dossier CTI generado", kind="success")

    def _on_render(self):
        """Ejecutar render.py y abrir el HTML"""
        self._set_busy(True)
        self._log("Renderizando HTML del boletin...")

        self.render_thread = RenderThread(CTI_BASE)
        self.render_thread.progress.connect(self._log)
        self.render_thread.finished_ok.connect(self._on_render_done)
        self.render_thread.error.connect(self._on_error)
        self.render_thread.start()

    def _on_render_done(self, html_path):
        """Abrir el HTML generado en el navegador"""
        self._set_busy(False)
        self._log(f"✅ HTML generado: {html_path}")
        self.app.toast.show("Boletin HTML generado", kind="success")

        # Abrir en el navegador
        if html_path and Path(html_path).exists():
            import webbrowser
            webbrowser.open(f"file://{html_path}")
            self._log(f"Abierto en navegador: {html_path}")

    def _on_validate(self):
        """Ejecutar validar.py"""
        self._log("Validacion en desarrollo...")
        self.app.toast.show("Validacion: funcionalidad en desarrollo", kind="info")

    def _on_send(self):
        """Ejecutar mail_graph.py"""
        reply = QMessageBox.question(
            self, "Confirmar Envio",
            "Enviar boletin CTI por correo?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self._log("Envio por correo en desarrollo...")
            self.app.toast.show("Envio: funcionalidad en desarrollo", kind="info")

    def _on_error(self, error_msg):
        self._set_busy(False)
        self._log(f"❌ Error: {error_msg}")
        self.app.toast.show(f"Error CTI: {error_msg[:50]}...", kind="error")

    def _load_items(self):
        """Cargar items CTI en la tabla"""
        # Por ahora placeholder - luego cargar de items.jsonl
        self.table.setRowCount(0)
        self._log("Carga de items en desarrollo...")

    def refresh(self):
        """Refrescar tab (llamado por la app principal)"""
        self._load_items()
