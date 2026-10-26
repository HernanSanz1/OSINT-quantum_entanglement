"""
CTI Tab — Threat Intelligence integrado.
Recoleccion de feeds, dossiers por cliente, boletines HTML.
"""
import os
import sys
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

from .components import DevNotice, SentinelModal
from ..utils.data_paths import active_cti_store, cti_reports_dir


# Código del módulo CTI (los datos van aparte, en la carpeta del usuario: ver active_cti_store)
CTI_BASE = Path(__file__).parent.parent.parent / "sentinel_unified" / "modules" / "cti"


def _run_cti_script(cti_path: Path, script: str, args: list, timeout: int,
                    store: Path = None, reports: Path = None) -> subprocess.CompletedProcess:
    """Ejecuta un script del módulo CTI con el mismo Python que SENTINEL.

    - sys.executable: "python3" no existe en Windows (abre la Microsoft Store).
    - os.pathsep: el separador de PYTHONPATH es ";" en Windows y ":" en Linux/Mac.
    - UTF-8 en ambos sentidos: los scripts imprimen acentos y emojis, y la
      consola de Windows (cp1252) no los admite.
    - store/reports: carpetas de datos fuera del proyecto (sin ellas, el script usa las de dentro).
    """
    env = os.environ.copy()
    if store:
        env["SENTINEL_CTI_STORE"] = str(store)
    if reports:
        env["SENTINEL_CTI_REPORTS"] = str(reports)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(cti_path), env.get("PYTHONPATH", "")) if p)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, str(cti_path / script), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(cti_path),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        env=env,
        timeout=timeout,
    )


class HarvestThread(QThread):
    """Thread para ejecutar harvest.py"""
    progress = Signal(str)
    finished_ok = Signal(dict)
    error = Signal(str)

    def __init__(self, cti_path, store=None):
        super().__init__()
        self.cti_path = cti_path
        self.store = Path(store) if store else cti_path / "store"

    def run(self):
        try:
            harvest_py = self.cti_path / "harvest.py"
            if not harvest_py.exists():
                self.error.emit(f"No existe {harvest_py}")
                return

            self.progress.emit("Descargando de las fuentes y guardando lo nuevo (tarda 1–3 minutos)...")

            # Antes iba en modo prueba (--dry-run) para no tocar archivos versionados dentro del proyecto;
            # ahora los datos están en la carpeta del usuario y se guardan de verdad.
            result = _run_cti_script(self.cti_path, "harvest.py", [], timeout=300, store=self.store)

            if result.returncode == 0:
                audit = {}
                try:
                    audit = json.loads((self.store / "harvest-run.json").read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    pass
                self.finished_ok.emit({"output": result.stdout, "audit": audit})
            else:
                self.error.emit(result.stderr or "Error desconocido")

        except subprocess.TimeoutExpired:
            self.error.emit("Timeout: la recolección tardó más de 5 minutos")
        except Exception as e:
            self.error.emit(str(e))


class DossierThread(QThread):
    """Thread para ejecutar dossier.py"""
    progress = Signal(str)
    finished_ok = Signal(str)
    error = Signal(str)

    def __init__(self, cti_path, client="", fecha="", store=None, reports=None):
        super().__init__()
        self.cti_path = cti_path
        self.store, self.reports = store, reports
        self.client = client
        self.fecha = fecha

    def run(self):
        try:
            dossier_py = self.cti_path / "dossier.py"
            if not dossier_py.exists():
                self.error.emit(f"No existe {dossier_py}")
                return

            self.progress.emit(f"Generando dossier{' para ' + self.client if self.client else ''}...")

            args = ["--resumen"]
            if self.client and self.client != "GLOBAL":
                args.extend(["--cliente", self.client])
            if self.fecha:
                args.extend(["--fecha", self.fecha])

            result = _run_cti_script(self.cti_path, "dossier.py", args, timeout=180,
                                     store=self.store, reports=self.reports)

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

    def __init__(self, cti_path, store=None, reports=None):
        super().__init__()
        self.cti_path = cti_path
        self.store = Path(store) if store else cti_path / "store"
        self.reports = reports

    def run(self):
        try:
            render_py = self.cti_path / "render.py"
            if not render_py.exists():
                self.error.emit(f"No existe {render_py}")
                return

            self.progress.emit("Renderizando HTML del boletin...")

            # render.py sin argumentos elige el dossier por orden alfabético, y
            # "dossier-2026-W39.json" va después de "dossier-2026-W39-CER.json":
            # renderizaba el global aunque acabaras de generar el de un cliente.
            # Se le pasa explícitamente el dossier generado más recientemente.
            dossiers = sorted(self.store.glob("dossier-*.json"),
                              key=lambda f: f.stat().st_mtime)
            if not dossiers:
                self.error.emit("No hay dossier para renderizar. Genera uno primero.")
                return
            self.progress.emit(f"Dossier: {dossiers[-1].name}")
            result = _run_cti_script(self.cti_path, "render.py", [str(dossiers[-1])], timeout=120,
                                     store=self.store, reports=self.reports)

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

        lbl_title = QLabel("🛡  INTELIGENCIA DE AMENAZAS (CTI)")
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
        layout.addWidget(DevNotice(
            "Validar y Enviar (correo) aún no están programados. Para cruzar estas amenazas con un caso, usa "
            "«Cruzar con CTI» en la pestaña Correlación."))

        # ── Actions Bar ────────────────────────────────────────────────────────
        actions = QHBoxLayout()

        self.btn_harvest = QPushButton("📡  Actualizar noticias")
        self.btn_harvest.setToolTip("Descarga noticias y vulnerabilidades nuevas de las fuentes públicas y las guarda "
                                    "en tu carpeta de datos (no en la del programa)")
        self.btn_harvest.setObjectName("btnPrimary")
        self.btn_harvest.clicked.connect(self._on_harvest)
        actions.addWidget(self.btn_harvest)

        self.btn_dossier = QPushButton("📋  Generar Dossier")
        self.btn_dossier.setToolTip("Resume las amenazas de la semana, priorizadas para el cliente elegido")
        self.btn_dossier.clicked.connect(self._on_dossier)
        actions.addWidget(self.btn_dossier)

        self.btn_render = QPushButton("🎨  Ver boletín")
        self.btn_render.setToolTip("Crea el boletín del último dossier y lo abre en el navegador")
        self.btn_render.clicked.connect(self._on_render)
        actions.addWidget(self.btn_render)

        actions.addStretch()

        self.btn_validate = QPushButton("✅  Validar")
        self.btn_validate.clicked.connect(self._on_validate)
        self.btn_validate.setEnabled(False)          # sin programar: antes solo decía "en desarrollo" al pulsarlo
        self.btn_validate.setToolTip("En desarrollo")
        actions.addWidget(self.btn_validate)

        self.btn_send = QPushButton("📧  Enviar")
        self.btn_send.setObjectName("btnSuccess")
        self.btn_send.clicked.connect(self._on_send)
        self.btn_send.setEnabled(False)
        self.btn_send.setToolTip("En desarrollo: enviará el boletín por correo")
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

        self.lbl_items = QLabel("📰  Noticias y vulnerabilidades guardadas")
        self.lbl_items.setStyleSheet("font-weight: bold; color: #00d4ff;")
        table_layout.addWidget(self.lbl_items)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Fuente", "Título", "CVE", "Fecha", "Producto"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        table_layout.addWidget(self.table)

        splitter.addWidget(table_frame)

        # Log Area
        log_frame = QFrame()
        log_frame.setObjectName("panelInner")
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(8, 8, 8, 8)

        lbl_log = QLabel("📋  Registro")
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
            self.log_area.appendPlainText("✅  Módulo CTI listo.\n")

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
        self._log("Consultando las fuentes de inteligencia de amenazas...")

        self.harvest_thread = HarvestThread(CTI_BASE, store=active_cti_store())
        self.harvest_thread.progress.connect(self._log)
        self.harvest_thread.finished_ok.connect(self._on_harvest_done)
        self.harvest_thread.error.connect(self._on_error)
        self.harvest_thread.start()

    def _on_harvest_done(self, result):
        self._set_busy(False)
        audit = result.get("audit") or {}
        sources = audit.get("sources") or {}
        if audit.get("finished"):
            self._log(f"✅ {len(sources)} fuentes consultadas: {audit.get('total_leidos', 0)} noticias y "
                      f"vulnerabilidades leídas, {audit.get('total_nuevos', 0)} nuevas guardadas.")
            empty = [name for name, st in sources.items() if not st.get("leidos")]
            if empty:
                self._log("   Sin resultados esta vez: " + ", ".join(empty))
            for err in audit.get("errors") or []:
                self._log(f"   ⚠️ {err.get('fuente')}: no respondió ({str(err.get('error'))[:120]})")
        else:
            self._log("✅ Recolección terminada")
        self.app.toast.show(f"Noticias CTI actualizadas: {audit.get('total_nuevos', 0)} nuevas", kind="success")
        self._load_items()

    def _on_dossier(self):
        """Ejecutar dossier.py"""
        client = self.combo_client.currentText()
        self._set_busy(True)
        self._log(f"Generando dossier para {client}...")

        self.dossier_thread = DossierThread(CTI_BASE, client, store=active_cti_store(), reports=cti_reports_dir())
        self.dossier_thread.progress.connect(self._log)
        self.dossier_thread.finished_ok.connect(self._on_dossier_done)
        self.dossier_thread.error.connect(self._on_error)
        self.dossier_thread.start()

    def _on_dossier_done(self, output):
        self._set_busy(False)
        # Antes se volcaba el JSON tal cual en el registro
        try:
            data = json.loads(output or "{}")
            self._log(f"✅ Dossier de la semana {data.get('semana', '?')} generado.")
            totals = data.get("totales") or {}
            if isinstance(totals, dict) and totals:
                self._log("   Totales: " + " · ".join(f"{k.replace('_', ' ')}: {v}" for k, v in totals.items()))
            sections = data.get("secciones") or {}
            if sections:
                self._log("   Secciones: " + " · ".join(f"{k.replace('_', ' ')}: {v}" for k, v in sections.items()))
            if data.get("brechas"):
                self._log(f"   Datos que faltan: {data['brechas']}")
            self._log("   Pulsa «Ver boletín» para verlo en el navegador.")
        except ValueError:
            self._log("✅ Dossier generado")
            self._log(output)
        self.app.toast.show("Dossier CTI generado", kind="success")

    def _on_render(self):
        """Ejecutar render.py y abrir el HTML"""
        self._set_busy(True)
        self._log("Renderizando HTML del boletin...")

        self.render_thread = RenderThread(CTI_BASE, store=active_cti_store(), reports=cti_reports_dir())
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
            webbrowser.open(Path(html_path).resolve().as_uri())
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

    MAX_ROWS = 300

    def _load_items(self):
        """Muestra las noticias y vulnerabilidades guardadas por el módulo CTI (las más recientes primero).

        Antes la tabla quedaba siempre vacía con el aviso "Carga de items en desarrollo".
        """
        self.table.setRowCount(0)
        items_file = active_cti_store() / "items.jsonl"
        if not items_file.exists():
            self.lbl_items.setText("📰  Noticias y vulnerabilidades guardadas: ninguna todavía")
            return
        items = []
        with items_file.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    items.append(json.loads(line))
                except ValueError:
                    continue
        items.sort(key=lambda it: str(it.get("fecha") or ""), reverse=True)
        shown = items[:self.MAX_ROWS]
        self.table.setRowCount(len(shown))
        for row, it in enumerate(shown):
            product = " ".join(str(it.get(k) or "") for k in ("vendor", "product")).strip()
            values = (it.get("fuente", ""), it.get("titulo", ""), ", ".join((it.get("cves") or [])[:3]),
                      str(it.get("fecha") or "")[:10], product)
            for col, val in enumerate(values):
                cell = QTableWidgetItem(str(val))
                if col == 1:
                    cell.setToolTip(str(it.get("resumen") or "")[:500])
                if it.get("kev") or it.get("exploited"):
                    cell.setForeground(QColor("#ff6b6b"))     # explotada activamente
                self.table.setItem(row, col, cell)
        latest = str(shown[0].get("fecha") or "")[:10] if shown else "—"
        self.lbl_items.setText(f"📰  Noticias y vulnerabilidades guardadas: {len(items)} (se muestran las "
                               f"{len(shown)} más recientes; la última es del {latest}; en rojo, explotadas activamente)")

    def refresh(self):
        """Refrescar tab (llamado por la app principal)"""
        self._load_items()
