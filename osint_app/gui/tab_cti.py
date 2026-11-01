"""
CTI Tab — Threat Intelligence integrado.
Recoleccion de feeds, dossiers por cliente, boletines HTML.
"""
import importlib.util
import os
import sys
import json
import subprocess
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTableWidget, QTableWidgetItem, QPlainTextEdit,
    QProgressBar, QFrame, QSplitter, QHeaderView, QMessageBox, QApplication
)
from PySide6.QtCore import Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices

from ..utils.data_paths import active_cti_store, cti_reports_dir
from ..cti_link import _truthy, normalize_cves


# Código del módulo CTI (los datos van aparte, en la carpeta del usuario: ver active_cti_store)
CTI_BASE = Path(__file__).parent.parent.parent / "sentinel_unified" / "modules" / "cti"


@lru_cache(maxsize=1)
def cti_products():
    """productos.py del módulo CTI (sin dependencias): la misma regla de producto que usa el boletín.

    Se carga desde su archivo para no meter la carpeta del CTI en la ruta de Python (sus scripts tienen nombres
    genéricos como clientes.py o fuentes.py).
    """
    spec = importlib.util.spec_from_file_location("sentinel_cti_productos", CTI_BASE / "productos.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def validation_lines(report: dict) -> list:
    """El resultado de validar.py en frases para el registro."""
    problems = report.get("problemas") or []
    lines = [f"   {report.get('noticias', 0)} noticia(s) revisada(s)."]
    for p in problems:
        where = " · ".join(x for x in (p.get("seccion"), p.get("titulo")) if x)
        lines.append(f"   ⚠️ {p.get('tipo', '').capitalize()}{' — ' + where if where else ''}: {p.get('detalle', '')}")
    lines.append("✅ Sin problemas: listo para enviar." if not problems else
                 f"Revisa {len(problems)} problema(s) antes de enviarlo al cliente.")
    return lines


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


# Secciones del boletín, en palabras (antes "items store: 7800 · items ventana: 110 · cves previas excluidas: 0")
SECTION_NAMES = {"amenaza_semana": "amenaza de la semana", "entorno_cliente": "de la infraestructura del cliente",
                 "seguridad_ecuador": "de Ecuador",
                 "noticias_principales": "noticias principales", "principales_cves": "vulnerabilidades (CVE)",
                 "alrededor_mundo": "del mundo", "referencias": "fuentes citadas"}


def dossier_summary_lines(data: dict) -> list:
    """Resumen del dossier para una persona no técnica."""
    totals = data.get("totales") or {}
    sections = data.get("secciones") or {}
    lines = [f"✅ Boletín preparado (periodo {data.get('semana', '?')})."]
    if totals:
        lines.append(f"   Se revisaron {totals.get('items_store', 0)} noticias guardadas: {totals.get('items_ventana', 0)} "
                     f"son de este periodo y {totals.get('explotados', 0)} hablan de vulnerabilidades explotadas.")
    if sections:
        lines.append("   Contenido: " + " · ".join(f"{v} {SECTION_NAMES.get(k, k.replace('_', ' '))}"
                                                  for k, v in sections.items()
                                                  if v or k != "entorno_cliente"))    # el GLOBAL no tiene cliente
    missing = []
    for note in data.get("brechas") or []:          # "Seguridad Ecuador: 1/3 candidatos."
        name, _, counts = str(note).partition(":")
        got, _, want = counts.strip().split(" ")[0].partition("/")
        missing.append(f"{name} ({got} de {want})" if want else str(note))
    if missing:
        lines.append("   ⚠ Hay pocas noticias para completar: " + ", ".join(missing) + ". El boletín sale igual, "
                     "más corto. Pulsa «Actualizar noticias» o genera el boletín más adelante.")
    lines.append("   Pulsa «Ver boletín» para verlo en el navegador.")
    return lines


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

            if result.returncode == 0:      # el resumen lo explica _on_dossier_done (antes se volcaba el JSON)
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
        self.combo_client.setToolTip("Para quién es el boletín. Con un cliente, se priorizan las noticias que afectan "
                                     "a sus tecnologías (su inventario) y cada una lo indica con «Relevante para su "
                                     "entorno». GLOBAL: boletín general, sin cliente.")
        header.addWidget(self.combo_client)

        layout.addLayout(header)

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
        self.btn_validate.setToolTip("Revisa el último boletín antes de enviarlo: frases cortadas, párrafos en inglés, "
                                     "productos dudosos o repetidos, noticias sin enlace, secciones vacías y que el de "
                                     "un cliente lo diga. No cambia el boletín: lo que encuentre sale en el registro.")
        actions.addWidget(self.btn_validate)

        self.btn_send = QPushButton("📧  Enviar")
        self.btn_send.setObjectName("btnSuccess")
        self.btn_send.clicked.connect(self._on_send)
        self.btn_send.setToolTip("Revisa el último boletín y lo prepara como correo nuevo en tu programa de correo, "
                                 "con los destinatarios del cliente. No envía nada: lo revisas y pulsas Enviar tú.")
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
        # El título ocupa lo que sobra; las demás columnas se pueden ensanchar con el ratón
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        for col, width in ((0, 150), (2, 150), (3, 90), (4, 180)):
            self.table.setColumnWidth(col, width)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        # Filas compactas y sin la columna de números (salía cortada): en un portátil maximizado (1536×864 a 125 %)
        # se veían solo 5 noticias (evaluación 4)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.setStyleSheet("QTableWidget::item { padding: 2px 8px; } QHeaderView::section { padding: 4px 8px; }")
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
        self.log_area.setMinimumHeight(40)   # cede su sitio a la tabla; el separador permite agrandarlo
        log_layout.addWidget(self.log_area)

        splitter.addWidget(log_frame)
        splitter.setStretchFactor(0, 5)     # antes la tabla dejaba ver solo 5 filas
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([600, 90])

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
        self.btn_validate.setEnabled(not busy)
        self.btn_send.setEnabled(not busy)
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
            for line in dossier_summary_lines(json.loads(output or "{}")):
                self._log(line)
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
        self._last_html = html_path
        self._log(f"✅ HTML generado: {html_path}")
        self.app.toast.show("Boletin HTML generado", kind="success")

        # Abrir en el navegador
        if html_path and Path(html_path).exists():
            import webbrowser
            webbrowser.open(Path(html_path).resolve().as_uri())
            self._log(f"Abierto en navegador: {html_path}")

    def _latest_bulletin(self):
        """El último boletín generado (el de esta sesión o, si no, el más reciente de la carpeta)."""
        last = getattr(self, "_last_html", "")
        if last and Path(last).exists():
            return Path(last)
        folder = cti_reports_dir()
        found = sorted(folder.glob("*.html"), key=lambda f: f.stat().st_mtime) if folder.exists() else []
        return found[-1] if found else None

    def _on_validate(self):
        """Revisa el último boletín con validar.py (antes: "funcionalidad en desarrollo")."""
        bulletin = self._latest_bulletin()
        if bulletin is None:
            self.app.toast.show("No hay boletín que revisar: genera el dossier y pulsa «Ver boletín»", kind="warning")
            return
        report = self._validate(bulletin)
        if report is None:
            return
        problems = len(report.get("problemas") or [])
        if problems:
            self.app.toast.show(f"Boletín revisado: {problems} problema(s), ver registro", kind="warning")
        else:
            self.app.toast.show("Boletín revisado: sin problemas", kind="success")

    def _validate(self, bulletin: Path):
        """Informe de validar.py del boletín (y sus líneas en el registro), o None si no se pudo revisar."""
        self._log(f"🔎 Revisando {bulletin.name}…")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            result = _run_cti_script(CTI_BASE, "validar.py", [str(bulletin)], timeout=60,
                                     store=active_cti_store(), reports=cti_reports_dir())
        finally:
            QApplication.restoreOverrideCursor()
        try:
            report = json.loads(result.stdout or "")
        except ValueError:
            self._log(f"❌ No se pudo revisar el boletín: {(result.stderr or result.stdout)[-300:]}")
            self.app.toast.show("No se pudo revisar el boletín (ver registro)", kind="error")
            return None
        for line in validation_lines(report):
            self._log(line)
        return report

    def _on_send(self):
        """Valida el último boletín y lo prepara como borrador de correo o para pegar (utils/mail_draft.py).

        No envía nada (decisión del 31-10-2026): SENTINEL lo usan empresas con correos distintos y no guarda
        contraseñas de correo; el analista revisa el borrador en su programa y pulsa Enviar.
        """
        bulletin = self._latest_bulletin()
        if bulletin is None:
            self.app.toast.show("No hay boletín que enviar: genera el dossier y pulsa «Ver boletín»", kind="warning")
            return
        report = self._validate(bulletin)
        problems = len((report or {}).get("problemas") or [])
        if report is None or problems:
            reason = (f"La revisión encontró {problems} problema(s) (están en el registro)." if report is not None
                      else "No se pudo revisar el boletín.")
            answer = QMessageBox.question(self, "¿Preparar el correo igualmente?",
                                          f"{reason}\n\n¿Quieres prepararlo igualmente?",
                                          QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
        from .send_dialog import SendDialog, copy_bulletin, open_draft
        dialog = SendDialog(self, bulletin)
        if dialog.exec() != SendDialog.Accepted:
            return
        if dialog.choice == "copy" or dialog.choice.startswith("web:"):
            copy_bulletin(bulletin.read_text(encoding="utf-8"))
            if dialog.choice.startswith("web:"):
                from ..utils.mail_draft import webmail_url
                QDesktopServices.openUrl(QUrl(webmail_url(dialog.choice[4:], dialog.addresses, dialog.subject)))
            self._log(f"📋 Boletín copiado: haz clic en el cuerpo del correo y pulsa Ctrl+V. Asunto: {dialog.subject}")
            self.app.toast.show("Boletín copiado: pégalo en el cuerpo del correo con Ctrl+V", kind="success")
            return
        try:
            mode = open_draft(bulletin, dialog.addresses)
        except OSError as e:
            self._log(f"❌ No se pudo abrir el correo: {e}")
            self.app.toast.show("No se pudo abrir el correo: usa «Copiar para pegar»", kind="error")
            return
        to = ", ".join(dialog.addresses) or "sin destinatarios"
        if mode == "mailto":
            self._log(f"📧 Correo nuevo abierto ({to}; asunto: {dialog.subject}). El boletín está copiado: haz clic "
                      f"en el cuerpo del correo y pulsa Ctrl+V. Revísalo y pulsa Enviar.")
            self.app.toast.show("Correo nuevo abierto: pega el boletín con Ctrl+V y pulsa Enviar", kind="success")
            return
        self._log(f"📧 Borrador abierto en tu programa de correo ({to}). Revísalo y pulsa Enviar. "
                  f"Archivo: {mode[4:]}")
        self.app.toast.show("Borrador abierto en tu programa de correo: revísalo y pulsa Enviar", kind="success")

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
        # Una noticia ("CISA Adds Two Known Exploited Vulnerabilities…") no trae la marca KEV ni el producto: se
        # sacan de sus CVE en el catálogo (antes salía en blanco y con la columna Producto vacía)
        exploited_cves = set()
        for it in items:
            if _truthy(it.get("kev")) or _truthy(it.get("exploited")):
                exploited_cves.update(normalize_cves(it.get("cves")))
        # El producto con la regla del boletín (evaluación 4): antes "Microsoft ipv4: free inet_opt…" en un fallo del
        # kernel de Linux, porque Microsoft también publica fallos de otros
        productos = cti_products()
        products = productos.catalog_products(items)
        shown = items[:self.MAX_ROWS]
        self.table.setRowCount(len(shown))
        for row, it in enumerate(shown):
            cves = normalize_cves(it.get("cves"))
            product = productos.item_product(it)
            product = product or ", ".join(dict.fromkeys(products[c] for c in cves if c in products))
            exploited = _truthy(it.get("kev")) or _truthy(it.get("exploited")) or any(c in exploited_cves for c in cves)
            values = (it.get("fuente", ""), it.get("titulo", ""), ", ".join(cves[:3]),
                      str(it.get("fecha") or "")[:10], product)
            for col, val in enumerate(values):
                cell = QTableWidgetItem(str(val))
                cell.setToolTip(str(it.get("resumen") or "")[:500] if col == 1 else str(val))
                if exploited:
                    cell.setForeground(QColor("#ff6b6b"))     # explotada activamente
                self.table.setItem(row, col, cell)
        latest = str(shown[0].get("fecha") or "")[:10] if shown else "—"
        self.lbl_items.setText(f"📰  Noticias y vulnerabilidades guardadas: {len(items)} (se muestran las "
                               f"{len(shown)} más recientes; la última es del {latest}; en rojo, explotadas activamente)")

    def refresh(self):
        """Refrescar tab (llamado por la app principal)"""
        self._load_items()
        self._items_loaded = True

    def showEvent(self, event):
        """La primera vez que se abre la pestaña se cargan las noticias. Antes la tabla salía vacía hasta cambiar de
        caso (evaluación de usuario, 14-10-2026); cargarlas al arrancar retrasaría la apertura del programa."""
        super().showEvent(event)
        if not getattr(self, "_items_loaded", False):
            self.refresh()
