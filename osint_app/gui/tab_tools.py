"""
Tools Tab — con diagnóstico completo por herramienta.

Botón "Verificar Tool":
  - Funciona SIN tener un caso abierto (solo para ver estado)
  - Muestra: ✅ listo / ⚠️ falta paquete / 🔑 falta API key / ❌ no instalado
  - Muestra el comando de instalación si aplica
  - Si el tool ESTÁ listo Y hay caso abierto → ejecuta la tool
"""
import threading
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem,
    QPlainTextEdit, QPushButton, QLabel, QProgressBar, QSplitter, QFrame,
    QLineEdit
)
from PySide6.QtCore import Qt, QTimer, QObject, Signal, QThread, QProcess, QProcessEnvironment
from ..core.models import SearchResult
from PySide6.QtGui import QColor, QTextCursor
from .components import SentinelModal


# ── Colores por estado ────────────────────────────────────────────────────────

class ToolRunnerThread(QThread):
    progress = Signal(str)
    success = Signal()
    error = Signal(str)
    
    def __init__(self, t_name, case_id, framework, parent=None, target_data_ids=None, extra_args=""):
        super().__init__(parent)
        self.t_name = t_name
        self.case_id = case_id
        self.framework = framework
        self.target_data_ids = target_data_ids
        self.extra_args = extra_args

    def run(self):
        try:
            self.progress.emit(f"🚀 Iniciando ejecución de {self.t_name}...")
            report = self.framework.run_tool(
                tool_name=self.t_name,
                case_id=self.case_id,
                progress_cb=self.progress.emit,
                target_data_ids=self.target_data_ids,
                extra_args=self.extra_args
            )
            self.success.emit()
        except Exception as e:
            self.error.emit(str(e))
_STATUS_COLORS = {
    "ready":             "#00ff66",   # verde
    "needs_key":         "#ffaa00",   # amarillo
    "not_installed":     "#ff3333",   # rojo (incluye tools Docker no levantadas)
    "python_pkg_missing": "#ffaa00",  # amarillo
}

_STATUS_LABELS = {
    "ready":             "LISTA",
    "needs_key":         "FALTA API KEY",
    "not_installed":     "NO INSTALADA / SERVIDOR APAGADO",
    "python_pkg_missing": "PAQUETE PYTHON FALTANTE",
}


class ToolsTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setObjectName("panelMain")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)

        # ── Left: Tools List ──────────────────────────────────────────────────
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("🛠  Herramientas disponibles"))

        self.list_tools = QListWidget()
        self.list_tools.itemSelectionChanged.connect(self._on_select)
        left_layout.addWidget(self.list_tools)
        splitter.addWidget(left_panel)

        # ── Right: Detail Panel ───────────────────────────────────────────────
        right_panel = QWidget()
        right_panel.setObjectName("panelInner")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setSpacing(8)

        # Tool name
        self.lbl_tool = QLabel("← Selecciona una herramienta")
        self.lbl_tool.setStyleSheet("font-size: 16px; font-weight: bold; color: #00d4ff;")
        right_layout.addWidget(self.lbl_tool)

        # Tool description
        self.lbl_desc = QLabel("")
        self.lbl_desc.setStyleSheet("color: #8A9AA9; font-size: 12px;")
        self.lbl_desc.setWordWrap(True)
        right_layout.addWidget(self.lbl_desc)

        # Status banner
        self.status_frame = QFrame()
        self.status_frame.setObjectName("panelInner")
        status_lay = QVBoxLayout(self.status_frame)
        status_lay.setContentsMargins(12, 8, 12, 8)

        self.lbl_status_icon = QLabel("")
        self.lbl_status_icon.setStyleSheet("font-size: 22px;")
        self.lbl_status_msg = QLabel("")
        self.lbl_status_msg.setWordWrap(True)
        self.lbl_status_msg.setStyleSheet("font-size: 12px; color: #E0E6ED;")

        status_lay.addWidget(self.lbl_status_icon)
        status_lay.addWidget(self.lbl_status_msg)
        right_layout.addWidget(self.status_frame)
        self.status_frame.hide()

        # Install command box (shown when install is needed)
        self.lbl_install_title = QLabel("📋  Comando de instalación:")
        self.lbl_install_title.setStyleSheet("color: #ffaa00; font-weight: bold; font-size: 12px;")
        right_layout.addWidget(self.lbl_install_title)
        self.lbl_install_title.hide()

        self.txt_install = QPlainTextEdit()
        self.txt_install.setReadOnly(True)
        self.txt_install.setFixedHeight(64)
        self.txt_install.setStyleSheet(
            "background-color: #0c111d; color: #00ff66; "
            "font-family: monospace; font-size: 12px; border-radius: 6px;"
        )
        right_layout.addWidget(self.txt_install)
        self.txt_install.hide()

        # Log area (execution output)
        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet(
            "background-color: #0c111d; color: #00ff66; font-family: monospace; font-size: 11px;"
        )
        right_layout.addWidget(self.log_area)

        # ── INTERACTIVE MINI SHELL ──
        shell_lay = QHBoxLayout()
        shell_lay.setContentsMargins(0, 4, 0, 4)
        
        lbl_prompt = QLabel(">_")
        lbl_prompt.setStyleSheet("color: #00ff66; font-weight: bold; font-family: monospace;")
        shell_lay.addWidget(lbl_prompt)
        
        self.txt_shell = QLineEdit()
        self.txt_shell.setPlaceholderText("Terminal Interactiva: Envía comandos a la tool (Ej: ghunt login)")
        self.txt_shell.setStyleSheet("background-color: #0c111d; color: #00ff66; font-family: monospace; border: 1px solid #1f2937; padding: 4px;")
        self.txt_shell.returnPressed.connect(self._on_shell_enter)
        shell_lay.addWidget(self.txt_shell)
        
        self.btn_shell_run = QPushButton("⚡ Enviar")
        self.btn_shell_run.setObjectName("btnPrimary")
        self.btn_shell_run.clicked.connect(self._on_shell_enter)
        shell_lay.addWidget(self.btn_shell_run)
        
        self.btn_shell_kill = QPushButton("🛑 Kill Shell")
        self.btn_shell_kill.setObjectName("btnReject")
        self.btn_shell_kill.clicked.connect(self._kill_shell)
        self.btn_shell_kill.hide()
        shell_lay.addWidget(self.btn_shell_kill)
        
        self.btn_shell_export = QPushButton("📥 Enviar a Reportes")
        self.btn_shell_export.setObjectName("btnGeneric")
        self.btn_shell_export.setToolTip("Guarda el log actual en la base de datos del caso")
        self.btn_shell_export.clicked.connect(self._export_shell_log)
        shell_lay.addWidget(self.btn_shell_export)
        
        right_layout.addLayout(shell_lay)
        self._shell_process = None

        # Progress bar
        self.prog_exec = QProgressBar()
        self.prog_exec.setTextVisible(False)
        self.prog_exec.hide()
        right_layout.addWidget(self.prog_exec)

        # Buttons row
        bot_lay = QHBoxLayout()
        bot_lay.addStretch()

        self.btn_guide = QPushButton("📖  Guía")
        self.btn_guide.setObjectName("btnVerify") # Usar estilo secundario
        self.btn_guide.setCursor(Qt.PointingHandCursor)
        self.btn_guide.clicked.connect(self._show_guide)
        self.btn_guide.setEnabled(False)
        bot_lay.addWidget(self.btn_guide)

        self.btn_check = QPushButton("🔍  Verificar Estado")
        self.btn_check.setObjectName("btnVerify")
        self.btn_check.setCursor(Qt.PointingHandCursor)
        self.btn_check.clicked.connect(self._verify_status)
        self.btn_check.setEnabled(False)
        bot_lay.addWidget(self.btn_check)

        self.btn_run = QPushButton("▶  Ejecutar Tool")
        self.btn_run.setObjectName("btnPrimary")
        self.btn_run.setCursor(Qt.PointingHandCursor)
        self.btn_run.clicked.connect(self._run_tool)
        self.btn_run.setEnabled(False)
        bot_lay.addWidget(self.btn_run)

        self.btn_stop = QPushButton("🛑  Detener")
        self.btn_stop.setObjectName("btnReject") # Rojo
        self.btn_stop.setCursor(Qt.PointingHandCursor)
        self.btn_stop.hide()
        bot_lay.addWidget(self.btn_stop)

        bot_lay.addStretch()
        right_layout.addLayout(bot_lay)

        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        self._running = False
        self.refresh()

    # ── Interactive Shell Methods ─────────────────────────────────────────────

    def _kill_shell(self):
        if self._shell_process and self._shell_process.state() == QProcess.Running:
            self._shell_process.kill()
            self._shell_process.waitForFinished()
        self.btn_shell_kill.hide()
        self._shell_process = None
        self.log_area.appendPlainText("\n[💀 Shell terminada por el usuario]")

    def _export_shell_log(self):
        if not self.app.active_case_id:
            SentinelModal.warning(self, "Sin caso activo", "Abre o crea un caso para guardar esta evidencia.")
            return
            
        text = self.log_area.toPlainText().strip()
        if not text:
            SentinelModal.warning(self, "Output vacío", "No hay datos en la consola para exportar.")
            return
            
        t_name = "Mini-Shell"
        item = self.list_tools.currentItem()
        if item:
            t_name = item.text()
            
        res = SearchResult(
            title=f"Evidencia Manual: {t_name}",
            url="",
            snippet=text,
            source_tool=f"{t_name} (Consola)",
            category="Reporte Manual",
            relevance_score=80
        )
        
        try:
            import json
            import datetime
            from ..db.feedback_db import db
            from ..core.models import ToolReport
            
            # Format the output as a valid JSON list of SearchResult so the rest of the app parses it correctly
            results_json = json.dumps([res.to_dict()])
            
            report = ToolReport(
                case_id=self.app.active_case_id,
                tool_name=t_name,
                raw_json=results_json,
                summary=f"Datos extraídos manualmente de {t_name}",
                status="success",
                execution_time=0.0,
                results_count=1,
                run_at=datetime.datetime.now().isoformat()
            )
            db.save_report(report)
            self.app._update_all_tabs()
            
            SentinelModal.success(self, "Exportado a Reportes", "El contenido de la terminal se anexó a los reportes del caso actual. La IA podrá analizarlo.")
        except Exception as e:
            SentinelModal.warning(self, "Error al Exportar", f"Error guardando evidencia: {e}")

    def _on_shell_enter(self):
        text = self.txt_shell.text().strip()
        if not text and not self._shell_process:
            return
            
        # If a process is running, feed it to stdin
        if self._shell_process and self._shell_process.state() == QProcess.Running:
            self.log_area.appendPlainText(f"> {text}")
            self._shell_process.write((text + "\n").encode("utf-8"))
            self.txt_shell.clear()
            return

        # Start a new process
        if not text: return
        
        # Act as a normal shell without background replacements
        self._shell_process = QProcess(self)
        self._shell_process.setProcessChannelMode(QProcess.MergedChannels)
        # Use Unbuffered so password prompts without newlines are flushed immediately

        # Inject the virtual environment's bin folder into the PATH
        import sys, os
        from pathlib import Path
        env = QProcessEnvironment.systemEnvironment()
        venv_bin = os.path.dirname(sys.executable)
        go_bin = str(Path.home() / "go/bin")
        current_path = env.value("PATH", "")
        
        path_components = current_path.split(os.pathsep)
        new_paths = []
        if venv_bin not in path_components:
            new_paths.append(venv_bin)
        if go_bin not in path_components:
            new_paths.append(go_bin)
            
        if new_paths:
            env.insert("PATH", f"{os.pathsep.join(new_paths)}{os.pathsep}{current_path}")
            
        # Inject Tor Proxy if globally enabled
        if getattr(self.app, "_use_tor_proxy", False):
            env.insert("ALL_PROXY", "socks5h://127.0.0.1:9050")
            env.insert("HTTP_PROXY", "socks5h://127.0.0.1:9050")
            env.insert("HTTPS_PROXY", "socks5h://127.0.0.1:9050")
            
        # Force Python scripts to flush stdout immediately instead of buffering
        env.insert("PYTHONUNBUFFERED", "1")
            
        self._shell_process.setProcessEnvironment(env)
        
        self.log_area.appendPlainText(f"\n$ {text}")
        
        def on_ready_read():
            try:
                data = self._shell_process.readAll().data()
                try:
                    msg = data.decode("utf-8")
                except:
                    msg = data.decode("latin1", errors="replace")
                
                # Avoid QPlainTextEdit.appendPlainText injecting extra newlines
                cursor = self.log_area.textCursor()
                cursor.movePosition(QTextCursor.End)
                cursor.insertText(msg)
                self.log_area.setTextCursor(cursor)
                self.log_area.ensureCursorVisible()
            except RuntimeError:
                pass # Widget was destroyed by the user closing the app

        def on_finish(exitCode, exitStatus):
            try:
                self.log_area.appendPlainText(f"\n[Proceso terminado con código {exitCode}]")
                if exitCode == 127:
                    item = self.list_tools.currentItem()
                    tool_hint = f"'{item.text()}'" if item else "la herramienta"
                    self.log_area.appendPlainText(
                        "⚠️ Comando no encontrado (Error 127) o dependencias de Go ausentes.\n"
                        f"👉 Consejo: Selecciona {tool_hint} en la lista de la izquierda y haz clic en 'Ejecutar' para autocompletar la ruta, o usa el botón 'Verificar Estado' para leer la Guía de Instalación."
                    )
                self.btn_shell_kill.hide()
                self._shell_process = None
            except RuntimeError:
                pass # Widget already destroyed
            
        self._shell_process.readyReadStandardOutput.connect(on_ready_read)
        self._shell_process.finished.connect(on_finish)
        
        self.btn_shell_kill.show()
        
        import platform
        if platform.system() == "Windows":
            self._shell_process.start("cmd.exe", ["/c", text])
        else:
            self._shell_process.start("bash", ["-c", text])


    # ── Populate list ─────────────────────────────────────────────────────────

    def refresh(self):
        self.list_tools.clear()
        for name, tool in self.app.framework.tools.items():
            if hasattr(tool, "check_available"):
                tool.check_available()
            item = QListWidgetItem()
            if tool.is_available:
                item.setText(f"✅  {name}")
                item.setForeground(QColor("#00ff66"))
            else:
                item.setText(f"❌  {name}")
                item.setForeground(QColor("#ff3333"))
            item.setData(Qt.UserRole, name)   # store clean name
            self.list_tools.addItem(item)

    # ── Selection changed ─────────────────────────────────────────────────────

    def _on_select(self):
        items = self.list_tools.selectedItems()
        if not items:
            self.btn_check.setEnabled(False)
            self.btn_run.setEnabled(False)
            self.btn_guide.setEnabled(False)
            return

        t_name = items[0].data(Qt.UserRole)
        tool = self.app.framework.tools.get(t_name)
        if not tool:
            return

        self.lbl_tool.setText(f"  {t_name}")
        self.lbl_desc.setText(tool.description)

        # Habilitar botones de información
        self.btn_check.setEnabled(True)
        self.btn_guide.setEnabled(True)

        # "Ejecutar" solo si tool lista Y hay caso abierto
        self.btn_run.setEnabled(
            tool.is_available and bool(self.app.active_case_id) and not self._running
        )

        # Actualizar placeholder del mini-shell para guiar al usuario
        # Fill input with the actual command path so it works like a normal shell
        binary_map = {
            "TheHarvester": "theHarvester",
            "Subfinder": "subfinder",
            "Amass": "amass",
            "SpiderFoot": "python3 /Users/gabysanz/Downloads/IAprototipe/spiderfoot/sf.py",
            "Recon-ng": "recon-ng",
            "Sherlock": "sherlock",
            "GHunt": "ghunt",
            "Instaloader": "instaloader",
            "Maigret": "maigret",
            "CENSYS": "censys",
            "Hunter.io": "hunter",
            "OpenCTI": "opencti",
            "MISP": "misp",
            "Cortex": "cortex",
            "IntelMQ": "intelmq",
            "IntelOwn": "intelown",
        }
        cmd_prefix = binary_map.get(t_name)
        if cmd_prefix:
            import shutil
            import sys
            import shlex
            from pathlib import Path
            parts = shlex.split(cmd_prefix)
            if len(parts) > 1 or Path(cmd_prefix).exists():
                # Leave complex commands or explicit absolute paths alone
                abs_path = cmd_prefix
            else:
                abs_path = shutil.which(cmd_prefix) or shutil.which(cmd_prefix.lower())
                if not abs_path:
                    # Check for Go-based tools in the default Go bin directory
                    go_path = Path.home() / f"go/bin/{cmd_prefix}"
                    if go_path.exists():
                        abs_path = str(go_path.absolute())
                    else:
                        local_pth = Path(f"{cmd_prefix}/{cmd_prefix}.py")
                        if local_pth.exists():
                            abs_path = f"{sys.executable} {local_pth.absolute()}"
                        else:
                            abs_path = f"{sys.executable} -m {cmd_prefix}"
            self.txt_shell.setText(f"{abs_path} ")
            self.txt_shell.setPlaceholderText(f"Esperando comando...")
        else:
            self.txt_shell.clear()
            self.txt_shell.setPlaceholderText("Comando interactivo libre...")

        # Clear previous status
        self.status_frame.hide()
        self.lbl_install_title.hide()
        self.txt_install.hide()
        self.log_area.clear()

    # ── Verify status (no case needed) ────────────────────────────────────────

    def _verify_status(self):
        items = self.list_tools.selectedItems()
        if not items:
            return

        t_name = items[0].data(Qt.UserRole)
        tool = self.app.framework.tools.get(t_name)
        if not tool:
            return

        self.log_area.clear()
        diag = tool.diagnose_status()

        status   = diag["status"]
        icon     = diag["icon"]
        message  = diag["message"]
        inst_cmd = diag["install_cmd"]
        color    = _STATUS_COLORS.get(status, "#E0E6ED")

        # Update status banner
        self.lbl_status_icon.setText(icon)
        self.lbl_status_msg.setText(message)
        self.lbl_status_msg.setStyleSheet(f"font-size: 12px; color: {color};")
        self.status_frame.show()

        # Show install command if needed
        if inst_cmd:
            self.lbl_install_title.show()
            self.txt_install.setPlainText(inst_cmd)
            self.txt_install.show()
        else:
            self.lbl_install_title.hide()
            self.txt_install.hide()

        # Log full diagnostic
        self.log_area.appendPlainText(f"{'─'*50}")
        self.log_area.appendPlainText(f"DIAGNÓSTICO: {t_name}")
        self.log_area.appendPlainText(f"Estado : {icon} {status}")
        self.log_area.appendPlainText(f"Mensaje: {message}")
        if inst_cmd:
            self.log_area.appendPlainText(f"\nCOMO INSTALAR:\n{inst_cmd}")
        if status == "ready":
            if not self.app.active_case_id:
                self.log_area.appendPlainText(
                    "\n⚠️  Herramienta lista — abre un caso para poder ejecutarla."
                )
            else:
                self.log_area.appendPlainText("\n✅  Lista para ejecutar. Presiona ▶ Ejecutar Tool.")
        self.log_area.appendPlainText(f"{'─'*50}")

        # Update run button state after diagnosis
        self.btn_run.setEnabled(
            status == "ready" and bool(self.app.active_case_id) and not self._running
        )

    # ── Show tool guide ───────────────────────────────────────────────────────

    def _show_guide(self):
        items = self.list_tools.selectedItems()
        if not items:
            return
            
        t_name = items[0].data(Qt.UserRole)
        tool = self.app.framework.tools.get(t_name)
        if not tool:
            return
            
        modal = SentinelModal(self.window(), f"Guía: {t_name}", 500, 400)
        lay = QVBoxLayout(modal.content)
        lay.setSpacing(10)
        
        # Backend Description
        lbl_desc = QLabel(f"<b>Operación Backend:</b><br>{tool.description}")
        lbl_desc.setWordWrap(True)
        lay.addWidget(lbl_desc)
        
        reqs = tool.requirements
        
        # Mandatory
        mand_str = ", ".join(reqs.mandatory) if reqs.mandatory else "Ninguno"
        lbl_mand = QLabel(f"<span style='color: #ff3333;'><b>Requisitos Obligatorios:</b></span> {mand_str}")
        lbl_mand.setWordWrap(True)
        lay.addWidget(lbl_mand)
        
        # Optional
        opt_str = ", ".join(reqs.optional) if reqs.optional else "Ninguno"
        lbl_opt = QLabel(f"<span style='color: #ffaa00;'><b>Mejoradores (Opcionales):</b></span> {opt_str}")
        lbl_opt.setWordWrap(True)
        lay.addWidget(lbl_opt)
        
        # Produces
        prod_str = ", ".join(reqs.produces) if reqs.produces else "Datos crudos"
        lbl_prod = QLabel(f"<span style='color: #00ff66;'><b>Datos Descubiertos:</b></span> {prod_str}")
        lbl_prod.setWordWrap(True)
        lay.addWidget(lbl_prod)
        
        # Hint/Advice
        if reqs.hint:
            lbl_hint = QLabel(f"<br><b>💡 Consejo de uso:</b><br><i>{reqs.hint}</i>")
            lbl_hint.setWordWrap(True)
            lbl_hint.setStyleSheet("color: #8A9AA9;")
            lay.addWidget(lbl_hint)
            
        modal.add_button("Cerrar", modal.accept, variant="primary")
        modal.exec()

    # ── Execute tool ──────────────────────────────────────────────────────────

    def _run_tool(self):
        if not self.app.active_case_id:
            self.app.toast.show("Abre un caso primero", kind="warning")
            return

        items = self.list_tools.selectedItems()
        if not items:
            return
        t_name = items[0].data(Qt.UserRole)
        tool = self.app.framework.tools.get(t_name)

        def _execute(selected_ids, extra_args=""):
            self._running = True
            self.btn_run.setEnabled(False)
            self.btn_check.setEnabled(False)
            self.prog_exec.show()
            self.prog_exec.setRange(0, 0)
            self.log_area.clear()
            self.app.set_status(f"⚙ Ejecutando {t_name}…", "warning")

            thread = ToolRunnerThread(t_name, self.app.active_case_id, self.app.framework, self, selected_ids, extra_args)
            self._current_thread = thread # Keep reference

            def _on_progress(msg):
                self.log_area.appendPlainText(msg)
                vsb = self.log_area.verticalScrollBar()
                vsb.setValue(vsb.maximum())

            def _on_success():
                self.prog_exec.setRange(0, 100)
                self.prog_exec.setValue(100)
                self.app.set_status(f"✔ Ejecutado {t_name}", "success")
                if not getattr(tool, "_is_cancelled", False):
                    self.app.toast.show(f"{t_name} finalizado", kind="success")
                
                # Auto-refresh Reports and AI tabs to reflect new data
                for page_name, widget in self.app.pages:
                    if page_name in ("Reportes", "Correlational Intelligence IA"):
                        if hasattr(widget, "refresh"):
                            widget.refresh()

            def _on_error(err_msg):
                self.app.toast.show(f"Error: {err_msg}", kind="error")
                self.log_area.appendPlainText(f"❌ Error: {err_msg}")

            def _on_finish():
                if hasattr(tool, "_is_cancelled"):
                    tool._is_cancelled = False
                self._running = False
                self.btn_run.show()
                self.btn_stop.hide()
                self.btn_run.setEnabled(True)
                self.btn_check.setEnabled(True)
                self.prog_exec.hide()

            thread.progress.connect(_on_progress)
            thread.success.connect(_on_success)
            thread.error.connect(_on_error)
            thread.finished.connect(_on_finish)

            # Start thread and toggle UI
            self.btn_run.hide()
            self.btn_stop.show()
            self.btn_stop.setEnabled(True)
            
            # Disconnect old signals from btn_stop just in case
            try:
                self.btn_stop.clicked.disconnect()
            except Exception:
                pass
            self.btn_stop.clicked.connect(lambda: [
                tool.stop(),
                self.btn_stop.setEnabled(False),
                self.btn_stop.setText("Deteniendo...")
            ])

            thread.start()

        def _show_data_selection():
            from ..db.feedback_db import db
            from PySide6.QtWidgets import QCheckBox, QScrollArea, QWidget, QVBoxLayout, QLineEdit
            target_data = db.get_target_data(self.app.active_case_id)
            if not target_data:
                self.app.toast.show("El caso no tiene datos para analizar.", kind="warning")
                return
                
            modal = SentinelModal(self.app, f"Ejecutar {t_name}", 450, 400)
            modal_layout = QVBoxLayout(modal.content)
            
            # --- SECCION DATOS ---
            modal_layout.addWidget(QLabel("1. Selecciona los datos objetivo:", modal.content))
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            content = QWidget()
            lay = QVBoxLayout(content)
            
            checkboxes = {}
            for td in target_data:
                chk = QCheckBox(f"[{td.field_type}] {td.value}")
                chk.setChecked(True)
                lay.addWidget(chk)
                checkboxes[chk] = td.id
                
            scroll.setWidget(content)
            modal_layout.addWidget(scroll)
            
            # --- SECCION EXTRA ARGS ---
            lbl_extra = QLabel("2. Opcional: Parámetros personalizados / Console Flags:", modal.content)
            lbl_extra.setStyleSheet("margin-top: 10px; color: #ffaa00; font-weight: bold;")
            modal_layout.addWidget(lbl_extra)
            
            txt_extra = QLineEdit()
            txt_extra.setPlaceholderText("Ej: -b all -l 500")
            txt_extra.setStyleSheet(
                "background-color: #0c111d; color: #00ff66; "
                "padding: 8px; border-radius: 4px; border: 1px solid #1f2937;"
            )
            modal_layout.addWidget(txt_extra)
            
            def _on_confirm():
                selected_ids = [td_id for chk, td_id in checkboxes.items() if chk.isChecked()]
                if not selected_ids:
                    self.app.toast.show("Debes seleccionar al menos un dato.", kind="warning")
                    return
                modal.accept()
                _execute(selected_ids, txt_extra.text().strip())
                
            modal.add_button("Cancelar", modal.reject)
            modal.add_button("Ejecutar", _on_confirm, variant="primary")
            modal.exec()

        if tool.is_heavy and self.app.framework.resource.is_overloaded():
            modal = SentinelModal(self.app, "Carga Pesada", 400, 200)
            QLabel("Sistema bajo carga. Procede con cuidado.", modal.content)
            modal.add_button("Cancelar", modal.reject)
            modal.add_button("Continuar", lambda: [modal.accept(), _show_data_selection()], variant="danger")
            modal.exec()
        else:
            _show_data_selection()
