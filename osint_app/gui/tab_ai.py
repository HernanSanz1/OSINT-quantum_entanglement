"""
Correlational Intelligence IA Tab.

Muestra estado de cada brain con guía de instalación si no está disponible.
- OllamaBrain  : local, necesita Ollama instalado + modelo descargado
- VeniceBrain 1: API key de Venice.ai
- VeniceBrain 2: API key de Venice.ai + otro modelo (ej. para debates)
"""
import importlib
import threading
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit, QPushButton,
    QLabel, QSplitter, QCheckBox, QScrollArea, QFrame, QLineEdit,
    QComboBox, QTabWidget
)
from PySide6.QtCore import Qt, QMetaObject, Q_ARG, QTimer, Signal
from PySide6.QtGui import QColor
from .components import SentinelModal
from ..db.feedback_db import db


# ── Setup info per brain ───────────────────────────────────────────────────────
_BRAIN_SETUP = {
    "Ollama": {
        "pkg":        None,                       # no pip pkg — binary
        "binary":     "ollama",
        "install_steps": (
            "1. Descarga Ollama desde:\n"
            "   https://ollama.ai/download\n\n"
            "2. Instala y levanta el servicio:\n"
            "   ollama serve\n\n"
            "3. Descarga el modelo (solo la primera vez):\n"
            "   ollama pull llama3.2\n"
            "   (llama3.2 ~ 2 GB RAM, recomendado)\n\n"
            "4. Modelos alternativos:\n"
            "   ollama pull mistral\n"
            "   ollama pull phi3"
        ),
        "key_name":   None,
        "key_url":    None,
    },
    "Venice 1": {
        "pkg":        "openai",
        "binary":     None,
        "install_steps": (
            "1. Instala el paquete Python:\n"
            "   pip install openai\n\n"
            "2. Crea cuenta y obtén tu API key en:\n"
            "   https://venice.ai/settings/api\n\n"
            '3. Agrégala en ~/.osint_v2_keys:\n'
            '   "Venice": "tu-venice-key"\n\n'
            "   Modelo A para consulta y correlación"
        ),
        "key_name":   "Venice",
        "key_url":    "https://venice.ai/settings/api",
    },
    "Venice 2": {
        "pkg":        "openai",
        "binary":     None,
        "install_steps": (
            "1. Instala el paquete Python:\n"
            "   pip install openai\n\n"
            "2. Crea cuenta y obtén tu API key en:\n"
            "   https://venice.ai/settings/api\n\n"
            '3. Agrégala en ~/.osint_v2_keys:\n'
            '   "Venice": "tu-venice-key"\n\n'
            "   Modelo B para debate IA"
        ),
        "key_name":   "Venice",
        "key_url":    "https://venice.ai/settings/api",
    },
}


def _check_brain_prereqs(brain_name: str, brain) -> dict:
    """
    Devuelve dict con: status, icon, title, detail, install_steps.
    Parecido a diagnose_status() de las tools.
    """
    import shutil
    cfg = _BRAIN_SETUP.get(brain_name, {})

    # 1. Check binary (Ollama)
    if cfg.get("binary"):
        if not shutil.which(cfg["binary"]):
            return {
                "status": "not_installed",
                "icon":   "❌",
                "title":  f"{brain_name}: NO INSTALADO",
                "detail": f"El binario '{cfg['binary']}' no está en PATH.",
                "install_steps": cfg.get("install_steps", ""),
            }

    # 2. Check Python package (openai)
    if cfg.get("pkg"):
        try:
            importlib.import_module(cfg["pkg"])
        except ImportError:
            return {
                "status": "pkg_missing",
                "icon":   "⚠️",
                "title":  f"{brain_name}: PAQUETE FALTANTE",
                "detail": f"Falta pip install {cfg['pkg']}",
                "install_steps": cfg.get("install_steps", ""),
            }

    # 3. Check API key
    if cfg.get("key_name") and not getattr(brain, "api_key", ""):
        return {
            "status": "needs_key",
            "icon":   "🔑",
            "title":  f"{brain_name}: FALTA API KEY",
            "detail": f"Agrega la key en ~/.osint_v2_keys → \"{cfg['key_name']}\"",
            "install_steps": cfg.get("install_steps", ""),
        }

    # 4. Connectivity check (for Ollama: check if running)
    if not brain.is_available():
        err = getattr(brain, "_last_error", "")
        return {
            "status": "unavailable",
            "icon":   "🟡",
            "title":  f"{brain_name}: SERVICIO NO ACTIVO",
            "detail": err or "No se pudo conectar.",
            "install_steps": cfg.get("install_steps", ""),
        }

    return {
        "status": "ready",
        "icon":   "✅",
        "title":  f"{brain_name}: LISTO",
        "detail": "Disponible para análisis.",
        "install_steps": "",
    }


_STATUS_COLOR = {
    "ready":         "#00ff66",
    "unavailable":   "#ffaa00",
    "needs_key":     "#ffaa00",
    "pkg_missing":   "#ffaa00",
    "not_installed": "#ff3333",
}


class _BrainStatusCard(QFrame):
    """Tarjeta de estado + guía para un brain."""

    def __init__(self, brain_name: str, parent=None):
        super().__init__(parent)
        self.brain_name = brain_name
        self.setObjectName("panelInner")
        self.setFixedHeight(56)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 4, 10, 4)

        self.lbl_icon = QLabel("…")
        self.lbl_icon.setFixedWidth(24)
        self.lbl_title = QLabel(brain_name)
        self.lbl_title.setStyleSheet("font-weight: bold; font-size: 12px;")
        self.lbl_detail = QLabel("")
        self.lbl_detail.setStyleSheet("font-size: 10px; color: #8A9AA9;")

        self.btn_setup = QPushButton("Ver guía")
        self.btn_setup.setFixedWidth(80)
        self.btn_setup.setCursor(Qt.PointingHandCursor)
        self.btn_setup.hide()
        
        self._click_conn = None

        left = QVBoxLayout()
        left.setSpacing(0)
        left.addWidget(self.lbl_title)
        left.addWidget(self.lbl_detail)

        lay.addWidget(self.lbl_icon)
        lay.addLayout(left, 1)
        lay.addWidget(self.btn_setup)

    def update_status(self, result: dict, on_guide_click):
        color = _STATUS_COLOR.get(result["status"], "#E0E6ED")
        self.lbl_icon.setText(result["icon"])
        self.lbl_title.setText(result["title"])
        self.lbl_title.setStyleSheet(f"font-weight: bold; font-size: 12px; color: {color};")
        self.lbl_detail.setText(result["detail"])

        if result.get("install_steps"):
            self.btn_setup.show()
            if self._click_conn:
                try:
                    self.btn_setup.clicked.disconnect(self._click_conn)
                except Exception:
                    pass
            self._click_conn = self.btn_setup.clicked.connect(on_guide_click)
        else:
            self.btn_setup.hide()


class AITab(QWidget):
    brain_status_ready = Signal(str, object)

    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setObjectName("panelMain")
        self._analyzing = False
        self._chk_vars = {}
        
        self.brain_status_ready.connect(self._on_brain_status_ready)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        # ── Brain Status Cards ────────────────────────────────────────────────
        cards_layout = QHBoxLayout()
        self._cards = {}
        for bname in ("Ollama", "Venice 1", "Venice 2"):
            card = _BrainStatusCard(bname)
            self._cards[bname] = card
            cards_layout.addWidget(card)
        layout.addLayout(cards_layout)

        # ── Main Splitter ─────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        # Left: Reports Checkboxes
        left_panel = QFrame()
        left_panel.setObjectName("panelInner")
        left_layout = QVBoxLayout(left_panel)
        left_layout.addWidget(QLabel("REPORTES DEL CASO"))

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.scroll_content)
        left_layout.addWidget(self.scroll_area, 1)

        btn_sel = QPushButton("☑ Seleccionar todos")
        btn_sel.clicked.connect(self._select_all)
        left_layout.addWidget(btn_sel)

        self.btn_analyze = QPushButton("◎ Analizar con Triple IA")
        self.btn_analyze.setObjectName("btnPrimary")
        self.btn_analyze.clicked.connect(self._start_analysis)
        left_layout.addWidget(self.btn_analyze)

        self.btn_debate = QPushButton("🗣 Iniciar Debate Multi-IA")
        self.btn_debate.setObjectName("btnSecondary")
        self.btn_debate.setStyleSheet("background-color: #261b47; color: #b794f4; border: 1px solid #6b46c1;")
        self.btn_debate.clicked.connect(self._start_debate)
        left_layout.addWidget(self.btn_debate)

        splitter.addWidget(left_panel)

        # Right: 3 Text Areas
        right_panel = QWidget()
        right_layout = QHBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        self.txt_ollama  = QPlainTextEdit()
        self.txt_venice1 = QPlainTextEdit()
        self.txt_venice2 = QPlainTextEdit()

        for t, name in [
            (self.txt_ollama,  "🦙 Ollama"),
            (self.txt_venice1, "🧠 Venice (Modelo A)"),
            (self.txt_venice2, "🔓 Venice (Modelo B)"),
        ]:
            t.setReadOnly(True)
            col = QVBoxLayout()
            lbl = QLabel(name)
            lbl.setStyleSheet("font-weight: bold; color: #00d4ff; font-size: 13px;")
            col.addWidget(lbl)
            t.setStyleSheet("background-color: #0c111d; color: #E0E6ED; font-family: monospace; font-size: 11px;")
            col.addWidget(t)
            right_layout.addLayout(col)

        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)

        # ── Bottom Prompt Area ────────────────────────────────────────────────
        bot_layout = QHBoxLayout()
        self.combo_ollama = QComboBox()
        self.combo_ollama.addItems(["llama3.2", "mistral", "phi3", "llama3.1:8b"])
        bot_layout.addWidget(QLabel("Ollama:"))
        bot_layout.addWidget(self.combo_ollama)
        
        self.combo_venice1 = QComboBox()
        self.combo_venice1.setEditable(True)
        self.combo_venice1.addItems([
            "openai-gpt-52", "claude-opus-4-6", "glm-4.7-flash-heretic", 
            "glm-4.6", "glm-5", "deepseek-v3.2", "grok-4.1-fast", "kimi-k2.5"
        ])
        bot_layout.addWidget(QLabel("Venice 1:"))
        bot_layout.addWidget(self.combo_venice1)

        self.combo_venice2 = QComboBox()
        self.combo_venice2.setEditable(True)
        self.combo_venice2.addItems([
            "openai-gpt-52", "claude-opus-4-6", "glm-4.7-flash-heretic", 
            "glm-4.6", "glm-5", "deepseek-v3.2", "grok-4.1-fast", "kimi-k2.5"
        ])
        bot_layout.addWidget(QLabel("Venice 2:"))
        bot_layout.addWidget(self.combo_venice2)

        self.prompt_entry = QLineEdit()
        self.prompt_entry.setPlaceholderText("Consulta libre a la IA...")
        bot_layout.addWidget(self.prompt_entry, 1)

        btn_ask = QPushButton("Enviar")
        btn_ask.setObjectName("btnPrimary")
        btn_ask.clicked.connect(self._manual_query)
        bot_layout.addWidget(btn_ask)

        layout.addLayout(bot_layout)
        self.refresh()

    # ── Refresh ───────────────────────────────────────────────────────────────

    def refresh(self):
        self._load_reports()
        
        # Async status check to avoid blocking the UI if network is slow/failing
        def _check():
            try:
                for bname, card in self._cards.items():
                    brain = self.app.ai_engine.brains.get(bname)
                    if not brain:
                        continue
                    result = _check_brain_prereqs(bname, brain)
                    self.brain_status_ready.emit(bname, result)
            except Exception as e:
                print(f"Error checking AI status: {e}")
                
        threading.Thread(target=_check, daemon=True).start()

    def _on_brain_status_ready(self, bname: str, result: dict):
        card = self._cards.get(bname)
        if card:
            card.update_status(result, lambda r=result, n=bname: self._show_guide(n, r))

    def _show_guide(self, brain_name: str, result: dict):
        """Muestra modal con guía de instalación."""
        modal = SentinelModal(self.app, f"⚙  Configurar {brain_name}", width=520, height=400)
        from PySide6.QtWidgets import QVBoxLayout
        lay = QVBoxLayout(modal.content)

        lbl_status = QLabel(f"{result['icon']}  {result['title']}")
        lbl_status.setStyleSheet("font-weight: bold; font-size: 13px;")
        lay.addWidget(lbl_status)

        lbl_detail = QLabel(result["detail"])
        lbl_detail.setStyleSheet("color: #8A9AA9;")
        lay.addWidget(lbl_detail)

        txt = QPlainTextEdit()
        txt.setReadOnly(True)
        txt.setPlainText(result.get("install_steps", ""))
        txt.setStyleSheet(
            "background-color: #0c111d; color: #00ff66; "
            "font-family: monospace; font-size: 12px; border-radius: 8px;"
        )
        lay.addWidget(txt, 1)

        modal.add_button("Cerrar", modal.reject)
        modal.exec()

    # ── Load reports ──────────────────────────────────────────────────────────

    def _load_reports(self):
        while self.scroll_layout.count():
            child = self.scroll_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self._chk_vars.clear()

        if not self.app.active_case_id:
            lbl = QLabel("Sin caso activo — abre un caso primero.")
            lbl.setStyleSheet("color: #8A9AA9;")
            self.scroll_layout.addWidget(lbl)
            return

        reports = db.get_reports(self.app.active_case_id)
        if not reports:
            lbl = QLabel("Sin reportes aún — ejecuta algunas herramientas.")
            lbl.setStyleSheet("color: #8A9AA9;")
            self.scroll_layout.addWidget(lbl)
            return

        for r in reports:
            chk = QCheckBox(f"[Caso #{getattr(r, 'case_id', '?')}] Report ID #{getattr(r, 'id', '?')} - {getattr(r, 'tool_name', '?')}  ({getattr(r, 'results_count', 0)} resultados)")
            chk.setChecked(True)
            self.scroll_layout.addWidget(chk)
            self._chk_vars[getattr(r, "id", 0)] = chk

    def _select_all(self):
        for chk in self._chk_vars.values():
            chk.setChecked(True)

    # ── Analysis ──────────────────────────────────────────────────────────────

    def _start_analysis(self):
        if not self.app.active_case_id:
            self.app.toast.show("Abre un caso primero.", kind="warning")
            return

        selected = [rid for rid, chk in self._chk_vars.items() if chk.isChecked()]
        if not selected:
            self.app.toast.show("Selecciona al menos un reporte.", kind="warning")
            return

        # Check if at least one brain is ready
        enabled = self.app.ai_engine.enabled_brains()
        if not enabled:
            self.app.toast.show(
                "Ningún brain disponible. Configura Ollama, ChatGPT o Venice.",
                kind="error"
            )
            return

        self.app.ai_engine.set_model("Ollama", self.combo_ollama.currentText())
        self.app.ai_engine.set_model("Venice 1", self.combo_venice1.currentText())
        self.app.ai_engine.set_model("Venice 2", self.combo_venice2.currentText())

        if self._analyzing:
            return

        self._analyzing = True
        self.btn_analyze.setEnabled(False)
        self.btn_debate.setEnabled(False)
        self.txt_ollama.clear()
        self.txt_venice1.clear()
        self.txt_venice2.clear()

        # Show "analyzing" placeholder
        self.txt_ollama.setPlainText("⏳ Analizando individualmente...")
        self.txt_venice1.setPlainText("⏳ Analizando individualmente...")
        self.txt_venice2.setPlainText("⏳ Analizando individualmente...")

        self.app.set_status("🧠 Analizando con Triple IA...", "loading")

        def _worker():
            try:
                def _cb(brain_name, status):
                    msg = f"[{brain_name}] {status}"
                    QTimer.singleShot(0, lambda: self.app.set_status(f"🧠 {msg}", "loading"))

                res, _ = self.app.ai_engine.analyze(
                    self.app.active_case_id,
                    selected,
                    progress_cb=_cb,
                )

                o_res = res.responses.get("Ollama",   res.errors.get("Ollama",  "⬜ No disponible"))
                c_res = res.responses.get("Venice 1", res.errors.get("Venice 1", "⬜ No disponible"))
                v_res = res.responses.get("Venice 2", res.errors.get("Venice 2", "⬜ No disponible"))

                QMetaObject.invokeMethod(self.txt_ollama,  "setPlainText", Qt.QueuedConnection, Q_ARG(str, str(o_res)))
                QMetaObject.invokeMethod(self.txt_venice1, "setPlainText", Qt.QueuedConnection, Q_ARG(str, str(c_res)))
                QMetaObject.invokeMethod(self.txt_venice2, "setPlainText", Qt.QueuedConnection, Q_ARG(str, str(v_res)))

                QTimer.singleShot(0, lambda: self.app.set_status("✅ Análisis completado", "success"))
                QTimer.singleShot(0, lambda: self.app.toast.show("Análisis IA completado", kind="success"))

            except Exception as e:
                err = str(e)
                QMetaObject.invokeMethod(self.txt_ollama, "setPlainText", Qt.QueuedConnection, Q_ARG(str, f"❌ Error: {err}"))
                QTimer.singleShot(0, lambda: self.app.toast.show(f"Error IA: {err}", kind="error"))
            finally:
                self._analyzing = False
                QMetaObject.invokeMethod(self.btn_analyze, "setEnabled", Qt.QueuedConnection, Q_ARG(bool, True))
                QMetaObject.invokeMethod(self.btn_debate, "setEnabled", Qt.QueuedConnection, Q_ARG(bool, True))

        threading.Thread(target=_worker, daemon=True).start()

    def _start_debate(self):
        if not self.app.active_case_id:
            self.app.toast.show("Abre un caso primero.", kind="warning")
            return

        selected = [rid for rid, chk in self._chk_vars.items() if chk.isChecked()]
        if not selected:
            self.app.toast.show("Selecciona al menos un reporte.", kind="warning")
            return

        enabled = self.app.ai_engine.enabled_brains()
        if len(enabled) < 2:
            self.app.toast.show(
                "Se requieren al menos 2 cerebros IA configurados y activos para realizar un DEBATE.",
                kind="error"
            )
            return

        self.app.ai_engine.set_model("Ollama", self.combo_ollama.currentText())
        self.app.ai_engine.set_model("Venice 1", self.combo_venice1.currentText())
        self.app.ai_engine.set_model("Venice 2", self.combo_venice2.currentText())

        if self._analyzing:
            return

        self._analyzing = True
        self.btn_analyze.setEnabled(False)
        self.btn_debate.setEnabled(False)
        self.txt_ollama.clear()
        self.txt_venice1.clear()
        self.txt_venice2.clear()

        self.txt_ollama.setPlainText("🗣 Iniciando Ronda 1 (Análisis)...")
        self.txt_venice1.setPlainText("🗣 Iniciando Ronda 1 (Análisis)...")
        self.txt_venice2.setPlainText("🗣 Iniciando Ronda 1 (Análisis)...")

        self.app.set_status("🗣 Comenzando Debate Multi-IA...", "loading")

        def _worker():
            try:
                def _cb(brain_name, status):
                    msg = f"[{brain_name}] {status}"
                    QTimer.singleShot(0, lambda: self.app.set_status(f"🗣 {msg}", "loading"))

                res, corr = self.app.ai_engine.run_debate(
                    self.app.active_case_id,
                    selected,
                    progress_cb=_cb,
                )

                # The `res.responses` contains Phase 2 outputs
                # But we might want to show Phase 1 details if something failed
                o_res = res.responses.get("Ollama",   res.errors.get("Ollama",  "⬜ Excluido del debate"))
                c_res = res.responses.get("Venice 1", res.errors.get("Venice 1", "⬜ Excluido del debate"))
                v_res = res.responses.get("Venice 2", res.errors.get("Venice 2", "⬜ Excluido del debate"))

                QMetaObject.invokeMethod(self.txt_ollama,  "setPlainText", Qt.QueuedConnection, Q_ARG(str, str(o_res)))
                QMetaObject.invokeMethod(self.txt_venice1, "setPlainText", Qt.QueuedConnection, Q_ARG(str, str(c_res)))
                QMetaObject.invokeMethod(self.txt_venice2, "setPlainText", Qt.QueuedConnection, Q_ARG(str, str(v_res)))

                QTimer.singleShot(0, lambda: self.app.set_status("✅ Debate Concluido", "success"))
                QTimer.singleShot(0, lambda: self.app.toast.show("Debate de IA concluido con éxito", kind="success"))

            except Exception as e:
                err = str(e)
                QMetaObject.invokeMethod(self.txt_ollama, "setPlainText", Qt.QueuedConnection, Q_ARG(str, f"❌ Error Crítico: {err}"))
                QTimer.singleShot(0, lambda: self.app.toast.show(f"Error Debate IA: {err}", kind="error"))
            finally:
                self._analyzing = False
                QMetaObject.invokeMethod(self.btn_analyze, "setEnabled", Qt.QueuedConnection, Q_ARG(bool, True))
                QMetaObject.invokeMethod(self.btn_debate, "setEnabled", Qt.QueuedConnection, Q_ARG(bool, True))

        threading.Thread(target=_worker, daemon=True).start()

    # ── Manual query ──────────────────────────────────────────────────────────

    def _manual_query(self):
        q = self.prompt_entry.text().strip()
        if not q or not self.app.active_case_id:
            if not self.app.active_case_id:
                self.app.toast.show("Abre un caso primero.", kind="warning")
            return

        self.app.ai_engine.set_model("Ollama", self.combo_ollama.currentText())
        self.app.ai_engine.set_model("Venice 1", self.combo_venice1.currentText())
        self.app.ai_engine.set_model("Venice 2", self.combo_venice2.currentText())

        self.prompt_entry.clear()
        for t in (self.txt_ollama, self.txt_venice1, self.txt_venice2):
            t.appendPlainText(f"\n▶ {q}\n")

        def _worker():
            try:
                selected = [rid for rid, chk in self._chk_vars.items() if chk.isChecked()]
                res = self.app.ai_engine.query_manually(q, self.app.active_case_id, selected)

                o_res = res.responses.get("Ollama",  res.errors.get("Ollama",  "⬜ No disponible"))
                c_res = res.responses.get("Venice 1", res.errors.get("Venice 1", "⬜ No disponible"))
                v_res = res.responses.get("Venice 2",  res.errors.get("Venice 2",  "⬜ No disponible"))

                QMetaObject.invokeMethod(self.txt_ollama,  "appendPlainText", Qt.QueuedConnection, Q_ARG(str, "\n" + str(o_res)))
                QMetaObject.invokeMethod(self.txt_venice1, "appendPlainText", Qt.QueuedConnection, Q_ARG(str, "\n" + str(c_res)))
                QMetaObject.invokeMethod(self.txt_venice2,  "appendPlainText", Qt.QueuedConnection, Q_ARG(str, "\n" + str(v_res)))
            except Exception as e:
                QTimer.singleShot(0, lambda: self.app.toast.show(f"Error: {e}", kind="error"))

        threading.Thread(target=_worker, daemon=True).start()

    def on_open(self):
        self.refresh()
