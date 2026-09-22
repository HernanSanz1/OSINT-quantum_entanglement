"""
Correlation Tab — Visualización de correlaciones y grafo de entidades.
Motor de inteligencia para perfilamiento automático.
"""
import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QPlainTextEdit, QFrame,
    QSplitter, QHeaderView, QTreeWidget, QTreeWidgetItem,
    QProgressBar, QGroupBox
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor

from .components import SentinelModal
from ..correlation_engine import CorrelationEngine, EntityExtractor, CrossCaseCorrelator


class AutoEnrichThread(QThread):
    """Thread para enriquecimiento automático"""
    progress = Signal(str)
    entity_found = Signal(str, str, int)  # type, value, confidence
    finished_ok = Signal(int)  # total nuevas entidades
    error = Signal(str)

    def __init__(self, case_id, framework):
        super().__init__()
        self.case_id = case_id
        self.framework = framework

    def run(self):
        try:
            engine = CorrelationEngine(self.case_id)
            suggestions = engine.suggest_tools()

            if not suggestions:
                self.progress.emit("No hay datos para enriquecer. Agrega datos primero.")
                self.finished_ok.emit(0)
                return

            total_new = 0
            for tool_name, reason in suggestions[:3]:
                self.progress.emit(f"Ejecutando {tool_name}: {reason}")

                # Verificar si la herramienta está disponible
                tool = self.framework.tools.get(tool_name)
                if not tool or not tool.is_available:
                    self.progress.emit(f"  ⚠️ {tool_name} no disponible, saltando...")
                    continue

                # Ejecutar herramienta
                try:
                    report = self.framework.run_tool(
                        tool_name=tool_name,
                        case_id=self.case_id,
                        progress_cb=lambda msg: self.progress.emit(f"  {msg}")
                    )
                    if report and report.raw_json:
                        new_count = engine.process_tool_results(tool_name, report.raw_json)
                        total_new += new_count
                        self.progress.emit(f"  ✅ {new_count} nuevas entidades extraídas")
                except Exception as e:
                    self.progress.emit(f"  ❌ Error: {str(e)[:50]}")

            self.finished_ok.emit(total_new)

        except Exception as e:
            self.error.emit(str(e))


class CorrelationTab(QWidget):
    """Tab de correlación y perfilamiento"""

    def __init__(self, app):
        super().__init__()
        self.app = app
        self.engine = None
        self.setObjectName("panelMain")
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # ── Header ─────────────────────────────────────────────────────────────
        header = QHBoxLayout()

        lbl_title = QLabel("🔗  CORRELACIÓN DE INTELIGENCIA")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #00d4ff;")
        header.addWidget(lbl_title)

        header.addStretch()

        # Stats
        self.lbl_entities = QLabel("Entidades: 0")
        self.lbl_entities.setStyleSheet("color: #00ff66;")
        header.addWidget(self.lbl_entities)

        self.lbl_correlations = QLabel("Correlaciones: 0")
        self.lbl_correlations.setStyleSheet("color: #ffaa00;")
        header.addWidget(self.lbl_correlations)

        layout.addLayout(header)

        # ── Actions Bar ────────────────────────────────────────────────────────
        actions = QHBoxLayout()

        self.btn_analyze = QPushButton("🔍  Analizar Caso")
        self.btn_analyze.setObjectName("btnPrimary")
        self.btn_analyze.clicked.connect(self._on_analyze)
        actions.addWidget(self.btn_analyze)

        self.btn_auto_enrich = QPushButton("🚀  Auto-Enriquecer")
        self.btn_auto_enrich.clicked.connect(self._on_auto_enrich)
        self.btn_auto_enrich.setToolTip("Ejecuta herramientas automáticamente según los datos disponibles")
        actions.addWidget(self.btn_auto_enrich)

        self.btn_cross_case = QPushButton("🔀  Correlación Cruzada")
        self.btn_cross_case.clicked.connect(self._on_cross_case)
        self.btn_cross_case.setToolTip("Busca entidades compartidas entre casos")
        actions.addWidget(self.btn_cross_case)

        actions.addStretch()

        self.btn_export = QPushButton("📄  Exportar Perfil")
        self.btn_export.clicked.connect(self._on_export)
        actions.addWidget(self.btn_export)

        layout.addLayout(actions)

        # ── Progress Bar ───────────────────────────────────────────────────────
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.hide()
        layout.addWidget(self.progress)

        # ── Main Content Splitter ──────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        # Left: Entities by type
        left_frame = QFrame()
        left_frame.setObjectName("panelInner")
        left_layout = QVBoxLayout(left_frame)
        left_layout.setContentsMargins(8, 8, 8, 8)

        lbl_entities = QLabel("📊  Entidades por Tipo")
        lbl_entities.setStyleSheet("font-weight: bold; color: #00d4ff;")
        left_layout.addWidget(lbl_entities)

        self.tree_entities = QTreeWidget()
        self.tree_entities.setHeaderLabels(["Tipo / Valor", "Fuente", "Confianza"])
        self.tree_entities.setColumnWidth(0, 250)
        self.tree_entities.setColumnWidth(1, 100)
        self.tree_entities.itemClicked.connect(self._on_entity_clicked)
        left_layout.addWidget(self.tree_entities)

        # Suggested tools
        self.grp_suggestions = QGroupBox("💡 Herramientas Sugeridas")
        self.grp_suggestions.setStyleSheet("QGroupBox { color: #ffaa00; font-weight: bold; }")
        sugg_layout = QVBoxLayout(self.grp_suggestions)
        self.lbl_suggestions = QLabel("Analiza el caso para ver sugerencias")
        self.lbl_suggestions.setStyleSheet("color: #8A9AA9;")
        self.lbl_suggestions.setWordWrap(True)
        sugg_layout.addWidget(self.lbl_suggestions)
        left_layout.addWidget(self.grp_suggestions)

        splitter.addWidget(left_frame)

        # Right: Correlations and log
        right_splitter = QSplitter(Qt.Vertical)

        # Correlations table
        corr_frame = QFrame()
        corr_frame.setObjectName("panelInner")
        corr_layout = QVBoxLayout(corr_frame)
        corr_layout.setContentsMargins(8, 8, 8, 8)

        lbl_corr = QLabel("🔗  Correlaciones Detectadas")
        lbl_corr.setStyleSheet("font-weight: bold; color: #00d4ff;")
        corr_layout.addWidget(lbl_corr)

        self.table_correlations = QTableWidget()
        self.table_correlations.setColumnCount(5)
        self.table_correlations.setHorizontalHeaderLabels(["Entidad A", "Relación", "Entidad B", "Confianza", "Evidencia"])
        self.table_correlations.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_correlations.setSelectionBehavior(QTableWidget.SelectRows)
        corr_layout.addWidget(self.table_correlations)

        right_splitter.addWidget(corr_frame)

        # Log area
        log_frame = QFrame()
        log_frame.setObjectName("panelInner")
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(8, 8, 8, 8)

        lbl_log = QLabel("📋  Log de Análisis")
        lbl_log.setStyleSheet("font-weight: bold; color: #00d4ff;")
        log_layout.addWidget(lbl_log)

        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet(
            "background-color: #0c111d; color: #00ff66; "
            "font-family: monospace; font-size: 11px;"
        )
        self.log_area.setMaximumHeight(150)
        log_layout.addWidget(self.log_area)

        right_splitter.addWidget(log_frame)
        right_splitter.setSizes([400, 150])

        splitter.addWidget(right_splitter)
        splitter.setSizes([350, 550])

    def _log(self, msg):
        """Agregar mensaje al log"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.appendPlainText(f"[{timestamp}] {msg}")
        vsb = self.log_area.verticalScrollBar()
        vsb.setValue(vsb.maximum())

    def _set_busy(self, busy):
        """Toggle estado de carga"""
        self.btn_analyze.setEnabled(not busy)
        self.btn_auto_enrich.setEnabled(not busy)
        self.btn_cross_case.setEnabled(not busy)
        if busy:
            self.progress.setRange(0, 0)
            self.progress.show()
        else:
            self.progress.hide()

    # ── Actions ────────────────────────────────────────────────────────────────

    def _on_analyze(self):
        """Analiza el caso actual"""
        if not self.app.active_case_id:
            self.app.toast.show("Abre un caso primero", kind="warning")
            return

        self._log("Analizando caso...")
        self._set_busy(True)

        try:
            self.engine = CorrelationEngine(self.app.active_case_id)
            summary = self.engine.get_profile_summary()

            # Actualizar stats
            self.lbl_entities.setText(f"Entidades: {summary['total_entities']}")
            self.lbl_correlations.setText(f"Correlaciones: {summary['total_correlations']}")

            # Poblar árbol de entidades
            self._populate_entities_tree(summary['entities_by_type'])

            # Poblar tabla de correlaciones
            self._populate_correlations_table(summary['top_correlations'])

            # Mostrar sugerencias
            suggestions = self.engine.suggest_tools()
            if suggestions:
                sugg_text = "\n".join([f"• {tool}: {reason}" for tool, reason in suggestions])
                self.lbl_suggestions.setText(sugg_text)
            else:
                self.lbl_suggestions.setText("No hay sugerencias. Agrega más datos al caso.")

            self._log(f"✅ Análisis completado: {summary['total_entities']} entidades, {summary['total_correlations']} correlaciones")
            self.app.toast.show("Análisis completado", kind="success")

        except Exception as e:
            self._log(f"❌ Error: {str(e)}")
            self.app.toast.show(f"Error: {str(e)[:50]}", kind="error")

        finally:
            self._set_busy(False)

    def _populate_entities_tree(self, entities_by_type: dict):
        """Pobla el árbol de entidades"""
        self.tree_entities.clear()

        type_icons = {
            "email": "📧",
            "domain": "🌐",
            "ip": "🖥️",
            "username": "👤",
            "phone": "📱",
            "name": "📛",
            "hash_md5": "#️⃣",
            "hash_sha256": "#️⃣",
        }

        for entity_type, entities in entities_by_type.items():
            icon = type_icons.get(entity_type, "📌")
            parent = QTreeWidgetItem([f"{icon} {entity_type.upper()} ({len(entities)})", "", ""])
            parent.setExpanded(True)

            for e in entities:
                child = QTreeWidgetItem([
                    e["value"],
                    e["source"],
                    f"{e['confidence']}%"
                ])
                # Color por confianza
                if e["confidence"] >= 80:
                    child.setForeground(0, QColor("#00ff66"))
                elif e["confidence"] >= 50:
                    child.setForeground(0, QColor("#ffaa00"))
                else:
                    child.setForeground(0, QColor("#8A9AA9"))

                parent.addChild(child)

            self.tree_entities.addTopLevelItem(parent)

    def _populate_correlations_table(self, correlations: list):
        """Pobla la tabla de correlaciones"""
        self.table_correlations.setRowCount(len(correlations))

        relation_icons = {
            "same_entity": "≡",
            "same_person": "👤",
            "owns": "→",
            "subdomain_of": "⊂",
            "linked": "↔",
        }

        for i, corr in enumerate(correlations):
            icon = relation_icons.get(corr["type"], "—")

            self.table_correlations.setItem(i, 0, QTableWidgetItem(corr["a"]))
            self.table_correlations.setItem(i, 1, QTableWidgetItem(f"{icon} {corr['type']}")
            )
            self.table_correlations.setItem(i, 2, QTableWidgetItem(corr["b"]))

            conf_item = QTableWidgetItem(f"{corr['confidence']}%")
            if corr["confidence"] >= 80:
                conf_item.setForeground(QColor("#00ff66"))
            elif corr["confidence"] >= 50:
                conf_item.setForeground(QColor("#ffaa00"))
            else:
                conf_item.setForeground(QColor("#ff3333"))
            self.table_correlations.setItem(i, 3, conf_item)

            self.table_correlations.setItem(i, 4, QTableWidgetItem(corr["evidence"]))

    def _on_entity_clicked(self, item, column):
        """Al hacer clic en una entidad"""
        # Podría mostrar detalles o permitir ejecutar herramientas específicas
        pass

    def _on_auto_enrich(self):
        """Ejecuta enriquecimiento automático"""
        if not self.app.active_case_id:
            self.app.toast.show("Abre un caso primero", kind="warning")
            return

        self._log("Iniciando enriquecimiento automático...")
        self._set_busy(True)

        self.enrich_thread = AutoEnrichThread(self.app.active_case_id, self.app.framework)
        self.enrich_thread.progress.connect(self._log)
        self.enrich_thread.finished_ok.connect(self._on_enrich_done)
        self.enrich_thread.error.connect(self._on_enrich_error)
        self.enrich_thread.start()

    def _on_enrich_done(self, total_new):
        self._set_busy(False)
        self._log(f"✅ Enriquecimiento completado: {total_new} nuevas entidades")
        self.app.toast.show(f"Enriquecimiento: {total_new} nuevas entidades", kind="success")
        # Re-analizar para mostrar resultados
        self._on_analyze()

    def _on_enrich_error(self, error_msg):
        self._set_busy(False)
        self._log(f"❌ Error: {error_msg}")
        self.app.toast.show(f"Error: {error_msg[:50]}", kind="error")

    def _on_cross_case(self):
        """Correlación entre casos"""
        self._log("Buscando correlaciones entre casos...")

        try:
            correlator = CrossCaseCorrelator()

            # Cargar todos los casos
            from ..db.feedback_db import db
            cases = db.get_cases()

            if len(cases) < 2:
                self.app.toast.show("Necesitas al menos 2 casos para correlación cruzada", kind="warning")
                return

            for case in cases:
                correlator.load_case(case.id)

            shared = correlator.find_cross_correlations()

            if shared:
                msg = f"Encontradas {len(shared)} entidades compartidas:\n\n"
                for s in shared[:5]:
                    msg += f"• {s['entity_type']}: {s['value']}\n"
                    msg += f"  Casos: {', '.join(map(str, s['cases']))}\n\n"

                self._log(msg)
                self.app.toast.show(f"{len(shared)} entidades compartidas entre casos", kind="success")
            else:
                self._log("No se encontraron entidades compartidas entre casos")
                self.app.toast.show("No hay correlaciones cruzadas", kind="info")

        except Exception as e:
            self._log(f"❌ Error: {str(e)}")

    def _on_export(self):
        """Exporta el perfil correlacionado"""
        if not self.engine:
            self.app.toast.show("Analiza el caso primero", kind="warning")
            return

        summary = self.engine.get_profile_summary()
        self._log(f"Perfil exportado:\n{json.dumps(summary, indent=2, ensure_ascii=False)}")
        self.app.toast.show("Perfil exportado al log", kind="success")

    def refresh(self):
        """Refrescar tab"""
        if self.app.active_case_id:
            self._on_analyze()
