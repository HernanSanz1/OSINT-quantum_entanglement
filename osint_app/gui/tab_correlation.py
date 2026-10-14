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

from .components import DevNotice, SentinelModal
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
        layout.addWidget(DevNotice(
            "La correlación dentro de un caso y entre casos ya funciona, pero el cruce con CTI (noticias y "
            "vulnerabilidades) todavía es básico: solo compara CVE y nombres de tecnología. Revisa los resultados "
            "antes de usarlos en un informe."))

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

        self.btn_cti = QPushButton("🛡️  Cruzar con CTI")
        self.btn_cti.clicked.connect(self._on_cti)
        self.btn_cti.setToolTip("Cruza los CVEs y tecnologías del caso con la inteligencia de amenazas")
        actions.addWidget(self.btn_cti)

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
        self.table_correlations.setEditTriggers(QTableWidget.NoEditTriggers)
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
        self.btn_cti.setEnabled(not busy)
        if busy:
            self.progress.setRange(0, 0)
            self.progress.show()
        else:
            self.progress.hide()

    # ── Actions ────────────────────────────────────────────────────────────────

    def _on_analyze(self, quiet: bool = False):
        """Analiza el caso actual (`quiet`: sin avisos emergentes, al refrescar por un cambio de caso)."""
        if not self.app.active_case_id:
            if not quiet:
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
            self._populate_correlations_table(summary['correlations'])

            # Mostrar sugerencias
            suggestions = self.engine.suggest_tools()
            if suggestions:
                sugg_text = "\n".join([f"• {tool}: {reason}" for tool, reason in suggestions])
                self.lbl_suggestions.setText(sugg_text)
            else:
                self.lbl_suggestions.setText("No hay sugerencias. Agrega más datos al caso.")

            self._log(f"✅ Análisis completado: {summary['total_entities']} entidades, {summary['total_correlations']} correlaciones")
            if not quiet:   # antes salía "Análisis completado" al crear o abrir cualquier caso
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
            "profile": "🔗",
            "company": "🏢",
            "location": "📍",
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
            "same_handle": "🔁",
            "profile_of": "🔗",
            "named_in": "📛",
            "same_name": "📛",
            "name_in_handle": "🧩",
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
        """Datos que identifican a alguien (correo, usuario, teléfono…) y aparecen en el caso activo y en otros."""
        if not self.app.active_case_id:
            self.app.toast.show("Abre un caso primero: se buscan sus datos en los demás casos", kind="warning")
            return
        self._log("Buscando datos del caso activo que aparecen también en otros casos...")

        try:
            correlator = CrossCaseCorrelator()

            # Cargar todos los casos
            from ..db.feedback_db import db
            cases = db.get_cases()
            names = {case.id: case.name for case in cases}

            if len(cases) < 2:
                self.app.toast.show("Necesitas al menos 2 casos para correlación cruzada", kind="warning")
                return

            for case in cases:
                correlator.load_case(case.id)

            shared = correlator.find_cross_correlations(focus_case=self.app.active_case_id)

            if shared:
                msg = f"Encontrados {len(shared)} datos compartidos con otros casos:\n\n"
                for s in shared[:10]:
                    others = [f"#{c} {names.get(c, '')}" for c in s['cases'] if c != self.app.active_case_id]
                    msg += f"• {s['entity_type']}: {s['value']}\n  También en: {', '.join(others)}\n\n"

                self._log(msg)
                self.app.toast.show(f"{len(shared)} datos compartidos con otros casos", kind="success")
            else:
                self._log("Ningún correo, usuario, teléfono, dominio o IP de este caso aparece en otros casos "
                          "(país, ciudad y contexto no cuentan: los comparte mucha gente).")
                self.app.toast.show("No hay datos compartidos con otros casos", kind="info")

        except Exception as e:
            self._log(f"❌ Error: {str(e)}")

    def _on_cti(self):
        """Cruza los CVEs y tecnologías del caso con la inteligencia de amenazas."""
        if not self.app.active_case_id:
            self.app.toast.show("Abre un caso primero", kind="warning")
            return

        self._set_busy(True)
        self._log("🛡️ Cruzando el caso con la inteligencia de amenazas (CTI)…")
        try:
            from ..db.feedback_db import db

            from ..cti_link import collect_tech_terms_from_reports

            engine = CorrelationEngine(self.app.active_case_id)
            reports = db.get_reports(self.app.active_case_id)
            # Extrae entidades (incl. CVEs) de los reportes del caso
            for report in reports:
                engine.process_tool_results(report.tool_name, report.raw_json)

            # Tecnologías del objetivo: las detectadas por Tech Detect +
            # los valores de tipo company/organization del caso.
            tech_terms = collect_tech_terms_from_reports(reports)
            tech_terms += [
                e.value for e in engine.entities.values()
                if e.entity_type in ("company", "organization", "tech")
            ]

            result = engine.correlate_with_cti(tech_terms=tech_terms)
            self._populate_cti_matches(result)

            n_cve = result["total_cve_matches"]
            n_exp = result["actively_exploited"]
            n_tech = result["total_tech_matches"]
            self._log(f"✅ CTI: {n_cve} CVE(s) del caso en el CTI ({n_exp} explotados activamente); "
                      f"{n_tech} tecnología(s) con vulnerabilidades activas.")
            if n_cve == 0 and n_tech == 0:
                self.app.toast.show("Sin coincidencias con el CTI para este caso", kind="info")
            else:
                self.app.toast.show(
                    f"CTI: {n_cve} CVE(s) y {n_tech} tecnología(s) coinciden", kind="success")
        except Exception as e:
            self._log(f"❌ Error al cruzar con CTI: {e}")
            self.app.toast.show(f"Error CTI: {str(e)[:50]}", kind="error")
        finally:
            self._set_busy(False)

    def _populate_cti_matches(self, result: dict):
        """Muestra las coincidencias con el CTI en la tabla de correlaciones."""
        self.table_correlations.setRowCount(0)

        def _add_row(a, rel, b, conf, ev, color=None):
            row = self.table_correlations.rowCount()
            self.table_correlations.insertRow(row)
            for col, val in enumerate((a, rel, b, conf, ev)):
                item = QTableWidgetItem(str(val))
                if color:
                    item.setForeground(QColor(color))
                self.table_correlations.setItem(row, col, item)

        for m in result["cve_matches"]:
            h = m["hits"][0]
            if m["actively_exploited"]:
                rel, color = "⚠️ en CTI · EXPLOTADO", "#ff3333"
            else:
                rel, color = "en CTI", "#ffaa00"
            if m["ransomware"]:
                rel += " · ransomware"
            tech = f"{h['vendor']} {h['product']}".strip() or "—"
            _add_row(m["cve"], rel, tech, h.get("severity") or "—", h.get("source") or "", color)

        for t in result["tech_matches"]:
            _add_row(t["term"], f"tecnología · {t['count']} CVEs",
                     f"{t['actively_exploited']} explotados", "—", "CTI", "#ffaa00")

    def _on_export(self):
        """Exporta el perfil correlacionado"""
        if not self.engine:
            self.app.toast.show("Analiza el caso primero", kind="warning")
            return

        summary = self.engine.get_profile_summary()
        # Antes volcaba el JSON en el registro y no creaba ningún archivo
        from pathlib import Path
        from PySide6.QtWidgets import QFileDialog
        default = Path.home() / "Downloads" / f"correlacion_caso_{self.app.active_case_id}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Guardar el perfil correlacionado (JSON)", str(default),
                                              "Datos JSON (*.json)")
        if not path:
            return
        Path(path).write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        self._log(f"Perfil exportado: {path}")
        self.app.toast.show(f"Perfil exportado a {Path(path).name}", kind="success")

    def refresh(self):
        """Refrescar tab"""
        if self.app.active_case_id:
            self._on_analyze(quiet=True)
