"""
Profiling Tab — Perfilamiento inteligente de personas con feedback interactivo.

Flujo:
1. Usuario ingresa datos semilla (nombre, contexto, pais, username, email)
2. Sistema lanza TODAS las herramientas en paralelo
3. Sistema presenta candidatos ordenados por confianza
4. Usuario confirma o descarta candidatos
5. Sistema refina busqueda con feedback
6. Repite hasta satisfaccion

Las herramientas disponibles se muestran en la GUI y se ejecutan en paralelo.
"""
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTableWidget, QTableWidgetItem, QPlainTextEdit,
    QProgressBar, QFrame, QSplitter, QHeaderView, QMessageBox,
    QGroupBox, QFormLayout, QTextEdit, QCheckBox, QComboBox,
    QListWidget, QListWidgetItem, QAbstractItemView
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from osint_app.profiler_engine import ProfilerEngine, SeedData, Candidate
from osint_app.tools import build_tool_registry


class ProfilerThread(QThread):
    """Thread para ejecutar el motor de perfilamiento sin bloquear la GUI"""
    progress = Signal(str)
    tool_done = Signal(str, int)  # nombre_herramienta, num_resultados
    candidates_ready = Signal(list)
    finished_ok = Signal(dict)
    error = Signal(str)

    def __init__(self, seed: SeedData, selected_tools: List[str] = None):
        super().__init__()
        self.seed = seed
        self.selected_tools = selected_tools
        self.engine = None

    def run(self):
        try:
            def progress_cb(msg):
                self.progress.emit(msg)

            self.engine = ProfilerEngine(progress_callback=progress_cb)

            self.progress.emit(f"Iniciando perfilamiento de: {self.seed.name}")
            self.progress.emit(f"Contexto: {self.seed.context}")

            # Ejecutar herramientas en paralelo
            self.engine.run_parallel(self.seed, max_workers=6, timeout_per_tool=90)

            # Extraer candidatos
            candidates = self.engine.extract_candidates(self.seed, min_confidence=20.0)

            # Emitir candidatos
            candidates_data = [
                {
                    'source': c.source_tool,
                    'url': c.url,
                    'title': c.title,
                    'snippet': c.snippet,
                    'confidence': c.confidence,
                    'category': c.category,
                    'matched': c.matched_fields,
                    'verdict': c.user_verdict,
                }
                for c in candidates
            ]
            self.candidates_ready.emit(candidates_data)

            # Emitir resumen final
            self.finished_ok.emit(self.engine.get_summary())

        except Exception as e:
            self.error.emit(str(e))


class ProfilingTab(QWidget):
    """Tab de Perfilamiento Inteligente con feedback interactivo"""

    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setObjectName("panelMain")

        # Estado del perfilamiento
        self.candidates_data = []
        self.confirmed_urls = set()
        self.rejected_urls = set()
        self.profiler_thread = None

        # Cargar herramientas disponibles
        self.tools_registry = build_tool_registry()

        self._setup_ui()
        self._populate_tools()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # ── Header ─────────────────────────────────────────────────────────────
        header = QHBoxLayout()

        lbl_title = QLabel("🔍  PERFILAMIENTO INTELIGENTE")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #00d4ff;")
        header.addWidget(lbl_title)

        header.addStretch()

        self.btn_new_profile = QPushButton("➕  Nuevo Perfil")
        self.btn_new_profile.setObjectName("btnPrimary")
        self.btn_new_profile.clicked.connect(self._on_new_profile)
        header.addWidget(self.btn_new_profile)

        self.btn_generate_dossier = QPushButton("🎖️  Generar Ficha")
        self.btn_generate_dossier.setObjectName("btnSuccess")
        self.btn_generate_dossier.setStyleSheet("background-color: #059669; font-weight: bold;")
        self.btn_generate_dossier.clicked.connect(self._on_generate_dossier)
        header.addWidget(self.btn_generate_dossier)

        self.btn_export = QPushButton("📤  Exportar JSON")
        self.btn_export.clicked.connect(self._on_export)
        header.addWidget(self.btn_export)

        layout.addLayout(header)

        # ── Main Splitter ──────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        # ── Left Panel: Input + Tools (con scroll) ──────────────────────────────
        from PySide6.QtWidgets import QScrollArea

        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        left_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        left_panel = QFrame()
        left_panel.setObjectName("panelInner")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(10, 10, 10, 10)
        left_layout.setSpacing(10)

        left_scroll.setWidget(left_panel)
        left_scroll.setMinimumWidth(420)
        left_scroll.setMaximumWidth(480)

        # Seed Data - SIN GroupBox, directo al panel con labels pequeños y campos GRANDES
        lbl_section = QLabel("DATOS SEMILLA")
        lbl_section.setStyleSheet("color: #00d4ff; font-size: 11px; font-weight: bold; letter-spacing: 2px;")
        left_layout.addWidget(lbl_section)

        # Estilo GRANDE para inputs - campos muy visibles
        input_style = """
            QLineEdit {
                padding: 12px 15px;
                font-size: 15px;
                background-color: #0a1628;
                border: 1px solid #1e3a5f;
                border-radius: 5px;
                color: #ffffff;
            }
            QLineEdit:focus {
                border: 2px solid #00d4ff;
            }
        """
        label_style = "color: #5a7a9a; font-size: 10px; margin-top: 5px;"

        # Nombre
        lbl_name = QLabel("Nombre")
        lbl_name.setStyleSheet(label_style)
        left_layout.addWidget(lbl_name)
        self.input_name = QLineEdit()
        self.input_name.setPlaceholderText("Juan Carlos Riofrio Perez")
        self.input_name.setStyleSheet(input_style)
        self.input_name.setFixedHeight(40)
        left_layout.addWidget(self.input_name)

        # Contexto
        lbl_context = QLabel("Contexto")
        lbl_context.setStyleSheet(label_style)
        left_layout.addWidget(lbl_context)
        self.input_context = QLineEdit()
        self.input_context.setPlaceholderText("UDLA Ecuador, ingeniero, nacido 2000")
        self.input_context.setStyleSheet(input_style)
        self.input_context.setFixedHeight(40)
        left_layout.addWidget(self.input_context)

        # Fila: Pais + Username
        row1 = QHBoxLayout()
        row1.setSpacing(10)

        col1 = QVBoxLayout()
        col1.setSpacing(2)
        lbl_country = QLabel("Pais")
        lbl_country.setStyleSheet(label_style)
        col1.addWidget(lbl_country)
        self.input_country = QComboBox()
        self.input_country.addItems(["Ecuador", "Colombia", "Peru", "Mexico", "USA", "Otro"])
        self.input_country.setStyleSheet("""
            QComboBox {
                padding: 10px 12px;
                font-size: 14px;
                background-color: #0a1628;
                border: 1px solid #1e3a5f;
                border-radius: 5px;
                color: #ffffff;
            }
        """)
        self.input_country.setFixedHeight(40)
        col1.addWidget(self.input_country)
        row1.addLayout(col1)

        col2 = QVBoxLayout()
        col2.setSpacing(2)
        lbl_user = QLabel("Username")
        lbl_user.setStyleSheet(label_style)
        col2.addWidget(lbl_user)
        self.input_username = QLineEdit()
        self.input_username.setPlaceholderText("@usuario")
        self.input_username.setStyleSheet(input_style)
        self.input_username.setFixedHeight(40)
        col2.addWidget(self.input_username)
        row1.addLayout(col2)

        left_layout.addLayout(row1)

        # Fila: Email + Telefono
        row2 = QHBoxLayout()
        row2.setSpacing(10)

        col3 = QVBoxLayout()
        col3.setSpacing(2)
        lbl_email = QLabel("Email")
        lbl_email.setStyleSheet(label_style)
        col3.addWidget(lbl_email)
        self.input_email = QLineEdit()
        self.input_email.setPlaceholderText("correo@ejemplo.com")
        self.input_email.setStyleSheet(input_style)
        self.input_email.setFixedHeight(40)
        col3.addWidget(self.input_email)
        row2.addLayout(col3)

        col4 = QVBoxLayout()
        col4.setSpacing(2)
        lbl_phone = QLabel("Telefono")
        lbl_phone.setStyleSheet(label_style)
        col4.addWidget(lbl_phone)
        self.input_phone = QLineEdit()
        self.input_phone.setPlaceholderText("+593999999999")
        self.input_phone.setStyleSheet(input_style)
        self.input_phone.setFixedHeight(40)
        col4.addWidget(self.input_phone)
        row2.addLayout(col4)

        left_layout.addLayout(row2)

        # Dominio
        lbl_domain = QLabel("Dominio")
        lbl_domain.setStyleSheet(label_style)
        left_layout.addWidget(lbl_domain)
        self.input_domain = QLineEdit()
        self.input_domain.setPlaceholderText("empresa.com")
        self.input_domain.setStyleSheet(input_style)
        self.input_domain.setFixedHeight(40)
        left_layout.addWidget(self.input_domain)

        # Tools Selection - compacto
        lbl_tools = QLabel("HERRAMIENTAS")
        lbl_tools.setStyleSheet("color: #00d4ff; font-size: 11px; font-weight: bold; letter-spacing: 2px; margin-top: 10px;")
        left_layout.addWidget(lbl_tools)

        self.tools_list = QListWidget()
        self.tools_list.setSelectionMode(QAbstractItemView.MultiSelection)
        self.tools_list.setFixedHeight(120)
        self.tools_list.setStyleSheet("""
            QListWidget {
                background-color: #0a1628;
                color: #E0E6ED;
                font-size: 12px;
                border: 1px solid #1e3a5f;
                border-radius: 5px;
            }
            QListWidget::item:selected {
                background-color: #1e3a5f;
                color: #00d4ff;
            }
        """)
        left_layout.addWidget(self.tools_list)

        tools_btn_layout = QHBoxLayout()
        tools_btn_layout.setSpacing(5)
        btn_select_all = QPushButton("Todas")
        btn_select_all.setFixedHeight(30)
        btn_select_all.clicked.connect(self._select_all_tools)
        tools_btn_layout.addWidget(btn_select_all)

        btn_select_none = QPushButton("Ninguna")
        btn_select_none.setFixedHeight(30)
        btn_select_none.clicked.connect(self._select_no_tools)
        tools_btn_layout.addWidget(btn_select_none)
        left_layout.addLayout(tools_btn_layout)

        # Search Button - grande y visible
        self.btn_search = QPushButton("🚀  INICIAR PERFILAMIENTO")
        self.btn_search.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: bold;
                padding: 12px;
                background-color: #059669;
                border: none;
                border-radius: 6px;
                color: white;
            }
            QPushButton:hover {
                background-color: #10b981;
            }
        """)
        self.btn_search.setFixedHeight(45)
        self.btn_search.clicked.connect(self._on_search)
        left_layout.addWidget(self.btn_search)

        # Progress
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.hide()
        left_layout.addWidget(self.progress)

        # Confirmed Data Summary
        confirmed_group = QGroupBox("✅ Datos Confirmados")
        confirmed_group.setStyleSheet("QGroupBox { font-weight: bold; color: #00ff66; }")
        confirmed_layout = QVBoxLayout(confirmed_group)

        self.confirmed_list = QPlainTextEdit()
        self.confirmed_list.setReadOnly(True)
        self.confirmed_list.setStyleSheet(
            "background-color: #0a1628; color: #00ff66; "
            "font-family: monospace; font-size: 11px;"
        )
        self.confirmed_list.setMaximumHeight(120)
        confirmed_layout.addWidget(self.confirmed_list)

        left_layout.addWidget(confirmed_group)
        left_layout.addStretch()

        splitter.addWidget(left_scroll)

        # ── Right Panel: Candidates ────────────────────────────────────────────
        right_panel = QFrame()
        right_panel.setObjectName("panelInner")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(12, 12, 12, 12)

        # Candidates Header
        cand_header = QHBoxLayout()
        lbl_cand = QLabel("👥 Candidatos Encontrados")
        lbl_cand.setStyleSheet("font-weight: bold; color: #00d4ff; font-size: 14px;")
        cand_header.addWidget(lbl_cand)

        self.lbl_stats = QLabel("")
        self.lbl_stats.setStyleSheet("color: #8A9AA9;")
        cand_header.addWidget(self.lbl_stats)

        cand_header.addStretch()

        self.btn_confirm_selected = QPushButton("✅ Confirmar")
        self.btn_confirm_selected.setObjectName("btnSuccess")
        self.btn_confirm_selected.clicked.connect(self._on_confirm_candidate)
        cand_header.addWidget(self.btn_confirm_selected)

        self.btn_reject_selected = QPushButton("❌ Descartar")
        self.btn_reject_selected.setStyleSheet("background-color: #dc2626;")
        self.btn_reject_selected.clicked.connect(self._on_reject_candidate)
        cand_header.addWidget(self.btn_reject_selected)

        self.btn_refine = QPushButton("🔄 Refinar Busqueda")
        self.btn_refine.clicked.connect(self._on_refine)
        cand_header.addWidget(self.btn_refine)

        right_layout.addLayout(cand_header)

        # Candidates Table
        self.candidates_table = QTableWidget()
        self.candidates_table.setColumnCount(6)
        self.candidates_table.setHorizontalHeaderLabels([
            "Fuente", "Titulo", "Coincidencias", "Confianza", "Categoria", "Estado"
        ])
        self.candidates_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.candidates_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.candidates_table.setAlternatingRowColors(True)
        self.candidates_table.itemSelectionChanged.connect(self._on_candidate_selected)
        self.candidates_table.itemDoubleClicked.connect(self._on_open_url)
        right_layout.addWidget(self.candidates_table)

        # Candidate Details
        details_group = QGroupBox("📋 Detalles del Candidato")
        details_group.setStyleSheet("QGroupBox { font-weight: bold; color: #8A9AA9; }")
        details_layout = QVBoxLayout(details_group)

        self.candidate_details = QTextEdit()
        self.candidate_details.setReadOnly(True)
        self.candidate_details.setStyleSheet(
            "background-color: #0c111d; color: #E0E6ED; "
            "font-family: monospace; font-size: 11px;"
        )
        self.candidate_details.setMaximumHeight(120)
        details_layout.addWidget(self.candidate_details)

        right_layout.addWidget(details_group)

        # Log Area
        log_group = QGroupBox("📋 Log de Ejecucion")
        log_group.setStyleSheet("QGroupBox { font-weight: bold; color: #8A9AA9; }")
        log_layout = QVBoxLayout(log_group)

        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet(
            "background-color: #0c111d; color: #8A9AA9; "
            "font-family: monospace; font-size: 10px;"
        )
        self.log_area.setMaximumHeight(100)
        log_layout.addWidget(self.log_area)

        right_layout.addWidget(log_group)

        splitter.addWidget(right_panel)
        splitter.setSizes([400, 700])

        # Status
        self.lbl_status = QLabel("Estado: Listo para nueva busqueda")
        self.lbl_status.setStyleSheet("color: #00ff66;")
        layout.addWidget(self.lbl_status)

    def _populate_tools(self):
        """Poblar lista de herramientas disponibles."""
        for tool_name, tool in sorted(self.tools_registry.items()):
            item = QListWidgetItem(f"{tool_name}")
            if tool.is_available:
                item.setForeground(QColor("#00ff66"))
                item.setToolTip(f"{tool.description}\nEstado: Disponible")
            else:
                item.setForeground(QColor("#dc2626"))
                item.setToolTip(f"{tool.description}\nEstado: No disponible")
            self.tools_list.addItem(item)

        # Seleccionar las disponibles por defecto
        self._select_all_tools()

    def _select_all_tools(self):
        """Seleccionar todas las herramientas disponibles."""
        for i in range(self.tools_list.count()):
            item = self.tools_list.item(i)
            tool_name = item.text()
            if tool_name in self.tools_registry and self.tools_registry[tool_name].is_available:
                item.setSelected(True)

    def _select_no_tools(self):
        """Deseleccionar todas."""
        self.tools_list.clearSelection()

    def _log(self, msg):
        """Agregar mensaje al log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.appendPlainText(f"[{timestamp}] {msg}")
        vsb = self.log_area.verticalScrollBar()
        vsb.setValue(vsb.maximum())

    def _set_busy(self, busy):
        """Toggle estado de carga"""
        self.btn_search.setEnabled(not busy)
        self.btn_new_profile.setEnabled(not busy)
        if busy:
            self.progress.setRange(0, 0)
            self.progress.show()
            self.lbl_status.setText("Estado: Ejecutando herramientas...")
            self.lbl_status.setStyleSheet("color: #ffaa00;")
        else:
            self.progress.hide()
            self.lbl_status.setText("Estado: Listo")
            self.lbl_status.setStyleSheet("color: #00ff66;")

    def _on_new_profile(self):
        """Limpiar todo para un nuevo perfil"""
        self.input_name.clear()
        self.input_context.clear()
        self.input_username.clear()
        self.input_email.clear()
        self.input_phone.clear()
        self.input_domain.clear()
        self.confirmed_list.clear()
        self.candidates_table.setRowCount(0)
        self.candidate_details.clear()
        self.log_area.clear()
        self.lbl_stats.setText("")

        self.candidates_data = []
        self.confirmed_urls = set()
        self.rejected_urls = set()

        self._log("Nuevo perfil iniciado")
        self.app.toast.show("Nuevo perfil iniciado", kind="info")

    def _on_search(self):
        """Iniciar perfilamiento con los datos semilla"""
        name = self.input_name.text().strip()
        context = self.input_context.text().strip()
        country = self.input_country.currentText()
        username = self.input_username.text().strip() or None
        email = self.input_email.text().strip() or None
        phone = self.input_phone.text().strip() or None
        domain = self.input_domain.text().strip() or None

        if not name:
            self.app.toast.show("Ingresa un nombre para buscar", kind="error")
            return

        # Crear seed
        seed = SeedData(
            name=name,
            context=context,
            country=country,
            username=username,
            email=email,
            phone=phone,
            domain=domain
        )

        self._set_busy(True)
        self._log(f"Iniciando perfilamiento: {name}")
        self._log(f"Contexto: {context} | Pais: {country}")

        # Limpiar candidatos anteriores
        self.candidates_table.setRowCount(0)
        self.candidates_data = []

        # Obtener herramientas seleccionadas
        selected = [item.text() for item in self.tools_list.selectedItems()]
        self._log(f"Herramientas seleccionadas: {len(selected)}")

        # Iniciar thread
        self.profiler_thread = ProfilerThread(seed, selected)
        self.profiler_thread.progress.connect(self._log)
        self.profiler_thread.candidates_ready.connect(self._on_candidates_ready)
        self.profiler_thread.finished_ok.connect(self._on_search_done)
        self.profiler_thread.error.connect(self._on_error)
        self.profiler_thread.start()

    def _on_candidates_ready(self, candidates: List[Dict]):
        """Procesar candidatos encontrados."""
        self.candidates_data = candidates

        # Actualizar tabla
        self.candidates_table.setRowCount(0)

        for c in candidates:
            row = self.candidates_table.rowCount()
            self.candidates_table.insertRow(row)

            # Fuente
            self.candidates_table.setItem(row, 0, QTableWidgetItem(c['source']))

            # Titulo (truncado)
            title = c['title'][:60] + "..." if len(c['title']) > 60 else c['title']
            self.candidates_table.setItem(row, 1, QTableWidgetItem(title))

            # Coincidencias
            matched = ", ".join(c['matched'][:3]) if c['matched'] else "-"
            self.candidates_table.setItem(row, 2, QTableWidgetItem(matched))

            # Confianza con color
            conf = c['confidence']
            conf_item = QTableWidgetItem(f"{conf:.0f}%")
            if conf >= 70:
                conf_item.setForeground(QColor("#00ff66"))
            elif conf >= 40:
                conf_item.setForeground(QColor("#ffaa00"))
            else:
                conf_item.setForeground(QColor("#dc2626"))
            self.candidates_table.setItem(row, 3, conf_item)

            # Categoria
            cat = c.get('category', '-')[:20]
            self.candidates_table.setItem(row, 4, QTableWidgetItem(cat))

            # Estado
            url = c['url']
            if url in self.confirmed_urls:
                status = "✅ Confirmado"
                status_color = QColor("#00ff66")
            elif url in self.rejected_urls:
                status = "❌ Descartado"
                status_color = QColor("#dc2626")
            else:
                status = "Pendiente"
                status_color = QColor("#8A9AA9")

            status_item = QTableWidgetItem(status)
            status_item.setForeground(status_color)
            self.candidates_table.setItem(row, 5, status_item)

        # Actualizar stats
        self.lbl_stats.setText(f"({len(candidates)} encontrados)")

    def _on_search_done(self, summary: Dict):
        """Perfilamiento completado."""
        self._set_busy(False)

        msg = f"Completado: {summary['candidates']} candidatos de {summary['total_results']} resultados"
        self._log(msg)
        self.app.toast.show(msg, kind="success")

        if summary['candidates'] == 0:
            self._log("No se encontraron candidatos. Intenta agregar mas contexto o datos.")

    def _on_error(self, error_msg):
        """Error en el perfilamiento."""
        self._set_busy(False)
        self._log(f"Error: {error_msg}")
        self.app.toast.show(f"Error: {error_msg[:50]}", kind="error")

    def _on_candidate_selected(self):
        """Mostrar detalles del candidato seleccionado."""
        rows = self.candidates_table.selectionModel().selectedRows()
        if not rows:
            return

        row = rows[0].row()
        if row < len(self.candidates_data):
            c = self.candidates_data[row]
            details = f"""URL: {c['url']}

Fuente: {c['source']}
Confianza: {c['confidence']:.0f}%
Categoria: {c.get('category', 'N/A')}
Coincidencias: {', '.join(c['matched']) if c['matched'] else 'Ninguna'}

Snippet:
{c['snippet'][:300] if c['snippet'] else 'Sin descripcion'}
"""
            self.candidate_details.setPlainText(details)

    def _on_open_url(self, item):
        """Abrir URL del candidato en el navegador."""
        row = item.row()
        if row < len(self.candidates_data):
            url = self.candidates_data[row]['url']
            import webbrowser
            webbrowser.open(url)
            self._log(f"Abriendo: {url}")

    def _on_confirm_candidate(self):
        """Confirmar candidato seleccionado."""
        rows = self.candidates_table.selectionModel().selectedRows()
        if not rows:
            self.app.toast.show("Selecciona un candidato", kind="error")
            return

        row = rows[0].row()
        if row < len(self.candidates_data):
            c = self.candidates_data[row]
            url = c['url']

            self.confirmed_urls.add(url)
            if url in self.rejected_urls:
                self.rejected_urls.remove(url)

            # Actualizar tabla
            self.candidates_table.item(row, 5).setText("✅ Confirmado")
            self.candidates_table.item(row, 5).setForeground(QColor("#00ff66"))

            # Agregar a lista confirmada
            summary = f"[{c['source']}] {c['title'][:50]}"
            self.confirmed_list.appendPlainText(f"✅ {summary}")

            self._log(f"Confirmado: {summary}")
            self.app.toast.show("Candidato confirmado", kind="success")

    def _on_reject_candidate(self):
        """Descartar candidato seleccionado."""
        rows = self.candidates_table.selectionModel().selectedRows()
        if not rows:
            self.app.toast.show("Selecciona un candidato", kind="error")
            return

        row = rows[0].row()
        if row < len(self.candidates_data):
            c = self.candidates_data[row]
            url = c['url']

            self.rejected_urls.add(url)
            if url in self.confirmed_urls:
                self.confirmed_urls.remove(url)

            # Actualizar tabla
            self.candidates_table.item(row, 5).setText("❌ Descartado")
            self.candidates_table.item(row, 5).setForeground(QColor("#dc2626"))

            self._log(f"Descartado: {c['title'][:50]}")
            self.app.toast.show("Candidato descartado", kind="info")

    def _on_refine(self):
        """Refinar busqueda con datos confirmados."""
        if not self.confirmed_urls:
            self.app.toast.show("Confirma al menos un candidato primero", kind="error")
            return

        self._log("Refinando busqueda con datos confirmados...")
        self.app.toast.show("Funcion de refinamiento en desarrollo", kind="info")

    def _on_export(self):
        """Exportar perfil completo."""
        if not self.candidates_data:
            self.app.toast.show("No hay datos para exportar", kind="error")
            return

        # Generar reporte
        report = {
            "timestamp": datetime.now().isoformat(),
            "seed": {
                "name": self.input_name.text(),
                "context": self.input_context.text(),
                "country": self.input_country.currentText(),
            },
            "confirmed": [
                c for c in self.candidates_data if c['url'] in self.confirmed_urls
            ],
            "rejected_count": len(self.rejected_urls),
            "total_candidates": len(self.candidates_data),
            "all_candidates": self.candidates_data[:50]
        }

        # Guardar en archivo
        output_dir = Path.home() / "Downloads"
        name = self.input_name.text().replace(" ", "_")[:20]
        output_file = output_dir / f"perfil_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

        self._log(f"Exportado: {output_file}")
        self.app.toast.show(f"Perfil exportado a {output_file.name}", kind="success")

    def _on_generate_dossier(self):
        """Generar ficha de inteligencia estilo militar."""
        if not self.candidates_data:
            self.app.toast.show("Ejecuta un perfilamiento primero", kind="error")
            return

        # Recopilar datos confirmados
        confirmed = [c for c in self.candidates_data if c['url'] in self.confirmed_urls]

        if not confirmed:
            # Si no hay confirmados, usar los de mayor confianza
            confirmed = [c for c in self.candidates_data if c['confidence'] >= 50][:5]

        if not confirmed:
            self.app.toast.show("Confirma algunos candidatos o espera resultados con confianza alta", kind="error")
            return

        self._log("Generando ficha de inteligencia...")

        # Buscar avatar/foto
        avatar_url = None
        for c in confirmed:
            raw = c.get('raw_data', {}) if isinstance(c.get('raw_data'), dict) else {}
            if raw.get('avatar_url'):
                avatar_url = raw['avatar_url']
                break

        # Generar HTML de la ficha
        html = self._generate_intel_dossier_html(confirmed, avatar_url)

        # Guardar archivo
        output_dir = Path.home() / "Downloads"
        name = self.input_name.text().replace(" ", "_")[:20] or "objetivo"
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f"FICHA_INTEL_{name}_{timestamp}.html"

        output_file.write_text(html, encoding="utf-8")

        # Abrir en navegador
        import webbrowser
        webbrowser.open(f"file://{output_file}")

        self._log(f"Ficha generada: {output_file}")
        self.app.toast.show("Ficha de inteligencia generada", kind="success")

    def _generate_intel_dossier_html(self, confirmed: List[Dict], avatar_url: str = None) -> str:
        """Genera HTML de ficha de inteligencia estilo militar."""
        import html as html_lib

        name = self.input_name.text() or "DESCONOCIDO"
        context = self.input_context.text() or "-"
        country = self.input_country.currentText() or "-"
        username = self.input_username.text() or "-"
        email = self.input_email.text() or "-"
        phone = self.input_phone.text() or "-"
        domain = self.input_domain.text() or "-"

        # Extraer datos adicionales de candidatos confirmados
        usernames_found = set()
        emails_found = set()
        locations_found = set()
        companies_found = set()
        urls_found = []

        for c in confirmed:
            urls_found.append({
                'source': c.get('source', 'N/A'),
                'url': c.get('url', ''),
                'title': c.get('title', '')[:80],
                'confidence': c.get('confidence', 0)
            })

            raw = c.get('raw_data', {}) if isinstance(c.get('raw_data'), dict) else {}
            if raw.get('username'):
                usernames_found.add(raw['username'])
            if raw.get('email'):
                emails_found.add(raw['email'])
            if raw.get('location'):
                locations_found.add(raw['location'])
            if raw.get('company'):
                companies_found.add(raw['company'])

        # Avatar placeholder si no hay
        if not avatar_url:
            avatar_url = "https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y&s=200"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC-5")
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        # Generar filas de URLs
        urls_html = ""
        for i, u in enumerate(urls_found[:15], 1):
            conf_color = "#00ff66" if u['confidence'] >= 70 else "#ffaa00" if u['confidence'] >= 40 else "#ff4444"
            urls_html += f"""
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #333;">{i}</td>
                <td style="padding: 8px; border-bottom: 1px solid #333;">{html_lib.escape(u['source'])}</td>
                <td style="padding: 8px; border-bottom: 1px solid #333;">
                    <a href="{html_lib.escape(u['url'])}" target="_blank" style="color: #00d4ff;">{html_lib.escape(u['title'][:60])}</a>
                </td>
                <td style="padding: 8px; border-bottom: 1px solid #333; color: {conf_color}; font-weight: bold;">{u['confidence']:.0f}%</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FICHA DE INTELIGENCIA - {html_lib.escape(name)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', 'Arial', sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #0a0a0a 100%);
            color: #E0E6ED;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: linear-gradient(180deg, #0d1521 0%, #0a1628 100%);
            border: 2px solid #00d4ff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 0 30px rgba(0, 212, 255, 0.3);
        }}
        .header {{
            background: linear-gradient(90deg, #001a33 0%, #003366 50%, #001a33 100%);
            padding: 20px;
            display: flex;
            align-items: center;
            border-bottom: 3px solid #00d4ff;
        }}
        .header-left {{
            flex: 1;
        }}
        .classification {{
            background: #dc2626;
            color: white;
            padding: 5px 15px;
            font-size: 12px;
            font-weight: bold;
            letter-spacing: 2px;
            border-radius: 3px;
            display: inline-block;
            margin-bottom: 10px;
        }}
        .header h1 {{
            color: #00d4ff;
            font-size: 24px;
            letter-spacing: 3px;
            text-transform: uppercase;
        }}
        .header .case-id {{
            color: #8A9AA9;
            font-size: 12px;
            margin-top: 5px;
        }}
        .header-logo {{
            width: 80px;
            height: 80px;
            background: #0a1628;
            border: 2px solid #00d4ff;
            border-radius: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
        }}
        .subject-section {{
            display: flex;
            padding: 25px;
            border-bottom: 1px solid #1e3a5f;
            gap: 25px;
        }}
        .photo-container {{
            width: 180px;
            flex-shrink: 0;
        }}
        .photo {{
            width: 180px;
            height: 200px;
            background: #1a1a2e;
            border: 3px solid #00d4ff;
            border-radius: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }}
        .photo img {{
            width: 100%;
            height: 100%;
            object-fit: cover;
        }}
        .photo-label {{
            text-align: center;
            margin-top: 8px;
            font-size: 11px;
            color: #8A9AA9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .subject-info {{
            flex: 1;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }}
        .info-item {{
            background: #0a1628;
            border: 1px solid #1e3a5f;
            border-radius: 4px;
            padding: 12px;
        }}
        .info-item.full {{
            grid-column: span 2;
        }}
        .info-label {{
            color: #00d4ff;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }}
        .info-value {{
            color: #E0E6ED;
            font-size: 14px;
            font-weight: 500;
        }}
        .section {{
            padding: 20px 25px;
            border-bottom: 1px solid #1e3a5f;
        }}
        .section-title {{
            color: #00d4ff;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 1px solid #1e3a5f;
        }}
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }}
        .data-table th {{
            background: #001a33;
            color: #00d4ff;
            padding: 10px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 1px;
        }}
        .data-table td {{
            padding: 8px 10px;
            border-bottom: 1px solid #1e3a5f;
        }}
        .tag {{
            display: inline-block;
            background: #1e3a5f;
            color: #00d4ff;
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 11px;
            margin: 2px;
        }}
        .footer {{
            background: #001a33;
            padding: 15px 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 11px;
            color: #8A9AA9;
        }}
        .footer .stamp {{
            color: #dc2626;
            font-weight: bold;
            letter-spacing: 1px;
        }}
        .confidence-bar {{
            height: 6px;
            background: #1e3a5f;
            border-radius: 3px;
            overflow: hidden;
            margin-top: 5px;
        }}
        .confidence-fill {{
            height: 100%;
            background: linear-gradient(90deg, #00d4ff, #00ff66);
            border-radius: 3px;
        }}
        @media print {{
            body {{ background: white; color: black; }}
            .container {{ border: 2px solid #333; box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-left">
                <div class="classification">CONFIDENCIAL - OSINT</div>
                <h1>FICHA DE INTELIGENCIA</h1>
                <div class="case-id">{case_id} | {timestamp}</div>
            </div>
            <div class="header-logo">🔍</div>
        </div>

        <div class="subject-section">
            <div class="photo-container">
                <div class="photo">
                    <img src="{html_lib.escape(avatar_url)}" alt="Foto del objetivo" onerror="this.src='https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y&s=200'">
                </div>
                <div class="photo-label">Foto del Objetivo</div>
            </div>
            <div class="subject-info">
                <div class="info-grid">
                    <div class="info-item full">
                        <div class="info-label">Nombre Completo</div>
                        <div class="info-value" style="font-size: 18px; color: #00d4ff;">{html_lib.escape(name)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Pais / Nacionalidad</div>
                        <div class="info-value">{html_lib.escape(country)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Username Principal</div>
                        <div class="info-value">{html_lib.escape(username)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Email</div>
                        <div class="info-value">{html_lib.escape(email)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Telefono</div>
                        <div class="info-value">{html_lib.escape(phone)}</div>
                    </div>
                    <div class="info-item full">
                        <div class="info-label">Contexto / Afiliacion</div>
                        <div class="info-value">{html_lib.escape(context)}</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Identidades Digitales Confirmadas</div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                {''.join(f'<span class="tag">@{html_lib.escape(u)}</span>' for u in usernames_found) or '<span style="color: #8A9AA9;">Sin usernames adicionales</span>'}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Emails Asociados</div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                {''.join(f'<span class="tag">{html_lib.escape(e)}</span>' for e in emails_found) or '<span style="color: #8A9AA9;">Sin emails adicionales</span>'}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Ubicaciones Detectadas</div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                {''.join(f'<span class="tag">📍 {html_lib.escape(l)}</span>' for l in locations_found) or '<span style="color: #8A9AA9;">Sin ubicaciones detectadas</span>'}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Organizaciones / Empresas</div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                {''.join(f'<span class="tag">🏢 {html_lib.escape(c)}</span>' for c in companies_found) or '<span style="color: #8A9AA9;">Sin empresas detectadas</span>'}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Fuentes de Inteligencia ({len(urls_found)} registros)</div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th style="width: 40px;">#</th>
                        <th style="width: 120px;">Fuente</th>
                        <th>Descripcion</th>
                        <th style="width: 80px;">Confianza</th>
                    </tr>
                </thead>
                <tbody>
                    {urls_html}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <div>
                <strong>SENTINEL OSINT Platform</strong> | Generado automaticamente
            </div>
            <div class="stamp">
                DOCUMENTO DE INTELIGENCIA
            </div>
        </div>
    </div>
</body>
</html>"""
        return html

    def refresh(self):
        """Refrescar tab."""
        pass
