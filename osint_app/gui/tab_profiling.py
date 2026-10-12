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
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTableWidget, QTableWidgetItem, QPlainTextEdit,
    QProgressBar, QFrame, QSplitter, QHeaderView, QGroupBox, QTextEdit, QComboBox,
    QListWidget, QListWidgetItem, QAbstractItemView
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from osint_app.profiler_engine import ProfilerEngine, SeedData, parse_list
from osint_app.tools import build_tool_registry


class ProfilerThread(QThread):
    """Thread para ejecutar el motor de perfilamiento sin bloquear la GUI"""
    progress = Signal(str)
    tool_done = Signal(str, int)  # nombre_herramienta, num_resultados
    candidates_ready = Signal(list)
    case_saved = Signal(int)      # case_id donde se guardaron los resultados
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

            # Ejecutar herramientas en paralelo (solo las seleccionadas, si hay),
            # con búsqueda encadenada: los usernames descubiertos disparan una
            # segunda ronda (GitHub/Sherlock/Maigret).
            self.engine.run_parallel(self.seed, max_workers=6, timeout_per_tool=90,
                                     only_tools=self.selected_tools, chain=True)

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
                    'warning': c.warning,
                    'extra': c.extra_data,
                }
                for c in candidates
            ]
            self.candidates_ready.emit(candidates_data)

            # Guardar los resultados en un caso para que no se pierdan
            try:
                case_id = self.engine.save_to_case(self.seed)
                self.case_saved.emit(case_id)
            except Exception as e:
                self.progress.emit(f"⚠️ No se pudieron guardar los resultados en un caso: {e}")

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

        # Más datos del objetivo (plegable, para no recargar la pantalla)
        self.btn_more = QPushButton("▸ Más datos del objetivo (alias, otros correos, ciudad…)")
        self.btn_more.setCheckable(True)
        self.btn_more.setStyleSheet("text-align: left; padding: 6px; background: transparent; color: #00d4ff; border: none;")
        self.btn_more.toggled.connect(self._toggle_more)
        left_layout.addWidget(self.btn_more)

        self.more_box = QWidget()
        more_layout = QVBoxLayout(self.more_box)
        more_layout.setContentsMargins(0, 0, 0, 0)
        more_layout.setSpacing(2)
        more_fields = (
            ("input_company", "Empresa donde trabaja", "Banco Pichincha"),
            ("input_university", "Universidad", "UTPL"),
            ("input_city", "Ciudad", "Loja"),
            ("input_aliases", "Alias, apodos o variantes del nombre (separados por coma)", "Carlos Andrade León, Charly Andrade"),
            ("input_more_emails", "Otros correos (separados por coma)", "otro@gmail.com, trabajo@empresa.com"),
            ("input_more_usernames", "Otros usernames (separados por coma)", "@charly, candrade"),
            ("input_more_phones", "Otros teléfonos (separados por coma)", "+593988888888"),
        )
        for attr, label, placeholder in more_fields:
            lbl = QLabel(label)
            lbl.setStyleSheet(label_style)
            more_layout.addWidget(lbl)
            edit_widget = QLineEdit()
            edit_widget.setPlaceholderText(placeholder)
            edit_widget.setStyleSheet(input_style)
            edit_widget.setFixedHeight(40)
            setattr(self, attr, edit_widget)
            more_layout.addWidget(edit_widget)
        self.more_box.setVisible(False)
        left_layout.addWidget(self.more_box)

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
        for widget in (self.input_company, self.input_university, self.input_city, self.input_aliases,
                       self.input_more_emails, self.input_more_usernames, self.input_more_phones):
            widget.clear()
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

    def _toggle_more(self, shown: bool):
        self.more_box.setVisible(shown)
        self.btn_more.setText(("▾" if shown else "▸") + " Más datos del objetivo (alias, otros correos, ciudad…)")

    def _seed_from_inputs(self) -> SeedData:
        """Arma la semilla con todos los campos de la pantalla, incluidos los datos adicionales."""
        return SeedData(
            name=self.input_name.text().strip(),
            context=self.input_context.text().strip(),
            country=self.input_country.currentText(),
            username=self.input_username.text().strip() or None,
            email=self.input_email.text().strip() or None,
            phone=self.input_phone.text().strip() or None,
            domain=self.input_domain.text().strip() or None,
            company=self.input_company.text().strip() or None,
            university=self.input_university.text().strip(),
            city=self.input_city.text().strip(),
            aliases=parse_list(self.input_aliases.text()),
            extra_emails=parse_list(self.input_more_emails.text()),
            extra_usernames=parse_list(self.input_more_usernames.text(), strip_at=True),
            extra_phones=parse_list(self.input_more_phones.text()),
        )

    def _on_search(self):
        """Iniciar perfilamiento con los datos semilla"""
        seed = self._seed_from_inputs()
        name, context, country = seed.name, seed.context, seed.country

        if not name:
            self.app.toast.show("Ingresa un nombre para buscar", kind="error")
            return

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
        self.profiler_thread.case_saved.connect(self._on_case_saved)
        self.profiler_thread.finished_ok.connect(self._on_search_done)
        self.profiler_thread.error.connect(self._on_error)
        self.profiler_thread.start()

    def _on_case_saved(self, case_id: int):
        """Activa el caso recién guardado y refresca las pestañas dependientes."""
        name = f"Perfil: {self.input_name.text().strip()}"
        self.app.active_case_id = case_id
        self.app.active_case_name = name
        self.app.case_badge.setText(f"CASO ACTIVO: #{case_id} — {name.upper()}")
        self._log(f"💾 Resultados guardados en el caso #{case_id}. Míralos en la pestaña Reportes.")
        for page_name, widget in self.app.pages:
            if page_name in ("Casos", "Datos", "Reportes") and hasattr(widget, "refresh"):
                widget.refresh()

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

            # Titulo (truncado); marca ⚠️ si hay aviso de homónimo
            title = c['title'][:60] + "..." if len(c['title']) > 60 else c['title']
            if c.get('warning'):
                title = f"⚠️ {title}"
            title_item = QTableWidgetItem(title)
            if c.get('warning'):
                title_item.setToolTip(c['warning'])
                title_item.setForeground(QColor("#ffaa00"))
            self.candidates_table.setItem(row, 1, title_item)

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
            aviso = f"\n⚠️  AVISO: {c['warning']}\n" if c.get('warning') else ""
            details = f"""URL: {c['url']}
{aviso}
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
            self._promote_to_case(c)

    def _promote_to_case(self, candidate: Dict):
        """Pasa al caso activo lo que aporta un candidato confirmado (usuario, correo, empresa, perfil…)."""
        case_id = getattr(self.app, "active_case_id", None)
        if not case_id:
            return
        try:
            from ..profiler_engine import promote_confirmed_to_case
            added = promote_confirmed_to_case(case_id, [candidate])
        except Exception as e:
            self._log(f"⚠️ No se pudo añadir al caso: {e}")
            return
        if added:
            self._log("📌 Añadido al caso: " + ", ".join(f"{k}={v}" for k, v in added))
            for page_name, widget in self.app.pages:
                if page_name in ("Datos", "Casos") and hasattr(widget, "refresh"):
                    widget.refresh()

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
        """Refinar búsqueda: enriquece la semilla con los candidatos confirmados
        (username, email, dominio) y vuelve a buscar."""
        if not self.confirmed_urls:
            self.app.toast.show("Confirma al menos un candidato primero", kind="error")
            return

        from ..profiler_engine import enrich_seed_from_candidates

        confirmed = [c for c in self.candidates_data if c.get("url") in self.confirmed_urls]
        base = self._seed_from_inputs()
        enriched = enrich_seed_from_candidates(base, confirmed)

        # Reflejar los datos nuevos en los campos para que el usuario los vea
        new_bits = []
        if enriched.username and not base.username:
            self.input_username.setText(enriched.username); new_bits.append(f"username={enriched.username}")
        if enriched.email and not base.email:
            self.input_email.setText(enriched.email); new_bits.append(f"email={enriched.email}")
        if enriched.domain and not base.domain:
            self.input_domain.setText(enriched.domain); new_bits.append(f"dominio={enriched.domain}")
        if enriched.company and not base.company:
            self.input_company.setText(enriched.company); new_bits.append(f"empresa={enriched.company}")

        if not new_bits:
            self.app.toast.show("Los candidatos confirmados no aportan datos nuevos", kind="info")
            self._log("Refinar: sin datos nuevos que añadir.")
            return

        self._log(f"🔁 Refinando con datos nuevos: {', '.join(new_bits)}")
        self.app.toast.show("Refinando búsqueda con los datos confirmados…", kind="info")
        self._on_search()

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
        """Genera la ficha legible de la persona (reports/person_report) y la abre en el navegador.

        Sustituye a la "ficha de inteligencia" anterior, cuyas secciones de datos salían siempre vacías y que
        cargaba imágenes de internet al abrirse (ver el módulo).
        """
        if not self.candidates_data:
            self.app.toast.show("Ejecuta un perfilamiento primero", kind="error")
            return
        from ..reports.person_report import build_person_report, render_person_html

        seed = self._seed_from_inputs()
        seed_dict = {"name": seed.name, "context": seed.context, "country": seed.country, "city": seed.city,
                     "username": seed.username, "email": seed.email, "phone": seed.phone, "domain": seed.domain}
        report = build_person_report(seed_dict, self.candidates_data, self.confirmed_urls, self.rejected_urls,
                                     case_id=getattr(self.app, "active_case_id", None))
        output_dir = Path.home() / "Downloads"
        output_dir.mkdir(parents=True, exist_ok=True)
        name = re.sub(r"[^\w-]+", "_", seed.name)[:30].strip("_") or "persona"
        output_file = output_dir / f"Ficha_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        output_file.write_text(render_person_html(report), encoding="utf-8")

        import webbrowser
        webbrowser.open(output_file.as_uri())
        self._log(f"Ficha generada: {output_file}")
        self.app.toast.show("Ficha generada y abierta en el navegador", kind="success")

    def refresh(self):
        """Refrescar tab."""
        pass
