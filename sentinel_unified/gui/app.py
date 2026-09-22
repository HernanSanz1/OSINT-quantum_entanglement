"""
SENTINEL UNIFIED - Main Application
GUI unificada para Profile, Recon y CTI
"""
import sys
import os
import json
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QFrame, QSplitter, QListWidget,
    QListWidgetItem, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTreeWidget, QTreeWidgetItem, QComboBox, QSpinBox, QCheckBox,
    QProgressBar, QStatusBar, QMessageBox, QDialog, QFormLayout,
    QGroupBox, QScrollArea, QStackedWidget, QHeaderView
)
from PySide6.QtCore import Qt, QThread, Signal, QSize
from PySide6.QtGui import QFont, QIcon

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, Case, Target, Asset, IOC, CaseType, CaseStatus
from core.graph import GraphEngine


class NewCaseDialog(QDialog):
    """Dialogo para crear nuevo caso"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nuevo Caso")
        self.setMinimumWidth(400)

        layout = QFormLayout(self)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Nombre del caso...")
        layout.addRow("Nombre:", self.name_input)

        self.desc_input = QTextEdit()
        self.desc_input.setPlaceholderText("Descripcion...")
        self.desc_input.setMaximumHeight(80)
        layout.addRow("Descripcion:", self.desc_input)

        self.type_combo = QComboBox()
        self.type_combo.addItems(["profile", "recon", "cti", "mixed"])
        layout.addRow("Tipo:", self.type_combo)

        btn_layout = QHBoxLayout()
        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.clicked.connect(self.reject)
        self.btn_create = QPushButton("Crear")
        self.btn_create.setObjectName("btnPrimary")
        self.btn_create.clicked.connect(self.accept)
        btn_layout.addWidget(self.btn_cancel)
        btn_layout.addWidget(self.btn_create)
        layout.addRow(btn_layout)

    def get_data(self):
        return {
            "name": self.name_input.text(),
            "description": self.desc_input.toPlainText(),
            "case_type": self.type_combo.currentText()
        }


class SentinelGUI(QMainWindow):
    """Ventana principal de Sentinel Unified"""

    def __init__(self):
        super().__init__()
        self.current_case_id = None
        self.setup_ui()
        self.load_cases()

    def setup_ui(self):
        self.setWindowTitle("SENTINEL UNIFIED")
        self.setMinimumSize(1400, 900)

        # Widget central
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Splitter principal
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)

        # ══════════════════════════════════════════════════════════════════════
        # SIDEBAR (Cases)
        # ══════════════════════════════════════════════════════════════════════
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QFrame()
        header.setObjectName("headerFrame")
        header_layout = QVBoxLayout(header)
        title = QLabel("SENTINEL")
        title.setObjectName("lblTitle")
        title.setAlignment(Qt.AlignCenter)
        subtitle = QLabel("UNIFIED INTELLIGENCE")
        subtitle.setObjectName("lblSubtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        sidebar_layout.addWidget(header)

        # Case list
        cases_label = QLabel("  CASOS")
        cases_label.setObjectName("lblSection")
        sidebar_layout.addWidget(cases_label)

        self.case_list = QListWidget()
        self.case_list.setObjectName("caseList")
        self.case_list.itemClicked.connect(self.on_case_selected)
        sidebar_layout.addWidget(self.case_list)

        # Buttons
        btn_frame = QFrame()
        btn_layout = QHBoxLayout(btn_frame)
        self.btn_new_case = QPushButton("+ Nuevo")
        self.btn_new_case.setObjectName("btnPrimary")
        self.btn_new_case.clicked.connect(self.create_case)
        self.btn_delete_case = QPushButton("Eliminar")
        self.btn_delete_case.setObjectName("btnDelete")
        self.btn_delete_case.clicked.connect(self.delete_case)
        btn_layout.addWidget(self.btn_new_case)
        btn_layout.addWidget(self.btn_delete_case)
        sidebar_layout.addWidget(btn_frame)

        splitter.addWidget(sidebar)

        # ══════════════════════════════════════════════════════════════════════
        # MAIN CONTENT (Tabs)
        # ══════════════════════════════════════════════════════════════════════
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)

        # Active case indicator
        self.active_case_label = QLabel("Ningun caso seleccionado")
        self.active_case_label.setObjectName("lblMuted")
        self.active_case_label.setAlignment(Qt.AlignCenter)
        content_layout.addWidget(self.active_case_label)

        # Tab widget
        self.tabs = QTabWidget()
        content_layout.addWidget(self.tabs)

        # Tab: PROFILE
        self.tab_profile = self.create_profile_tab()
        self.tabs.addTab(self.tab_profile, "PROFILE")

        # Tab: RECON
        self.tab_recon = self.create_recon_tab()
        self.tabs.addTab(self.tab_recon, "RECON")

        # Tab: CTI
        self.tab_cti = self.create_cti_tab()
        self.tabs.addTab(self.tab_cti, "CTI")

        # Tab: GRAPH
        self.tab_graph = self.create_graph_tab()
        self.tabs.addTab(self.tab_graph, "GRAPH")

        # Tab: REPORTS
        self.tab_reports = self.create_reports_tab()
        self.tabs.addTab(self.tab_reports, "REPORTS")

        splitter.addWidget(content)
        splitter.setSizes([220, 1180])

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Listo")

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: PROFILE
    # ══════════════════════════════════════════════════════════════════════════
    def create_profile_tab(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)

        # Left: Target info
        left = QFrame()
        left.setObjectName("card")
        left_layout = QVBoxLayout(left)

        lbl = QLabel("OBJETIVO")
        lbl.setObjectName("lblSection")
        left_layout.addWidget(lbl)

        form = QFormLayout()
        self.profile_name = QLineEdit()
        self.profile_name.setPlaceholderText("Nombre completo...")
        form.addRow("Nombre:", self.profile_name)

        self.profile_email = QLineEdit()
        self.profile_email.setPlaceholderText("correo@dominio.com")
        form.addRow("Email:", self.profile_email)

        self.profile_username = QLineEdit()
        self.profile_username.setPlaceholderText("@username")
        form.addRow("Username:", self.profile_username)

        self.profile_phone = QLineEdit()
        self.profile_phone.setPlaceholderText("+593...")
        form.addRow("Telefono:", self.profile_phone)

        self.profile_company = QLineEdit()
        self.profile_company.setPlaceholderText("Empresa...")
        form.addRow("Empresa:", self.profile_company)

        left_layout.addLayout(form)

        btn_add_target = QPushButton("Agregar Objetivo")
        btn_add_target.setObjectName("btnPrimary")
        btn_add_target.clicked.connect(self.add_target)
        left_layout.addWidget(btn_add_target)

        left_layout.addStretch()
        layout.addWidget(left)

        # Middle: Tools
        middle = QFrame()
        middle.setObjectName("card")
        middle_layout = QVBoxLayout(middle)

        lbl2 = QLabel("HERRAMIENTAS")
        lbl2.setObjectName("lblSection")
        middle_layout.addWidget(lbl2)

        self.profile_tools = QTreeWidget()
        self.profile_tools.setHeaderLabels(["Herramienta", "Estado"])
        self.profile_tools.setColumnWidth(0, 180)

        tools = [
            ("Sherlock", "Usernames en +300 sitios"),
            ("Holehe", "Email en servicios"),
            ("Maigret", "Username profundo"),
            ("GHunt", "Google account"),
            ("Hunter.io", "Emails corporativos"),
            ("Google Dorks", "Busqueda avanzada"),
        ]
        for name, desc in tools:
            item = QTreeWidgetItem([name, "Disponible"])
            item.setToolTip(0, desc)
            self.profile_tools.addTopLevelItem(item)

        middle_layout.addWidget(self.profile_tools)

        btn_run_profile = QPushButton("Ejecutar Seleccionadas")
        btn_run_profile.setObjectName("btnRun")
        btn_run_profile.clicked.connect(self.run_profile_tools)
        middle_layout.addWidget(btn_run_profile)

        layout.addWidget(middle)

        # Right: Results
        right = QFrame()
        right.setObjectName("card")
        right_layout = QVBoxLayout(right)

        lbl3 = QLabel("RESULTADOS")
        lbl3.setObjectName("lblSection")
        right_layout.addWidget(lbl3)

        self.profile_results = QTableWidget()
        self.profile_results.setColumnCount(4)
        self.profile_results.setHorizontalHeaderLabels(["Tipo", "Valor", "Fuente", "Confianza"])
        self.profile_results.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        right_layout.addWidget(self.profile_results)

        layout.addWidget(right)

        return widget

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: RECON
    # ══════════════════════════════════════════════════════════════════════════
    def create_recon_tab(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)

        # Left: Target input
        left = QFrame()
        left.setObjectName("card")
        left_layout = QVBoxLayout(left)

        lbl = QLabel("OBJETIVO")
        lbl.setObjectName("lblSection")
        left_layout.addWidget(lbl)

        form = QFormLayout()
        self.recon_domain = QLineEdit()
        self.recon_domain.setPlaceholderText("dominio.com")
        form.addRow("Dominio:", self.recon_domain)

        self.recon_ip = QLineEdit()
        self.recon_ip.setPlaceholderText("192.168.1.1")
        form.addRow("IP:", self.recon_ip)

        left_layout.addLayout(form)

        btn_add_asset = QPushButton("Agregar Asset")
        btn_add_asset.setObjectName("btnPrimary")
        btn_add_asset.clicked.connect(self.add_asset)
        left_layout.addWidget(btn_add_asset)

        left_layout.addStretch()
        layout.addWidget(left)

        # Middle: Tools
        middle = QFrame()
        middle.setObjectName("card")
        middle_layout = QVBoxLayout(middle)

        lbl2 = QLabel("HERRAMIENTAS")
        lbl2.setObjectName("lblSection")
        middle_layout.addWidget(lbl2)

        self.recon_tools = QTreeWidget()
        self.recon_tools.setHeaderLabels(["Herramienta", "Estado"])
        self.recon_tools.setColumnWidth(0, 180)

        tools = [
            ("Subfinder", "Subdominios pasivos"),
            ("Amass", "Enum completa"),
            ("TheHarvester", "Emails y hosts"),
            ("Censys", "Certificados e IPs"),
            ("Wayback", "Historico web"),
            ("DNS Tools", "Registros DNS"),
            ("IP Whois", "Info de IP/ASN"),
        ]
        for name, desc in tools:
            item = QTreeWidgetItem([name, "Disponible"])
            item.setToolTip(0, desc)
            self.recon_tools.addTopLevelItem(item)

        middle_layout.addWidget(self.recon_tools)

        btn_run_recon = QPushButton("Ejecutar Seleccionadas")
        btn_run_recon.setObjectName("btnRun")
        btn_run_recon.clicked.connect(self.run_recon_tools)
        middle_layout.addWidget(btn_run_recon)

        layout.addWidget(middle)

        # Right: Results
        right = QFrame()
        right.setObjectName("card")
        right_layout = QVBoxLayout(right)

        lbl3 = QLabel("ASSETS DESCUBIERTOS")
        lbl3.setObjectName("lblSection")
        right_layout.addWidget(lbl3)

        self.recon_results = QTableWidget()
        self.recon_results.setColumnCount(4)
        self.recon_results.setHorizontalHeaderLabels(["Tipo", "Valor", "Fuente", "Primera vez"])
        self.recon_results.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        right_layout.addWidget(self.recon_results)

        layout.addWidget(right)

        return widget

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: CTI
    # ══════════════════════════════════════════════════════════════════════════
    def create_cti_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Top: Actions
        top = QFrame()
        top.setObjectName("card")
        top_layout = QHBoxLayout(top)

        btn_harvest = QPushButton("Recolectar Feeds")
        btn_harvest.setObjectName("btnPrimary")
        btn_harvest.clicked.connect(self.harvest_cti)
        top_layout.addWidget(btn_harvest)

        btn_dossier = QPushButton("Generar Dossier")
        btn_dossier.clicked.connect(self.generate_dossier)
        top_layout.addWidget(btn_dossier)

        self.cti_client = QComboBox()
        self.cti_client.addItems(["GLOBAL", "CER", "MAVESA", "XTRIM", "SERVIANDINA"])
        top_layout.addWidget(QLabel("Cliente:"))
        top_layout.addWidget(self.cti_client)

        top_layout.addStretch()

        btn_render = QPushButton("Render HTML")
        btn_render.clicked.connect(self.render_cti)
        top_layout.addWidget(btn_render)

        layout.addWidget(top)

        # Bottom: Items table
        lbl = QLabel("ITEMS CTI")
        lbl.setObjectName("lblSection")
        layout.addWidget(lbl)

        self.cti_table = QTableWidget()
        self.cti_table.setColumnCount(5)
        self.cti_table.setHorizontalHeaderLabels(["Fuente", "Titulo", "CVEs", "Fecha", "Tags"])
        self.cti_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.cti_table)

        return widget

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: GRAPH
    # ══════════════════════════════════════════════════════════════════════════
    def create_graph_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Controls
        controls = QFrame()
        controls.setObjectName("card")
        ctrl_layout = QHBoxLayout(controls)

        btn_refresh = QPushButton("Actualizar Grafo")
        btn_refresh.setObjectName("btnPrimary")
        btn_refresh.clicked.connect(self.refresh_graph)
        ctrl_layout.addWidget(btn_refresh)

        btn_auto = QPushButton("Auto-correlacionar")
        btn_auto.clicked.connect(self.auto_correlate)
        ctrl_layout.addWidget(btn_auto)

        ctrl_layout.addStretch()

        # Stats
        self.graph_stats = QLabel("Nodos: 0 | Aristas: 0")
        ctrl_layout.addWidget(self.graph_stats)

        layout.addWidget(controls)

        # Graph area (placeholder - needs pyqtgraph or web view)
        self.graph_frame = QFrame()
        self.graph_frame.setObjectName("graphPanel")
        self.graph_frame.setMinimumHeight(500)
        graph_layout = QVBoxLayout(self.graph_frame)
        graph_placeholder = QLabel("Grafo se mostrara aqui\n\nSelecciona un caso y presiona 'Actualizar Grafo'")
        graph_placeholder.setAlignment(Qt.AlignCenter)
        graph_placeholder.setObjectName("lblMuted")
        graph_layout.addWidget(graph_placeholder)
        layout.addWidget(self.graph_frame)

        return widget

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: REPORTS
    # ══════════════════════════════════════════════════════════════════════════
    def create_reports_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        lbl = QLabel("GENERADOR DE REPORTES")
        lbl.setObjectName("lblSection")
        layout.addWidget(lbl)

        # Report types
        types_frame = QFrame()
        types_frame.setObjectName("card")
        types_layout = QHBoxLayout(types_frame)

        btn_profile_report = QPushButton("Reporte de Persona")
        btn_profile_report.setObjectName("btnPrimary")
        btn_profile_report.clicked.connect(lambda: self.generate_report("profile"))
        types_layout.addWidget(btn_profile_report)

        btn_recon_report = QPushButton("Reporte de Infra")
        btn_recon_report.clicked.connect(lambda: self.generate_report("recon"))
        types_layout.addWidget(btn_recon_report)

        btn_cti_report = QPushButton("Boletin CTI")
        btn_cti_report.clicked.connect(lambda: self.generate_report("cti"))
        types_layout.addWidget(btn_cti_report)

        btn_unified_report = QPushButton("Reporte Unificado (Actor)")
        btn_unified_report.setObjectName("btnSuccess")
        btn_unified_report.clicked.connect(lambda: self.generate_report("unified"))
        types_layout.addWidget(btn_unified_report)

        layout.addWidget(types_frame)

        # Report preview
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setPlaceholderText("Vista previa del reporte...")
        layout.addWidget(self.report_preview)

        # Export buttons
        export_frame = QFrame()
        export_layout = QHBoxLayout(export_frame)
        export_layout.addStretch()

        btn_export_html = QPushButton("Exportar HTML")
        btn_export_html.clicked.connect(lambda: self.export_report("html"))
        export_layout.addWidget(btn_export_html)

        btn_export_pdf = QPushButton("Exportar PDF")
        btn_export_pdf.clicked.connect(lambda: self.export_report("pdf"))
        export_layout.addWidget(btn_export_pdf)

        btn_export_json = QPushButton("Exportar JSON")
        btn_export_json.clicked.connect(lambda: self.export_report("json"))
        export_layout.addWidget(btn_export_json)

        layout.addWidget(export_frame)

        return widget

    # ══════════════════════════════════════════════════════════════════════════
    # CASE MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════════
    def load_cases(self):
        self.case_list.clear()
        cases = db.get_cases()
        for c in cases:
            item = QListWidgetItem(f"{c.name} [{c.case_type.value}]")
            item.setData(Qt.UserRole, c.id)
            self.case_list.addItem(item)

    def create_case(self):
        dialog = NewCaseDialog(self)
        if dialog.exec() == QDialog.Accepted:
            data = dialog.get_data()
            if not data["name"]:
                QMessageBox.warning(self, "Error", "El nombre es requerido")
                return
            case = Case(
                name=data["name"],
                description=data["description"],
                case_type=CaseType(data["case_type"])
            )
            case_id = db.create_case(case)
            self.load_cases()
            self.status_bar.showMessage(f"Caso '{data['name']}' creado (ID: {case_id})")

    def delete_case(self):
        item = self.case_list.currentItem()
        if not item:
            return
        case_id = item.data(Qt.UserRole)
        reply = QMessageBox.question(
            self, "Confirmar",
            f"Eliminar caso '{item.text()}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            db.delete_case(case_id)
            self.load_cases()
            self.current_case_id = None
            self.active_case_label.setText("Ningun caso seleccionado")
            self.status_bar.showMessage("Caso eliminado")

    def on_case_selected(self, item):
        self.current_case_id = item.data(Qt.UserRole)
        case = db.get_case(self.current_case_id)
        if case:
            self.active_case_label.setText(f"Caso activo: {case.name} ({case.case_type.value})")
            self.load_case_data()

    def load_case_data(self):
        if not self.current_case_id:
            return

        # Load targets
        targets = db.get_targets(self.current_case_id)
        self.profile_results.setRowCount(len(targets))
        for i, t in enumerate(targets):
            self.profile_results.setItem(i, 0, QTableWidgetItem("target"))
            self.profile_results.setItem(i, 1, QTableWidgetItem(t.name or t.email))
            self.profile_results.setItem(i, 2, QTableWidgetItem(t.source))
            self.profile_results.setItem(i, 3, QTableWidgetItem(str(t.confidence)))

        # Load assets
        assets = db.get_assets(self.current_case_id)
        self.recon_results.setRowCount(len(assets))
        for i, a in enumerate(assets):
            self.recon_results.setItem(i, 0, QTableWidgetItem(a.asset_type))
            self.recon_results.setItem(i, 1, QTableWidgetItem(a.value))
            self.recon_results.setItem(i, 2, QTableWidgetItem(a.source_tool))
            self.recon_results.setItem(i, 3, QTableWidgetItem(a.first_seen[:10]))

    # ══════════════════════════════════════════════════════════════════════════
    # PROFILE ACTIONS
    # ══════════════════════════════════════════════════════════════════════════
    def add_target(self):
        if not self.current_case_id:
            QMessageBox.warning(self, "Error", "Selecciona un caso primero")
            return

        target = Target(
            case_id=self.current_case_id,
            name=self.profile_name.text(),
            email=self.profile_email.text(),
            username=self.profile_username.text(),
            phone=self.profile_phone.text(),
            company=self.profile_company.text(),
            source="manual",
            confidence=80
        )
        db.add_target(target)
        self.load_case_data()
        self.status_bar.showMessage("Objetivo agregado")

        # Clear inputs
        self.profile_name.clear()
        self.profile_email.clear()
        self.profile_username.clear()
        self.profile_phone.clear()
        self.profile_company.clear()

    def run_profile_tools(self):
        if not self.current_case_id:
            QMessageBox.warning(self, "Error", "Selecciona un caso primero")
            return
        self.status_bar.showMessage("Ejecutando herramientas de perfilamiento...")
        # TODO: Implementar ejecucion real
        QMessageBox.information(self, "Info", "Funcionalidad en desarrollo")

    # ══════════════════════════════════════════════════════════════════════════
    # RECON ACTIONS
    # ══════════════════════════════════════════════════════════════════════════
    def add_asset(self):
        if not self.current_case_id:
            QMessageBox.warning(self, "Error", "Selecciona un caso primero")
            return

        domain = self.recon_domain.text().strip()
        ip = self.recon_ip.text().strip()

        if domain:
            asset = Asset(
                case_id=self.current_case_id,
                asset_type="domain",
                value=domain,
                source_tool="manual",
                confidence=80
            )
            db.add_asset(asset)

        if ip:
            asset = Asset(
                case_id=self.current_case_id,
                asset_type="ip",
                value=ip,
                source_tool="manual",
                confidence=80
            )
            db.add_asset(asset)

        self.load_case_data()
        self.status_bar.showMessage("Asset agregado")
        self.recon_domain.clear()
        self.recon_ip.clear()

    def run_recon_tools(self):
        if not self.current_case_id:
            QMessageBox.warning(self, "Error", "Selecciona un caso primero")
            return
        self.status_bar.showMessage("Ejecutando herramientas de reconocimiento...")
        # TODO: Implementar ejecucion real
        QMessageBox.information(self, "Info", "Funcionalidad en desarrollo")

    # ══════════════════════════════════════════════════════════════════════════
    # CTI ACTIONS
    # ══════════════════════════════════════════════════════════════════════════
    def harvest_cti(self):
        self.status_bar.showMessage("Recolectando feeds CTI...")
        # TODO: Ejecutar harvest.py
        QMessageBox.information(self, "Info", "Funcionalidad en desarrollo - ejecutar harvest.py")

    def generate_dossier(self):
        client = self.cti_client.currentText()
        self.status_bar.showMessage(f"Generando dossier para {client}...")
        # TODO: Ejecutar dossier.py
        QMessageBox.information(self, "Info", f"Funcionalidad en desarrollo - dossier para {client}")

    def render_cti(self):
        self.status_bar.showMessage("Renderizando HTML...")
        # TODO: Ejecutar render.py
        QMessageBox.information(self, "Info", "Funcionalidad en desarrollo - render.py")

    # ══════════════════════════════════════════════════════════════════════════
    # GRAPH ACTIONS
    # ══════════════════════════════════════════════════════════════════════════
    def refresh_graph(self):
        if not self.current_case_id:
            QMessageBox.warning(self, "Error", "Selecciona un caso primero")
            return

        engine = GraphEngine(self.current_case_id)
        engine.load_from_db()
        stats = engine.stats()
        self.graph_stats.setText(
            f"Nodos: {stats['total_nodes']} | Aristas: {stats['total_edges']}"
        )
        self.status_bar.showMessage("Grafo actualizado")
        # TODO: Renderizar grafo con pyqtgraph o vis.js

    def auto_correlate(self):
        if not self.current_case_id:
            QMessageBox.warning(self, "Error", "Selecciona un caso primero")
            return

        engine = GraphEngine(self.current_case_id)
        engine.load_from_db()
        engine.auto_correlate()
        self.refresh_graph()
        self.status_bar.showMessage("Auto-correlacion completada")

    # ══════════════════════════════════════════════════════════════════════════
    # REPORTS ACTIONS
    # ══════════════════════════════════════════════════════════════════════════
    def generate_report(self, report_type):
        if not self.current_case_id and report_type != "cti":
            QMessageBox.warning(self, "Error", "Selecciona un caso primero")
            return

        self.status_bar.showMessage(f"Generando reporte {report_type}...")
        # TODO: Implementar generadores de reportes
        self.report_preview.setText(f"[Vista previa del reporte {report_type}]\n\nFuncionalidad en desarrollo...")

    def export_report(self, fmt):
        self.status_bar.showMessage(f"Exportando a {fmt}...")
        # TODO: Implementar exportacion
        QMessageBox.information(self, "Info", f"Exportacion a {fmt} en desarrollo")


def main():
    app = QApplication(sys.argv)

    # Load stylesheet
    qss_path = Path(__file__).parent / "style.qss"
    if qss_path.exists():
        with open(qss_path, "r") as f:
            app.setStyleSheet(f.read())

    window = SentinelGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
