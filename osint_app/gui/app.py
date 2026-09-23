import sys
import os
import psutil
import pyqtgraph as pg
from collections import deque
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QStackedWidget, QFrame, QProgressBar, QSizePolicy
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap  # noqa: F401 – kept for potential use in other widgets

from ..framework import OSINTFramework
from ..case_manager import CaseManager
from ..ai_engine import MultiLLMEngine
from ..utils.secret_vault import vault
from .components import ToastManager, BrandLogo, HudStatPanel, TopBarContainer, SideBarContainer

from .tab_cases import CasesTab
from .tab_data import DataTab
from .tab_tools import ToolsTab
from .tab_reports import ReportsTab
from .tab_ai import AITab
from .tab_cti import CTITab
from .tab_correlation import CorrelationTab
from .tab_profiling import ProfilingTab

class OSINTGUI(QMainWindow):
    """Main application window — Sentinel PySide6 Qt Edition."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SENTINEL SOC Dashboard")
        self.resize(1440, 900)
        self.setMinimumSize(1100, 700)

        self.framework  = OSINTFramework()
        self.case_mgr   = CaseManager()
        self.ai_engine  = MultiLLMEngine(
            openai_key=vault.get("ChatGPT"),
            venice_key=vault.get("Venice"),
        )
        self.active_case_id = None
        self.active_case_name = ""
        self._use_tor_proxy = False

        # Root layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.root_layout = QVBoxLayout(central_widget)
        self.root_layout.setContentsMargins(8, 8, 8, 8)   # margen exterior de la ventana
        self.root_layout.setSpacing(6)                      # espacio entre topbar y contenido

        self.toast = ToastManager(self)
        
        self.cpu_history = deque([0]*40, maxlen=40)
        self._build_topbar()
        
        # Mid Section: Left Sidebar + Tab Content
        self.mid_layout = QHBoxLayout()
        self.root_layout.addLayout(self.mid_layout, 1) # stretch 1
        
        self._build_sidebar()
        self._build_tabs_and_content()

        self._build_statusbar()
        
        # Update stats
        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self._update_stats)
        self.stats_timer.start(2000)
        self._update_stats()

    def _build_topbar(self):
        # ─────────────────────────────────────────────────────────────────
        # TopBarContainer: posicionamiento ABSOLUTO por widget
        # altura=110 es el alto total del topbar; cambia este único valor
        # para dar más/menos espacio vertical a toda la barra.
        # Mueve cada widget con x= y= sin afectar a los demás.
        # ─────────────────────────────────────────────────────────────────
        topbar = TopBarContainer(height=110)

        # ── Logo ───────────────────────────────────────────────────────────
        _root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        logo_path = os.path.join(_root, "Sentinel_Logo.png")

        logo_lbl = BrandLogo(
            logo_path=logo_path,
            fixed_w=300,    # ← ancho del widget del logo
            fixed_h=105,    # ← alto del widget del logo
            offset_x=0,     # ← desplazamiento interno de la imagen
            offset_y=0,
            img_w=300,      # ← tamaño real de la imagen dibujada
            img_h=450,
        )
        topbar.add(logo_lbl, x=0, y=5)   # ← posición en el topbar

        # ── Active Case Badge ────────────────────────────────────────────
        self.case_badge = QLabel("ACTIVE CASE: NONE")
        self.case_badge.setObjectName("lblActiveCase")
        self.case_badge.setAlignment(Qt.AlignCenter)
        self.case_badge.setFixedSize(240, 40)   # ← tamaño del badge
        topbar.add(self.case_badge, x=375, y=35)  # ← posición en el topbar

        # ── CPU Panel ───────────────────────────────────────────────────
        cpu_panel = HudStatPanel(
            panel_w=220,    # ← ancho del panel CPU
            panel_h=80,     # ← alto del panel CPU
        )
        self.lbl_cpu_val = QLabel("CPU: 0%")
        self.lbl_cpu_val.setStyleSheet("color: #E0E6ED; font-weight: bold; font-size: 11px;")
        cpu_panel.inner_layout.addWidget(self.lbl_cpu_val)

        self.prog_cpu = pg.PlotWidget(background='transparent')
        self.prog_cpu.setFixedSize(205, 28)
        self.prog_cpu.hideAxis('left')
        self.prog_cpu.hideAxis('bottom')
        self.prog_cpu.setMouseEnabled(x=False, y=False)
        self.prog_cpu.setMenuEnabled(False)
        self.prog_cpu.setYRange(0, 100)
        pen   = pg.mkPen(color='#00d4ff', width=1)
        brush = pg.mkBrush(color=(0, 212, 255, 60))
        self.cpu_curve = self.prog_cpu.plot(
            list(self.cpu_history), pen=pen, fillLevel=0, fillBrush=brush
        )
        cpu_panel.inner_layout.addWidget(self.prog_cpu)
        topbar.add(cpu_panel, x=730, y=15)   # ← posición en el topbar

        # ── RAM Panel ───────────────────────────────────────────────────
        ram_panel = HudStatPanel(
            panel_w=220,    # ← ancho del panel RAM
            panel_h=80,     # ← alto del panel RAM
        )
        self.lbl_ram_val = QLabel("RAM: 0 GB / 0 GB")
        self.lbl_ram_val.setStyleSheet("color: #E0E6ED; font-weight: bold; font-size: 11px;")
        ram_panel.inner_layout.addWidget(self.lbl_ram_val)

        self.prog_ram = QProgressBar()
        self.prog_ram.setObjectName("progRAM")
        self.prog_ram.setTextVisible(False)
        self.prog_ram.setFixedSize(190, 8)
        self.prog_ram.setMaximum(100)
        ram_panel.inner_layout.addWidget(self.prog_ram)
        topbar.add(ram_panel, x=975, y=15)  # ← posición en el topbar

        # ── Global Tor Toggle ───────────────────────────────────────────
        self.btn_tor_toggle = QPushButton("🌐 Tor: OFF")
        self.btn_tor_toggle.setObjectName("btnTorToggle")
        self.btn_tor_toggle.setStyleSheet("background-color: #374151; color: #a1a1aa; font-weight: bold; border-radius: 4px; font-size: 14px;")
        self.btn_tor_toggle.clicked.connect(self._action_toggle_tor)
        self.btn_tor_toggle.setFixedSize(180, 40)
        topbar.add(self.btn_tor_toggle, x=1220, y=35)

        self.root_layout.addWidget(topbar)

    def _build_sidebar(self):
        # ──────────────────────────────────────────────────────────────
        # SideBarContainer: posicionamiento ABSOLUTO por botón
        # width  = ancho del panel completo
        # add(widget, x=, y=, w=, h=)
        #   x/y = posición del botón dentro del panel
        #   w/h = tamaño del botón (independiente de los demás)
        # ──────────────────────────────────────────────────────────────
        sidebar = SideBarContainer(
            width=160,    # ← ancho del panel sidebar
        )

        btn_new = QPushButton("+\nNew Case")
        btn_new.setObjectName("sideNewCase")
        btn_new.setProperty("class", "SidebarButton")
        btn_new.clicked.connect(self._action_new_case)
        sidebar.add(btn_new,
            x=10, y=125,    # ← posición del botón dentro del panel
            w=140, h=100,  # ← tamaño del botón
        )

        btn_open = QPushButton("📂\nOpen")
        btn_open.setObjectName("sideOpen")
        btn_open.setProperty("class", "SidebarButton")
        btn_open.clicked.connect(self._action_open)
        sidebar.add(btn_open,
            x=10, y=235,   # ← posición (y = y_anterior + h + espacio)
            w=140, h=100,
        )

        btn_del = QPushButton("🗑\nDelete")
        btn_del.setObjectName("sideDelete")
        btn_del.setProperty("class", "SidebarButton")
        btn_del.clicked.connect(self._action_delete)
        sidebar.add(btn_del,
            x=10, y=345,   # ← posición
            w=140, h=100,
        )

        btn_edit = QPushButton("✏️\nEdit")
        btn_edit.setObjectName("sideEdit")
        btn_edit.setProperty("class", "SidebarButton")
        btn_edit.clicked.connect(self._action_edit)
        sidebar.add(btn_edit,
            x=10, y=455,   # ← posición (+110px)
            w=140, h=100,
        )

        self.mid_layout.addWidget(sidebar)

    def _build_tabs_and_content(self):
        content_col = QVBoxLayout()
        
        # Tab Buttons
        self.tab_bar = QHBoxLayout()
        self.tab_bar.setSpacing(8)
        self.tab_bar.setAlignment(Qt.AlignLeft)
        
        # Tab Body Panel
        self.stack_wrapper = QFrame()
        self.stack_wrapper.setObjectName("panelWrap")
        stack_lay = QVBoxLayout(self.stack_wrapper)
        stack_lay.setContentsMargins(16, 16, 16, 16)
        
        self.stack = QStackedWidget()
        stack_lay.addWidget(self.stack)
        
        # Add Tabs
        self.pages = [
            ("Casos", CasesTab(self)),
            ("Datos", DataTab(self)),
            ("Herramientas", ToolsTab(self)),
            ("Perfilamiento", ProfilingTab(self)),
            ("Correlación", CorrelationTab(self)),
            ("CTI", CTITab(self)),
            ("Reportes", ReportsTab(self)),
            ("IA", AITab(self))
        ]
        
        self.tab_btns = []
        for i, (name, widget) in enumerate(self.pages):
            btn = QPushButton(name)
            btn.setProperty("class", "TabButton")
            btn.setCheckable(True)
            if i == 0:
                btn.setChecked(True)
            btn.clicked.connect(lambda checked, idx=i: self._switch_tab(idx))
            self.tab_bar.addWidget(btn)
            self.tab_btns.append(btn)
            self.stack.addWidget(widget)
            
        content_col.addLayout(self.tab_bar)
        content_col.addWidget(self.stack_wrapper, 1) # stretch 1
        
        self.mid_layout.addLayout(content_col, 1)

    def _switch_tab(self, index):
        for i, btn in enumerate(self.tab_btns):
            btn.setChecked(i == index)
        self.stack.setCurrentIndex(index)

    def _update_all_tabs(self):
        """Forces all child tabs to drop their state and reload from the DB using the active_case_id."""
        for name, widget in self.pages:
            if hasattr(widget, 'refresh'):
                widget.refresh()
            if hasattr(widget, '_load_reports'):
                widget._load_reports()
            if hasattr(widget, '_load_correlations'):
                widget._load_correlations()

    def _build_statusbar(self):
        status_bar = QHBoxLayout()
        self.status_lbl = QLabel("🟢 Connected | System Status: All Services Operational")
        self.status_lbl.setStyleSheet("color: #00ff66;")
        status_bar.addWidget(self.status_lbl)
        self.root_layout.addLayout(status_bar)

    def _update_stats(self):
        cpu = int(psutil.cpu_percent())
        
        mem = psutil.virtual_memory()
        ram_pct = int(mem.percent)
        ram_used = mem.used / (1024**3)
        ram_total = mem.total / (1024**3)
        
        self.lbl_cpu_val.setText(f"CPU: {cpu}%")
        self.cpu_history.append(cpu)
        self.cpu_curve.setData(list(self.cpu_history))
        
        self.lbl_ram_val.setText(f"RAM: {ram_used:.1f} GB / {ram_total:.1f} GB")
        self.prog_ram.setValue(ram_pct)

    def set_status(self, text, kind="info"):
        self.status_lbl.setText(text)
        
    def _get_cases_tab(self):
        """Retorna el widget CasesTab directamente — no depende del tab activo."""
        for name, widget in self.pages:
            if name == "Casos":
                return widget
        return None

    def _action_new_case(self):
        # Siempre abre el modal de nuevo caso, sin importar el tab activo
        cases_tab = self._get_cases_tab()
        if cases_tab:
            cases_tab.on_new_case()

    def _action_open(self):
        # Navega al tab de Casos primero para que el usuario pueda seleccionar
        cases_tab = self._get_cases_tab()
        if cases_tab:
            # Si hay algo seleccionado en la tabla, abrir directamente
            if cases_tab.table.selectedItems():
                cases_tab.on_open()
            else:
                # Ir al tab de Casos para que el usuario seleccione un caso
                self._switch_tab(0)
                self.toast.show("Selecciona un caso de la tabla y presiona Open nuevamente", kind="warning")

    def _action_delete(self):
        current_idx = self.stack.currentIndex()
        
        # Tab "Datos" (índice 1 según self.pages)
        if current_idx == 1:
            data_tab = self.pages[1][1]
            if hasattr(data_tab, 'table') and data_tab.table.selectedItems():
                data_tab.on_delete()
            else:
                self.toast.show("Selecciona un dato en la tabla para borrarlo", kind="warning")
            return
            
        # Tab "Reportes" (índice 3 según self.pages)
        if current_idx == 3:
            rep_tab = self.pages[3][1]
            if hasattr(rep_tab, 'tree') and rep_tab.tree.selectedItems():
                rep_tab.on_delete()
            else:
                self.toast.show("Selecciona un reporte en la lista para borrarlo", kind="warning")
            return
            
        cases_tab = self._get_cases_tab()
        if cases_tab:
            if current_idx == 0 and hasattr(cases_tab, 'table') and cases_tab.table.selectedItems():
                cases_tab.on_delete()
            else:
                if current_idx not in (0, 1, 3):
                    self._switch_tab(0)
                self.toast.show("Selecciona un caso, dato o reporte y presiona Delete", kind="warning")

    def _action_edit(self):
        current_idx = self.stack.currentIndex()
        
        # Tab "Datos"
        if current_idx == 1:
            data_tab = self.pages[1][1]
            if hasattr(data_tab, 'table') and data_tab.table.selectedItems():
                if hasattr(data_tab, 'on_edit'):
                    data_tab.on_edit()
            else:
                self.toast.show("Selecciona un dato en la tabla para editarlo", kind="warning")
            return
            
        # Tab "Reportes"
        if current_idx == 3:
            rep_tab = self.pages[3][1]
            if hasattr(rep_tab, 'tree') and rep_tab.tree.selectedItems():
                if hasattr(rep_tab, 'on_edit'):
                    rep_tab.on_edit()
            else:
                self.toast.show("Selecciona un reporte en la lista para editarlo", kind="warning")
            return
            
        # Tab por defecto: "Casos"
        cases_tab = self._get_cases_tab()
        if cases_tab:
            if current_idx == 0 and hasattr(cases_tab, 'table') and cases_tab.table.selectedItems():
                if hasattr(cases_tab, 'on_edit'):
                    cases_tab.on_edit()
            else:
                if current_idx not in (0, 1, 3):
                    self._switch_tab(0)
                self.toast.show("Selecciona un caso, dato o reporte y presiona Edit", kind="warning")

    def _action_toggle_tor(self):
        self._use_tor_proxy = not getattr(self, "_use_tor_proxy", False)
        if self._use_tor_proxy:
            self.btn_tor_toggle.setText("🌐 Tor: ON")
            self.btn_tor_toggle.setStyleSheet("background-color: #9333ea; color: #ffffff; font-weight: bold; border-radius: 4px; border: 1px solid #c084fc; font-size: 14px;")
            self.toast.show("Red Cebolla Activada. Herramientas rutearán vía 127.0.0.1:9050", kind="success")
        else:
            self.btn_tor_toggle.setText("🌐 Tor: OFF")
            self.btn_tor_toggle.setStyleSheet("background-color: #374151; color: #a1a1aa; font-weight: bold; border-radius: 4px; font-size: 14px;")
            self.toast.show("Red Cebolla Desactivada. Volviendo a Clear Web.", kind="info")
