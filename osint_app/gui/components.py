from PySide6.QtWidgets import QPushButton, QDialog, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QTreeWidget, QFrame
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect
from PySide6.QtGui import QColor

class Toast(QFrame):
    def __init__(self, parent, text, kind):
        super().__init__(parent)
        self.setWindowFlags(Qt.SubWindow)
        
        bg_color = "#00d4ff" if kind == "info" else "#00ff66" if kind == "success" else "#ffaa00" if kind == "warning" else "#ff3333"
        self.setStyleSheet(f"background-color: {bg_color}; color: #070A12; border-radius: 6px; font-weight: bold;")
        
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lbl = QLabel(text)
        lay.addWidget(lbl)
        
        self.adjustSize()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.hide_toast)
        self.timer.start(3000)
        
    def show_toast(self):
        self.show()
        # Ensure it is on top, position top-right
        geom = self.parent().geometry()
        x = geom.width() - self.width() - 24
        y = 70
        self.move(x, y)
        self.raise_()
        
    def hide_toast(self):
        self.hide()
        self.deleteLater()

class ToastManager:
    def __init__(self, parent):
        self.parent = parent
        
    def show(self, msg, kind="info"):
        t = Toast(self.parent, msg, kind)
        t.show_toast()

class SentinelModal(QDialog):
    def __init__(self, parent, title, width=400, height=200):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(width, height)
        self.vlayout = QVBoxLayout(self)
        self.content = QFrame()
        self.vlayout.addWidget(self.content)
        self.btn_layout = QHBoxLayout()
        self.vlayout.addLayout(self.btn_layout)

    def add_button(self, text, command, variant="default"):
        btn = QPushButton(text)
        btn.clicked.connect(command)
        if variant == "primary":
            btn.setObjectName("btnPrimary")
        elif variant == "danger":
            btn.setObjectName("btnDanger")
        self.btn_layout.addWidget(btn)

class SentinelButton(QPushButton):
    def __init__(self, text, command=None, variant="default", **kwargs):
        super().__init__(text)
        if command:
            self.clicked.connect(command)
        if variant == "primary":
            self.setObjectName("btnPrimary")
        elif variant == "danger":
            self.setObjectName("btnDanger")

class SectionDivider(QLabel):
    def __init__(self, master, text, **kwargs):
        super().__init__(text)
        self.setStyleSheet("color: #00d4ff; font-weight: bold; border-bottom: 1px solid #00507a;")

class EmptyState(QWidget):
    def __init__(self, parent, icon, title, subtitle):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(title))

class BrandLogo(QLabel):
    """Logo widget con posición de imagen controlable mediante offset.

    El widget ocupa un espacio fijo en el layout (fixed_w × fixed_h) pero
    la imagen se dibuja exactamente en (offset_x, offset_y) dentro de ese
    espacio, lo que permite moverla libremente sin afectar a los demás
    widgets del topbar.

    Args:
        parent    : widget padre
        logo_path : ruta absoluta al archivo PNG del logo (opcional)
        fixed_w   : ancho fijo del widget en el layout (px, default 120)
        fixed_h   : altura fija del widget en el layout (px, default 60)
        offset_x  : píxeles desde la izquierda del widget donde empieza
                    la imagen. Negativo = se sale por la izquierda.
                    Default 0.
        offset_y  : píxeles desde arriba del widget donde empieza la imagen.
                    Negativo = sube por encima del widget.
                    Default 0.
        img_w     : ancho de la imagen dibujada (px). Si es 0, usa fixed_w.
        img_h     : altura de la imagen dibujada (px). Si es 0, usa fixed_h.
    """
    def __init__(
        self,
        parent=None,
        logo_path: str = "",
        fixed_w: int = 120,
        fixed_h: int = 60,
        offset_x: int = 0,
        offset_y: int = 0,
        img_w: int = 0,
        img_h: int = 0,
    ):
        super().__init__(parent)
        from PySide6.QtGui import QPixmap
        from PySide6.QtCore import Qt as _Qt

        self._offset_x  = offset_x
        self._offset_y  = offset_y
        self._pixmap_raw = None

        # El widget ocupa su propio espacio fijo — no afecta a los demás
        self.setFixedSize(fixed_w, fixed_h)
        self.setContentsMargins(0, 0, 0, 0)

        # Dimensiones de la imagen dibujada
        draw_w = img_w if img_w > 0 else fixed_w
        draw_h = img_h if img_h > 0 else fixed_h

        if logo_path:
            from pathlib import Path
            if Path(logo_path).exists():
                self._pixmap_raw = QPixmap(logo_path).scaled(
                    draw_w, draw_h,
                    _Qt.KeepAspectRatio,
                    _Qt.SmoothTransformation,
                )
                return  # paintEvent se encargará de dibujarlo

        # Fallback de texto
        self.setText("👁 SENTINEL")
        self.setAlignment(_Qt.AlignCenter)
        self.setStyleSheet("color: #ffffff; font-size: 20px; font-weight: bold;")

    def paintEvent(self, event):
        """Dibuja el pixmap en las coordenadas exactas (offset_x, offset_y)."""
        if self._pixmap_raw is not None:
            from PySide6.QtGui import QPainter
            painter = QPainter(self)
            painter.drawPixmap(self._offset_x, self._offset_y, self._pixmap_raw)
            painter.end()
        else:
            # Fallback: deja que QLabel dibuje el texto normalmente
            super().paintEvent(event)


class HudStatPanel(QWidget):
    """Panel de estadísticas (CPU / RAM) con tamaño y offset independientes.

    Funciona IGUAL que BrandLogo:
      - panel_w / panel_h  → tamaño del QFrame visible (con borde y fondo)
      - offset_x / offset_y → dónde empieza el frame dentro del espacio
                               reservado en el layout.
        · offset positivo  → se aleja del borde (baja / va a la derecha)
        · offset negativo  → el frame desborda hacia arriba / izquierda

    El contenedor crece automáticamente con el offset positivo.

    Args:
        parent    : widget padre
        panel_w   : ancho del QFrame visible (px, default 160)
        panel_h   : alto  del QFrame visible (px, default 70)
        offset_x  : px desde la izquierda  (+ derecha, - desborda izq)
        offset_y  : px desde arriba        (+ abajo,   - sube por encima)
    """
    def __init__(
        self,
        parent=None,
        panel_w: int = 160,
        panel_h: int = 70,
        offset_x: int = 0,
        offset_y: int = 0,
    ):
        super().__init__(parent)

        # El contenedor crece para acomodar el offset positivo
        # (offset negativo: el frame desborda, Qt lo permite)
        cw = panel_w + max(0, offset_x)
        ch = panel_h + max(0, offset_y)

        self.setFixedSize(cw, ch)

        # QFrame interior — lo que el usuario ve (borde, fondo, datos)
        self._frame = QFrame(self)
        self._frame.setObjectName("panelHudStat")
        self._frame.setFixedSize(panel_w, panel_h)
        self._frame.move(max(0, offset_x), max(0, offset_y))

        # Layout público para agregar widgets al panel
        self.inner_layout = QVBoxLayout(self._frame)
        self.inner_layout.setContentsMargins(12, 8, 12, 8)
        self.inner_layout.setSpacing(4)

    def set_offset(self, x: int, y: int):
        """Mueve el frame visible en tiempo de ejecución."""
        self._frame.move(max(0, x), max(0, y))


class TopBarContainer(QWidget):
    """Barra superior con posicionamiento ABSOLUTO por widget.

    En lugar de un QHBoxLayout, cada widget se coloca en coordenadas (x, y)
    exactas dentro de este contenedor de altura fija. Cambiar las coordenadas
    de UN widget no afecta a los demás.

    Args:
        parent    : widget padre
        height    : altura fija del topbar en px (default 110)

    Uso:
        topbar = TopBarContainer(height=110)
        topbar.add(logo_widget,   x=0,    y=5)
        topbar.add(case_badge,    x=400,  y=38)
        topbar.add(cpu_panel,     x=920,  y=12)
        topbar.add(ram_panel,     x=1075, y=12)
        root_layout.addWidget(topbar)
    """
    def __init__(self, parent=None, height: int = 110):
        super().__init__(parent)
        self.setFixedHeight(height)
        # Sin layout — posicionamiento manual
        self._entries: list[tuple] = []   # (widget, x, y)

    def add(self, widget, x: int = 0, y: int = 0):
        """Añade un widget en posición absoluta (x, y) dentro del topbar."""
        widget.setParent(self)
        widget.move(x, y)
        widget.show()
        self._entries.append((widget, x, y))

    def move_widget(self, widget, x: int, y: int):
        """Reposiciona un widget ya añadido (útil para ajustes en runtime)."""
        widget.move(x, y)
        self._entries = [
            (w, (x if w is widget else ox), (y if w is widget else oy))
            for w, ox, oy in self._entries
        ]


class SideBarContainer(QFrame):
    """Panel lateral con posicionamiento ABSOLUTO por widget.

    Igual que TopBarContainer pero para la sidebar: ancho fijo, altura
    flexible. Cada botón se coloca en coordenadas (x, y) exactas dentro
    del panel; cambiar uno NO afecta a los demás.

    Args:
        parent  : widget padre
        width   : ancho fijo del panel (px, default 160)
        height  : alto fijo del panel (px, default 600) — usa 0 para flexible

    Uso:
        sidebar = SideBarContainer(width=160)
        sidebar.add(btn_new,  x=10, y=20,  w=140, h=80)
        sidebar.add(btn_open, x=10, y=115, w=140, h=80)
        sidebar.add(btn_del,  x=10, y=210, w=140, h=80)
        mid_layout.addWidget(sidebar)
    """
    def __init__(self, parent=None, width: int = 160, height: int = 0):
        super().__init__(parent)
        self.setObjectName("panelWrap")
        self.setFixedWidth(width)
        if height > 0:
            self.setFixedHeight(height)
        self._entries: list[tuple] = []

    def add(self, widget, x: int = 0, y: int = 0, w: int = 0, h: int = 0):
        """Añade un widget en posición absoluta.

        Args:
            widget : el QPushButton u otro widget
            x      : px desde la izquierda del panel
            y      : px desde arriba del panel
            w      : ancho del widget (0 = no cambiar tamaño)
            h      : alto del widget  (0 = no cambiar tamaño)
        """
        widget.setParent(self)
        if w > 0 and h > 0:
            widget.setFixedSize(w, h)
        elif w > 0:
            widget.setFixedWidth(w)
        elif h > 0:
            widget.setFixedHeight(h)
        widget.move(x, y)
        widget.show()
        self._entries.append((widget, x, y, w, h))

    def move_widget(self, widget, x: int, y: int):
        """Reposiciona un widget en runtime."""
        widget.move(x, y)

class SentinelTable(QTreeWidget):
    def __init__(self, parent, cols):
        super().__init__(parent)
        self.setColumnCount(len(cols))
        self.setHeaderLabels([c[0] for c in cols])
