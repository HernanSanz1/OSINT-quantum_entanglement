from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
    QHeaderView, QLabel, QAbstractItemView, QLineEdit, QComboBox, QPushButton
)
from PySide6.QtCore import Qt
from ..core.models import TargetData
from ..db.feedback_db import db
from ..utils.data_validation import DATA_TYPES, TYPE_LABELS, detect_type, validation_error

class DataTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setObjectName("panelMain")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["ID", "Tipo", "Valor", "Añadido"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setFocusPolicy(Qt.NoFocus)
        
        layout.addWidget(self.table, 1) # stretch 1
        
        # Input Form
        form_layout = QHBoxLayout()
        form_layout.addWidget(QLabel("Tipo:"))

        # "Detectar automáticamente" por defecto: en la prueba de usuario el desplegable no cambiaba con el ratón y
        # una URL acabó guardada como dominio. Con la detección, el tipo sale de la forma del dato.
        self.combo_type = QComboBox()
        self.combo_type.addItem("Detectar automáticamente", "AUTO")
        for code, label in DATA_TYPES:
            self.combo_type.addItem(label, code)
        form_layout.addWidget(self.combo_type)

        form_layout.addWidget(QLabel("Valor:"))
        self.e_val = QLineEdit()
        self.e_val.setPlaceholderText("Ej.: ejemplo.com · 8.8.8.8 · https://… · correo@dominio.com")
        self.e_val.returnPressed.connect(self._add_data)
        form_layout.addWidget(self.e_val, 1) # stretch 1

        btn_add = QPushButton("✚ Añadir dato")
        btn_add.setObjectName("btnPrimary")
        btn_add.clicked.connect(self._add_data)
        form_layout.addWidget(btn_add)
        
        layout.addLayout(form_layout)
        self.refresh()
        
    def refresh(self):
        self.table.setRowCount(0)
        if not self.app.active_case_id:
            return
            
        data = db.get_target_data(self.app.active_case_id)
        self.table.setRowCount(len(data))
        for row, d in enumerate(data):
            d_id = QTableWidgetItem(str(getattr(d, "id", "")))
            
            d_type_val = str(getattr(d, "field_type", ""))
            d_type = QTableWidgetItem(TYPE_LABELS.get(d_type_val.upper(), d_type_val))
            d_type.setData(Qt.UserRole, d_type_val.upper())
            
            d_val = QTableWidgetItem(str(getattr(d, "value", "")))
            d_val.setForeground(Qt.cyan) # aesthetic pop
            
            ts = str(getattr(d, "created_at", ""))
            d_time = QTableWidgetItem(ts[:16] if len(ts) > 16 else ts)
            
            self.table.setItem(row, 0, d_id)
            self.table.setItem(row, 1, d_type)
            self.table.setItem(row, 2, d_val)
            self.table.setItem(row, 3, d_time)

    def _add_data(self):
        if not self.app.active_case_id:
            self.app.toast.show("Primero crea o abre un caso (pestaña Casos).", kind="warning")
            return

        val = self.e_val.text().strip()
        if not val:
            self.app.toast.show("Escribe un valor para añadir.", kind="warning")
            return

        code = self.combo_type.currentData()
        if code == "AUTO":
            code = detect_type(val)
            if not code:
                self.app.toast.show("No se reconoce el tipo de dato: elige el tipo en el desplegable "
                                    "(Nombre, Usuario, Empresa…).", kind="warning")
                return
        error = validation_error(code, val)
        if error:
            self.app.toast.show(error, kind="warning")
            return
        t_str = TYPE_LABELS.get(code, code)
        try:
            from datetime import datetime
            td = TargetData(
                case_id=self.app.active_case_id,
                field_type=code,
                value=val,
                source="Manual",
                created_at=datetime.utcnow().isoformat()
            )
            db.add_target_data(td)
            self.app.toast.show(f"Añadido ({t_str}): {val}", kind="success")
            self.e_val.clear()
            self.refresh()
        except Exception as e:
            self.app.toast.show(f"No se pudo añadir el dato: {e}", kind="error")

    # Hook called when app changes active case
    def on_open(self):
        # We don't usually need it here since it's routed from app, 
        # but app.py could just call refresh on all tabs when case changes.
        pass

    def on_delete(self):
        selected = self.table.selectedItems()
        if not selected:
            self.app.toast.show("Selecciona un dato de la tabla.", kind="warning")
            return
            
        row = selected[0].row()
        item_id = self.table.item(row, 0).text()
        item_val = self.table.item(row, 2).text()
        
        from .components import SentinelModal
        dlg = SentinelModal(self.window(), "Borrar Dato", 400, 200)
        from PySide6.QtWidgets import QLabel
        QLabel(f"¿Estás seguro de que deseas borrar '{item_val}'?", dlg.content)
        dlg.add_button("Cancelar", dlg.reject)
        dlg.add_button("Borrar", dlg.accept, variant="danger")
        
        if dlg.exec():
            try:
                db.delete_target_data(int(item_id))
                self.app.toast.show(f"Dato borrado.", kind="success")
                self.refresh()
            except Exception as e:
                self.app.toast.show(f"Error al borrar dato: {e}", kind="error")

    def on_edit(self):
        selected = self.table.selectedItems()
        if not selected:
            self.app.toast.show("Selecciona un dato de la tabla.", kind="warning")
            return
            
        row = selected[0].row()
        item_id = self.table.item(row, 0).text()
        item_type = self.table.item(row, 1).data(Qt.UserRole) or self.table.item(row, 1).text()
        item_val = self.table.item(row, 2).text()
        
        from .components import SentinelModal
        modal = SentinelModal(self.window(), "✏️  Editar Dato", 400, 250)
        from PySide6.QtWidgets import QLabel, QVBoxLayout, QComboBox, QLineEdit
        lay = QVBoxLayout(modal.content)
        
        lay.addWidget(QLabel("Tipo:"))
        combo_type = QComboBox()
        for code, label in DATA_TYPES:
            combo_type.addItem(label, code)
        if combo_type.findData(str(item_type).upper()) < 0:      # contexto, país… (los guarda el Perfilamiento)
            combo_type.addItem(TYPE_LABELS.get(str(item_type).upper(), str(item_type)), str(item_type).upper())
        idx = combo_type.findData(str(item_type).upper())
        if idx >= 0:
            combo_type.setCurrentIndex(idx)
        lay.addWidget(combo_type)
        
        lay.addWidget(QLabel("Valor:"))
        e_val = QLineEdit(item_val)
        lay.addWidget(e_val)
        
        def _save():
            new_val = e_val.text().strip()
            new_type = combo_type.currentData()
            error = validation_error(new_type, new_val)
            if error:
                self.app.toast.show(error, kind="warning")
                return

            try:
                db.update_target_data(int(item_id), new_type, new_val, 50)
                self.app.toast.show(f"Dato actualizado: {new_val}", kind="success")
                self.refresh()
                modal.accept()
            except Exception as e:
                self.app.toast.show(f"Error al actualizar dato: {e}", kind="error")

        modal.add_button("Cancelar", modal.reject)
        modal.add_button("Guardar Cambios", _save, variant="primary")
        modal.exec()
