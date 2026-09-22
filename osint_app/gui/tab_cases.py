from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
    QHeaderView, QLabel, QAbstractItemView, QLineEdit
)
from PySide6.QtCore import Qt
from .components import SentinelModal

class CasesTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setObjectName("panelMain")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Description", "Status", "Created Date"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setFocusPolicy(Qt.NoFocus)
        
        layout.addWidget(self.table)
        self.refresh()
        
    def refresh(self):
        self.table.setRowCount(0)
        cases = self.app.case_mgr.list_all()
        if not cases:
            return

        self.table.setRowCount(len(cases))
        for row, c in enumerate(cases):
            # c es un objeto Case con atributos: .id, .name, .description, .status, .created_at
            c_id   = QTableWidgetItem(str(c.id))
            c_name = QTableWidgetItem(c.name)
            c_desc = QTableWidgetItem(c.description or "")

            # Status badge
            is_active = self.app.active_case_id == c.id
            c_status = QTableWidgetItem("● Active" if is_active else "○ Open")
            c_status.setTextAlignment(Qt.AlignCenter)
            c_status.setForeground(Qt.green if is_active else Qt.gray)

            created = c.created_at[:16] if c.created_at else ""
            c_date = QTableWidgetItem(created)

            self.table.setItem(row, 0, c_id)
            self.table.setItem(row, 1, c_name)
            self.table.setItem(row, 2, c_desc)
            self.table.setItem(row, 3, c_status)
            self.table.setItem(row, 4, c_date)


    def _get_selected_case_id(self):
        items = self.table.selectedItems()
        if not items:
            return None
        row = items[0].row()
        return int(self.table.item(row, 0).text())

    def on_open(self):
        case_id = self._get_selected_case_id()
        if not case_id:
            self.app.toast.show("Selecciona un caso para abrir.", kind="warning")
            return
        
        row = self.table.selectedItems()[0].row()
        name = self.table.item(row, 1).text()
        
        self.app.active_case_id = case_id
        self.app.active_case_name = name
        self.app.case_badge.setText(f"ACTIVE CASE: #{case_id} — {name.upper()}")
        self.app.set_status(f"✔  Caso abierto: {name}", "success")
        self.app.toast.show(f"Caso {name} establecido como activo", kind="success")
        self.refresh()
        
        # Auto-refresh todas las demás pestañas para limpiar el estado del caso anterior
        self.app._update_all_tabs()

    def on_delete(self):
        case_id = self._get_selected_case_id()
        if not case_id:
            self.app.toast.show("Selecciona un caso para eliminar.", kind="warning")
            return
            
        row = self.table.selectedItems()[0].row()
        name = self.table.item(row, 1).text()
        
        def _do_delete():
            try:
                self.app.case_mgr.delete(case_id)
                self.app.toast.show(f"Caso '{name}' eliminado.", kind="success")
                if self.app.active_case_id == case_id:
                    self.app.active_case_id = None
                    self.app.active_case_name = ""
                    self.app.case_badge.setText("ACTIVE CASE: NONE")
                self.app._update_all_tabs()
                modal.accept()
            except Exception as e:
                self.app.toast.show(f"Error: {e}", kind="error")
                
        modal = SentinelModal(self.app, "⊘  Eliminar caso", width=420, height=220)
        QLabel(f"¿Eliminar permanentemente el caso '{name}'?\n\nSe borrarán todos los datos y reportes asociados.", modal.content)
        modal.add_button("Cancelar", modal.reject)
        modal.add_button("Eliminar", _do_delete, variant="danger")
        modal.exec()

    def on_new_case(self):
        modal = SentinelModal(self.app, "✚  Nuevo Caso", width=400, height=300)
        lay = QVBoxLayout(modal.content)
        
        lay.addWidget(QLabel("Nombre del caso:"))
        e_name = QLineEdit()
        lay.addWidget(e_name)
        
        lay.addWidget(QLabel("Descripción (opcional):"))
        e_desc = QLineEdit()
        lay.addWidget(e_desc)
        
        def _save():
            name = e_name.text().strip()
            if not name:
                return
            new_id = self.app.case_mgr.create(name, e_desc.text().strip()).id
            self.app.toast.show(f"Caso creado: {name}", kind="success")
            self.app.active_case_id = new_id
            self.app.active_case_name = name
            self.app.case_badge.setText(f"ACTIVE CASE: #{new_id} — {name.upper()}")
            self.app._update_all_tabs()
            modal.accept()

        modal.add_button("Cancelar", modal.reject)
        modal.add_button("Guardar", _save, variant="primary")
        modal.exec()

    def on_edit(self):
        case_id = self._get_selected_case_id()
        if not case_id:
            self.app.toast.show("Selecciona un caso para editar.", kind="warning")
            return
            
        case = self.app.case_mgr.get(case_id)
        if not case:
            return
            
        modal = SentinelModal(self.app, "✏️  Editar Caso", width=400, height=300)
        lay = QVBoxLayout(modal.content)
        
        lay.addWidget(QLabel("Nombre del caso:"))
        e_name = QLineEdit(case.name)
        lay.addWidget(e_name)
        
        lay.addWidget(QLabel("Descripción (opcional):"))
        e_desc = QLineEdit(case.description or "")
        lay.addWidget(e_desc)
        
        def _save():
            name = e_name.text().strip()
            if not name:
                return
            self.app.case_mgr.update(case_id, name, e_desc.text().strip())
            self.app.toast.show(f"Caso '{name}' actualizado.", kind="success")
            
            # Si es el caso activo, actualizar el badge
            if self.app.active_case_id == case_id:
                self.app.active_case_name = name
                self.app.case_badge.setText(f"ACTIVE CASE: #{case_id} — {name.upper()}")
                
            self.refresh()
            modal.accept()

        modal.add_button("Cancelar", modal.reject)
        modal.add_button("Guardar Cambios", _save, variant="primary")
        modal.exec()
