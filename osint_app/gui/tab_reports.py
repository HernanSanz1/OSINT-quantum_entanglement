import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPlainTextEdit, QPushButton, QLabel, QSplitter
)
from PySide6.QtCore import Qt
from ..db.feedback_db import db

class ReportsTab(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setObjectName("panelMain")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)
        
        # Left: Reports Tree
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0,0,0,0)
        
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Case ID", "Report ID", "Tool", "Date"])
        self.tree.itemSelectionChanged.connect(self._on_select)
        left_layout.addWidget(self.tree)
        splitter.addWidget(left_panel)
        
        # Right: Viewer
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0,0,0,0)
        
        top_btn_lay = QHBoxLayout()
        self.lbl_rep = QLabel("Report Viewer")
        self.lbl_rep.setStyleSheet("font-weight: bold; color: #00d4ff;")
        top_btn_lay.addWidget(self.lbl_rep)
        
        btn_ai = QPushButton("🧠 Send to AI")
        btn_ai.setObjectName("btnPrimary")
        btn_ai.clicked.connect(self._send_to_ai)
        top_btn_lay.addWidget(btn_ai)
        
        right_layout.addLayout(top_btn_lay)
        
        self.viewer = QPlainTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setStyleSheet("background-color: #0c111d; color: #E0E6ED; font-family: monospace;")
        right_layout.addWidget(self.viewer)
        
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        self._current_report_id = None
        self.refresh()
        
    def refresh(self):
        self.tree.clear()
        if not self.app.active_case_id:
            return
            
        reports = db.get_reports(self.app.active_case_id)
        for r in reports:
            # r has id, case_id, tool_name, raw_json, created_at
            item = QTreeWidgetItem()
            item.setText(0, str(getattr(r, 'case_id', '')))
            item.setText(1, str(getattr(r, 'id', '')))
            item.setText(2, getattr(r, 'tool_name', ''))
            ts = str(getattr(r, 'run_at', ''))
            item.setText(3, ts[:16] if len(ts)>16 else ts)
            item.setData(0, Qt.UserRole, getattr(r, 'id', None))
            item.setData(1, Qt.UserRole, getattr(r, 'raw_json', '{}'))
            self.tree.addTopLevelItem(item)

    def _on_select(self):
        items = self.tree.selectedItems()
        if not items:
            self._current_report_id = None
            self.lbl_rep.setText("Report Viewer")
            self.viewer.clear()
            return
            
        item = items[0]
        self._current_report_id = item.data(0, Qt.UserRole)
        self.lbl_rep.setText(f"Report ID #{item.text(1)}: {item.text(2)}")
        try:
            raw = item.data(1, Qt.UserRole)
            parsed = json.loads(raw)
            self.viewer.setPlainText(json.dumps(parsed, indent=2))
        except:
            self.viewer.setPlainText(str(item.data(1, Qt.UserRole)))

    def _send_to_ai(self):
        if not self._current_report_id:
            self.app.toast.show("Selecciona un reporte.")
            return
        
        # Switch to AI tab
        self.app._switch_tab(4)
        self.app.toast.show("Activa los reportes que deseas en la pestaña de IA", kind="success")
        
    def on_open(self):
        self.refresh()

    def on_delete(self):
        items = self.tree.selectedItems()
        if not items:
            return
            
        item = items[0]
        report_id = item.data(0, Qt.UserRole)
        tool_name = item.text(1)
        
        from .components import SentinelModal
        dlg = SentinelModal(self.window(), "Borrar Reporte", 400, 200)
        from PySide6.QtWidgets import QLabel
        QLabel(f"¿Estás seguro de que deseas borrar el reporte de '{tool_name}'?", dlg.content)
        dlg.add_button("Cancelar", dlg.reject)
        dlg.add_button("Borrar", dlg.accept, variant="danger")
        
        if dlg.exec():
            try:
                db.delete_report(int(report_id))
                self.app.toast.show(f"Reporte borrado exitosamente.", kind="success")
                self._current_report_id = None
                self.lbl_rep.setText("Report Viewer")
                self.viewer.clear()
                self.refresh()
            except Exception as e:
                self.app.toast.show(f"Error al borrar reporte: {e}", kind="error")

    def on_edit(self):
        items = self.tree.selectedItems()
        if not items:
            return
            
        item = items[0]
        report_id = item.data(0, Qt.UserRole)
        tool_name = item.text(1)
        raw_json_str = str(item.data(1, Qt.UserRole))
        
        try:
            parsed = json.loads(raw_json_str)
            formatted_json = json.dumps(parsed, indent=2)
        except:
            formatted_json = raw_json_str
            
        from .components import SentinelModal
        modal = SentinelModal(self.window(), f"✏️  Editar Reporte: {tool_name}", 600, 500)
        from PySide6.QtWidgets import QVBoxLayout, QPlainTextEdit, QLabel
        lay = QVBoxLayout(modal.content)
        
        lay.addWidget(QLabel("Raw JSON:"))
        e_json = QPlainTextEdit(formatted_json)
        e_json.setStyleSheet("background-color: #0c111d; color: #E0E6ED; font-family: monospace;")
        lay.addWidget(e_json)
        
        def _save():
            new_json = e_json.toPlainText().strip()
            if not new_json:
                return
            # Validate JSON if possible
            try:
                json.loads(new_json)
            except json.JSONDecodeError:
                self.app.toast.show("Alerta: JSON Inválido, revisa el formato.", kind="error")
                return
                
            try:
                db.update_report_json(int(report_id), new_json)
                self.app.toast.show(f"Reporte de {tool_name} actualizado.", kind="success")
                
                # Refresh UI components
                item.setData(1, Qt.UserRole, new_json)
                if self._current_report_id == report_id:
                    self.viewer.setPlainText(new_json)
                    
                modal.accept()
            except Exception as e:
                self.app.toast.show(f"Error al actualizar reporte: {e}", kind="error")

        modal.add_button("Cancelar", modal.reject)
        modal.add_button("Guardar Cambios", _save, variant="primary")
        modal.exec()
