"""Pestaña Datos: la hora de «Añadido» es la hora local, como en el resto de la app (antes salía en UTC)."""
from datetime import datetime, timedelta

import pytest

from osint_app.case_manager import CaseManager


class _Toast:
    def __init__(self):
        self.messages = []

    def show(self, msg, kind="info", action=None):
        self.messages.append((msg, kind))


class _App:
    def __init__(self, case_id):
        self.active_case_id = case_id
        self.toast = _Toast()


def test_manual_data_is_saved_with_local_time(temp_db):
    QtWidgets = pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    from osint_app.gui.tab_data import DataTab

    case = CaseManager().create("Prueba hora", "")
    tab = DataTab(_App(case.id))
    before = datetime.now()
    tab.e_val.setText("ejemplo.com")
    tab._add_data()
    after = datetime.now()

    saved = temp_db.get_target_data(case.id)
    assert len(saved) == 1
    stamp = datetime.fromisoformat(saved[0].created_at)
    assert before - timedelta(seconds=1) <= stamp <= after + timedelta(seconds=1)
    # La tabla enseña esa misma hora, sin la «T»
    assert tab.table.item(0, 3).text() == stamp.strftime("%Y-%m-%d %H:%M")
