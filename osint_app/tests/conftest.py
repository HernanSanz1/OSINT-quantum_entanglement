"""Fixtures compartidos por los tests de osint_app.

Ningún test toca la red ni la base de datos real (osint_app/data/osint_v2.db).
"""
import pytest

from osint_app.db import feedback_db


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Redirige el singleton `db` a una base SQLite temporal y vacía."""
    fresh = feedback_db.Database(tmp_path / "test.db")
    monkeypatch.setattr(feedback_db.db, "db_path", fresh.db_path)
    return feedback_db.db
