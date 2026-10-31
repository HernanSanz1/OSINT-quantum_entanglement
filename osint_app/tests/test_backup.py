"""Copias de seguridad: casos, informes y CTI en un .zip, restaurables sin perder lo que había."""
import datetime
import sqlite3
import zipfile

import pytest

from osint_app.utils import backup


@pytest.fixture
def data(tmp_path, monkeypatch):
    root = tmp_path / "datos"
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(root))
    monkeypatch.setattr(backup, "make_private", lambda path: path.mkdir(parents=True, exist_ok=True) or True)
    (root / "informes").mkdir(parents=True)
    (root / "informes" / "Ficha_x.html").write_text("ficha", encoding="utf-8")
    (root / "informes" / ".carpeta_privada").write_text("marca", encoding="utf-8")
    (root / "cti").mkdir()
    (root / "cti" / "items.jsonl").write_text('{"titulo": "n"}\n', encoding="utf-8")
    db = root / "osint_v2.db"
    conn = sqlite3.connect(db)
    conn.execute("create table cases (id integer, name text)")
    conn.execute("insert into cases values (1, 'Perfil: Glenda')")
    conn.commit()
    conn.close()
    monkeypatch.setattr(backup, "_db_path", lambda: db)
    return root


def test_backup_contains_cases_reports_and_cti_but_not_the_private_mark(data, tmp_path):
    made = backup.make_backup(tmp_path / "usb")
    names = zipfile.ZipFile(made).namelist()
    assert {"osint_v2.db", "informes/Ficha_x.html", "cti/items.jsonl", "LEEME.txt"} <= set(names)
    assert not any(".carpeta_privada" in n for n in names) and not list((tmp_path / "usb").glob("*.parcial"))


def test_auto_backup_once_a_day_keeping_seven(data):
    start = datetime.datetime(2026, 10, 1, 9, 0)
    assert backup.auto_backup(now=start) is not None
    assert backup.auto_backup(now=start + datetime.timedelta(hours=2)) is None          # ya hay una de hoy
    for day in range(1, 10):
        assert backup.auto_backup(now=start + datetime.timedelta(days=day)) is not None
    assert len(list((data / "copias").glob("SENTINEL_copia_*.zip"))) == backup.AUTO_KEEP


def test_restore_brings_data_back_and_saves_the_current_state_first(data, tmp_path):
    made = backup.make_backup(tmp_path / "usb")
    conn = sqlite3.connect(data / "osint_v2.db")
    conn.execute("delete from cases")
    conn.commit()
    conn.close()
    (data / "informes" / "Ficha_x.html").unlink()
    previous = backup.restore_backup(made)
    assert previous.name.endswith("_antes_de_restaurar.zip") and previous.exists()
    assert sqlite3.connect(data / "osint_v2.db").execute("select count(*) from cases").fetchone()[0] == 1
    assert (data / "informes" / "Ficha_x.html").read_text(encoding="utf-8") == "ficha"


def test_restore_refuses_foreign_or_dangerous_archives(data, tmp_path):
    foreign = tmp_path / "otro.zip"
    with zipfile.ZipFile(foreign, "w") as zf:
        zf.writestr("documento.txt", "x")
    with pytest.raises(ValueError):
        backup.restore_backup(foreign)
    evil = tmp_path / "malo.zip"
    good_db = backup.make_backup(tmp_path / "usb")
    with zipfile.ZipFile(good_db) as src, zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("osint_v2.db", src.read("osint_v2.db"))
        zf.writestr("../fuera.txt", "x")
        zf.writestr("informes/../../fuera2.txt", "x")
    backup.restore_backup(evil)
    assert not (data.parent / "fuera.txt").exists() and not (data.parent / "fuera2.txt").exists()
