"""Seguridad de los datos: dónde se guardan los casos, migración sin pérdida y claves cifradas."""
import json
import os
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from osint_app.db.feedback_db import Database
from osint_app.utils import data_paths, secret_vault
from osint_app.utils.data_paths import (
    data_dir, migrate_legacy_db, resolve_db_path, synced_folder, synced_warning,
)
from osint_app.utils.secret_vault import SecretVault


# ── dónde van los datos ──────────────────────────────────────────────────────

def test_env_variable_overrides_the_data_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "mis datos"))
    assert data_dir() == tmp_path / "mis datos"


@pytest.mark.parametrize("platform,expected_tail", [
    ("win32", ("AppData", "Local", "SENTINEL")), ("darwin", ("Library", "Application Support", "SENTINEL")),
    ("linux", (".local", "share", "sentinel")),
])
def test_default_dir_is_outside_the_project_per_platform(monkeypatch, tmp_path, platform, expected_tail):
    monkeypatch.delenv("SENTINEL_DATA_DIR", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(data_paths.sys, "platform", platform)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert data_dir().parts[-3:] == expected_tail
    assert str(data_dir()).startswith(str(tmp_path))


def test_localappdata_and_xdg_are_respected(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINEL_DATA_DIR", raising=False)
    monkeypatch.setattr(data_paths.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert data_dir() == tmp_path / "local" / "SENTINEL"
    monkeypatch.setattr(data_paths.sys, "platform", "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert data_dir() == tmp_path / "xdg" / "sentinel"


# ── carpetas sincronizadas con la nube ───────────────────────────────────────

@pytest.mark.parametrize("path,provider", [
    ("C:/Users/ana/OneDrive/Desktop/proyecto/data", "OneDrive"),
    ("C:/Users/ana/OneDrive - Empresa SA/Documentos", "OneDrive"),
    ("C:/Users/ana/Dropbox/trabajo", "Dropbox"),
    ("C:/Users/ana/Google Drive/casos", "Google Drive"),
    ("/Users/ana/Library/Mobile Documents/com~apple~CloudDocs/casos", "iCloud"),
    ("/Users/ana/Library/CloudStorage/Dropbox/casos", "Dropbox"),
    ("/Users/ana/Library/CloudStorage/OneDrive-Empresa/casos", "OneDrive"),
    ("/Users/ana/iCloud Drive/casos", "iCloud"),
    ("C:/Users/ana/AppData/Local/SENTINEL", ""), ("/home/ana/.local/share/sentinel", ""),
    ("C:/Users/ana/Documents/mydropbox-notes", ""), ("C:/proyectos/onedrive_tools_no", "OneDrive"),
])
def test_synced_folder(path, provider):
    assert synced_folder(path) == provider


def test_synced_folder_uses_the_onedrive_environment_root(monkeypatch, tmp_path):
    root = tmp_path / "MiNube"
    (root / "casos").mkdir(parents=True)
    monkeypatch.setenv("OneDrive", str(root))
    assert synced_folder(root / "casos") == "OneDrive"
    assert synced_folder(tmp_path / "otra") == ""


def test_synced_warning_text():
    assert synced_warning("C:/Users/ana/AppData/Local/SENTINEL") == ""
    msg = synced_warning("C:/Users/ana/Dropbox/casos")
    assert "Dropbox" in msg and "nube" in msg and "SENTINEL_DATA_DIR" in msg


# ── migración de la base sin perder nada ─────────────────────────────────────

def _make_db(path: Path, cases=2, data=3):
    db = Database(path)
    with sqlite3.connect(path) as c:
        for i in range(cases):
            c.execute("INSERT INTO cases (name, description, status, created_at) VALUES (?,?,?,?)", (f"caso{i}", "d", "open", "2026-01-01"))
        for i in range(data):
            c.execute("INSERT INTO target_data (case_id, field_type, value, source, confidence, created_at) VALUES (1,'email',?,?,?,?)",
                      (f"p{i}@x.com", "seed", 100, "2026-01-01"))
    return db


def _counts(path: Path):
    with sqlite3.connect(path) as c:
        return {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("cases", "target_data", "tool_reports")}


def test_migration_copies_everything_and_never_touches_the_original(tmp_path):
    legacy, new = tmp_path / "proyecto" / "osint_v2.db", tmp_path / "local" / "SENTINEL" / "osint_v2.db"
    _make_db(legacy)
    before = legacy.read_bytes()
    assert migrate_legacy_db(new, legacy) == "copiada"
    assert _counts(new) == _counts(legacy) == {"cases": 2, "target_data": 3, "tool_reports": 0}
    assert legacy.read_bytes() == before                           # el original sigue intacto
    assert not list(new.parent.glob("*.tmp"))
    assert Database(new)                                           # la copia es una base válida y usable


def test_migration_runs_once_and_never_overwrites(tmp_path):
    legacy, new = tmp_path / "a" / "osint_v2.db", tmp_path / "b" / "osint_v2.db"
    _make_db(legacy)
    migrate_legacy_db(new, legacy)
    with sqlite3.connect(new) as c:                                # el usuario siguió trabajando en la base nueva
        c.execute("INSERT INTO cases (name, description, status, created_at) VALUES ('nuevo','','open','2026-02-02')")
    assert migrate_legacy_db(new, legacy) == ""                    # no se vuelve a copiar encima
    assert _counts(new)["cases"] == 3


def test_migration_does_nothing_without_a_legacy_db_or_for_the_same_file(tmp_path):
    assert migrate_legacy_db(tmp_path / "n" / "x.db", tmp_path / "no_existe.db") == ""
    legacy = tmp_path / "x.db"
    _make_db(legacy)
    assert migrate_legacy_db(legacy, legacy) == ""


def test_failed_migration_falls_back_to_the_original_instead_of_an_empty_db(tmp_path, monkeypatch):
    legacy, new_dir = tmp_path / "proyecto" / "osint_v2.db", tmp_path / "local"
    _make_db(legacy)
    monkeypatch.setattr(data_paths, "data_dir", lambda: new_dir)
    monkeypatch.setattr(data_paths, "legacy_db_path", lambda: legacy)

    def broken(new_path, legacy=None):
        raise OSError("disco lleno")
    monkeypatch.setattr(data_paths, "migrate_legacy_db", broken)
    assert resolve_db_path() == legacy                             # sigue con la original: no arranca vacío
    assert not (new_dir / "osint_v2.db").exists()


def test_resolve_prefers_the_new_location_and_creates_nothing_else(tmp_path, monkeypatch):
    legacy, new_dir = tmp_path / "proyecto" / "osint_v2.db", tmp_path / "local"
    _make_db(legacy)
    monkeypatch.setattr(data_paths, "data_dir", lambda: new_dir)
    monkeypatch.setattr(data_paths, "legacy_db_path", lambda: legacy)
    assert resolve_db_path() == new_dir / "osint_v2.db" and _counts(new_dir / "osint_v2.db")["cases"] == 2
    monkeypatch.setattr(data_paths, "legacy_db_path", lambda: tmp_path / "ninguna.db")
    assert resolve_db_path() == new_dir / "osint_v2.db"            # sin base antigua: la nueva


def test_tests_never_touch_the_real_data_dir():
    assert "sentinel-tests-" in str(data_dir())


# ── noticias CTI fuera del proyecto ──────────────────────────────────────────

def _legacy_cti(tmp_path):
    legacy, reports = tmp_path / "proyecto" / "store", tmp_path / "proyecto" / "cti-altel"
    legacy.mkdir(parents=True)
    reports.mkdir(parents=True)
    (legacy / "items.jsonl").write_text('{"id": "a"}\n{"id": "b"}\n', encoding="utf-8")
    (legacy / "dossier-2026-W39-CER.json").write_text("{}", encoding="utf-8")
    (reports / "AltelThreatIntell_2026W39.html").write_text("<html></html>", encoding="utf-8")
    return legacy, reports


def test_cti_store_is_copied_once_and_the_original_is_kept(tmp_path):
    legacy, reports = _legacy_cti(tmp_path)
    new_dir = tmp_path / "local" / "cti"
    assert data_paths.migrate_legacy_cti_store(new_dir, legacy, reports) == 3
    assert (new_dir / "items.jsonl").read_bytes() == (legacy / "items.jsonl").read_bytes()
    assert (new_dir / "dossier-2026-W39-CER.json").exists()
    assert (new_dir / "boletines" / "AltelThreatIntell_2026W39.html").exists()
    assert (legacy / "items.jsonl").exists() and (reports / "AltelThreatIntell_2026W39.html").exists()
    (new_dir / "items.jsonl").write_text('{"id": "nuevo"}\n', encoding="utf-8")
    assert data_paths.migrate_legacy_cti_store(new_dir, legacy, reports) == 0     # nunca pisa lo nuevo
    assert (new_dir / "items.jsonl").read_text(encoding="utf-8") == '{"id": "nuevo"}\n'


def test_cti_reads_the_old_folder_until_the_copy_is_complete(tmp_path, monkeypatch):
    legacy, _ = _legacy_cti(tmp_path)
    new_dir = tmp_path / "local" / "cti"
    monkeypatch.setattr(data_paths, "cti_store_dir", lambda: new_dir)
    monkeypatch.setattr(data_paths, "legacy_cti_store", lambda: legacy)
    assert data_paths.active_cti_store() == legacy
    new_dir.mkdir(parents=True)
    (new_dir / "dossier-2026-W39-CER.json").write_text("{}", encoding="utf-8")   # copia a medias: sin items.jsonl
    assert data_paths.active_cti_store() == legacy
    (new_dir / "items.jsonl").write_text("", encoding="utf-8")
    assert data_paths.active_cti_store() == new_dir


def test_cti_store_lives_in_the_user_data_dir_not_in_the_project():
    project = Path(data_paths.__file__).resolve().parent.parent.parent
    assert data_paths.cti_store_dir().parent == data_dir()
    assert project not in data_paths.cti_store_dir().parents


# ── baúl de claves cifrado ───────────────────────────────────────────────────

class FakeDpapi:
    """Cifrado reversible de mentira, para probar el formato en cualquier sistema."""
    AVAILABLE = True

    @staticmethod
    def protect(data: bytes) -> bytes:
        return b"ENC:" + data[::-1]

    @staticmethod
    def unprotect(data: bytes) -> bytes:
        if not data.startswith(b"ENC:"):
            raise OSError("no es de este usuario")
        return data[4:][::-1]


@pytest.fixture
def vault_path(tmp_path, monkeypatch):
    monkeypatch.setattr(secret_vault, "dpapi", FakeDpapi)
    for var in ("OSINT_HUNTER_KEY", "GITHUB_TOKEN", "OSINT_CENSYS_KEY"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path / ".osint_v2_keys"


def test_keys_are_stored_encrypted(vault_path):
    v = SecretVault(vault_path)
    v.set("Hunter.io", "clave-super-secreta-123")
    text = vault_path.read_text(encoding="utf-8")
    assert "clave-super-secreta-123" not in text and "Hunter.io" not in text
    assert json.loads(text)["_format"] == "dpapi-v1"
    assert SecretVault(vault_path).get("Hunter.io") == "clave-super-secreta-123"       # y se lee de vuelta
    assert SecretVault(vault_path).all_names() == ["Hunter.io"]                         # el formato no se cuenta como una clave


def test_plaintext_keys_are_encrypted_on_first_read(vault_path):
    vault_path.write_text(json.dumps({"Hunter.io": "vieja-clave-en-claro", "CENSYS": "otra"}), encoding="utf-8")
    assert SecretVault(vault_path).get("Hunter.io") == "vieja-clave-en-claro"          # sigue funcionando
    text = vault_path.read_text(encoding="utf-8")
    assert "vieja-clave-en-claro" not in text and "otra" not in text                    # y ya no está en claro
    assert SecretVault(vault_path).get("CENSYS") == "otra"


def test_delete_and_overwrite_keep_the_file_encrypted(vault_path):
    v = SecretVault(vault_path)
    v.set("Hunter.io", "uno")
    v.set("CENSYS", "dos")
    v.delete("Hunter.io")
    assert "dos" not in vault_path.read_text(encoding="utf-8")
    assert SecretVault(vault_path).all_names() == ["CENSYS"]


def test_unreadable_vault_is_backed_up_before_being_replaced(vault_path):
    blob = json.dumps({"_format": "dpapi-v1", "data": "QUJD"})                        # cifrado por otro usuario o equipo
    vault_path.write_text(blob, encoding="utf-8")
    v = SecretVault(vault_path)
    assert v.get("Hunter.io") == ""                                                    # no se puede leer
    v.set("CENSYS", "nueva")
    backup = vault_path.with_name(vault_path.name + ".unreadable.bak")
    assert backup.read_text(encoding="utf-8") == blob                                   # lo anterior no se perdió
    assert SecretVault(vault_path).get("CENSYS") == "nueva"


def test_without_dpapi_keys_stay_plain_but_work(tmp_path, monkeypatch):
    monkeypatch.setattr(secret_vault, "dpapi", SimpleNamespace(AVAILABLE=False))
    monkeypatch.delenv("OSINT_HUNTER_KEY", raising=False)
    path = tmp_path / "keys"
    v = SecretVault(path)
    v.set("Hunter.io", "abc")
    assert json.loads(path.read_text(encoding="utf-8")) == {"Hunter.io": "abc"} and SecretVault(path).get("Hunter.io") == "abc"


def test_env_variable_still_wins_over_the_vault(vault_path, monkeypatch):
    SecretVault(vault_path).set("Hunter.io", "del-baul")
    monkeypatch.setenv("OSINT_HUNTER_KEY", "del-entorno")
    assert SecretVault(vault_path).get("Hunter.io") == "del-entorno"


# ── DPAPI real (solo en Windows) ─────────────────────────────────────────────

@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI existe solo en Windows")
def test_real_dpapi_roundtrip_and_is_not_plaintext():
    from osint_app.utils import dpapi
    secret = "clave real de prueba ñ ✓".encode("utf-8")
    sealed = dpapi.protect(secret)
    assert secret not in sealed and dpapi.unprotect(sealed) == secret
    with pytest.raises(OSError):
        dpapi.unprotect(b"basura que no es un blob de DPAPI")


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI existe solo en Windows")
def test_real_vault_file_on_windows_is_encrypted(tmp_path, monkeypatch):
    monkeypatch.delenv("OSINT_HUNTER_KEY", raising=False)
    path = tmp_path / "keys"
    SecretVault(path).set("Hunter.io", "clave-real-visible?")
    assert "clave-real-visible?" not in path.read_text(encoding="utf-8")
    assert SecretVault(path).get("Hunter.io") == "clave-real-visible?"


def test_dpapi_refuses_outside_windows(monkeypatch):
    from osint_app.utils import dpapi
    monkeypatch.setattr(dpapi, "AVAILABLE", False)
    with pytest.raises(OSError):
        dpapi.protect(b"x")


# ── fichas e informes en una carpeta privada ─────────────────────────────────

def test_reports_go_to_the_user_data_dir_not_to_downloads():
    assert data_paths.reports_dir() == data_dir() / "informes"
    assert "Downloads" not in str(data_paths.reports_dir())


@pytest.mark.skipif(sys.platform != "win32", reason="permisos NTFS (icacls): solo en Windows")
def test_private_folder_is_readable_only_by_the_user_and_system(tmp_path):
    import subprocess
    folder = tmp_path / "informes"
    folder.mkdir()
    # Permisos PROPIOS previos (así venía la carpeta en el Windows de GitHub): Administradores y Todos
    subprocess.run(["icacls", str(folder), "/grant", "*S-1-5-32-544:(OI)(CI)F", "/grant", "*S-1-1-0:(OI)(CI)R"],
                   capture_output=True, check=True)
    assert data_paths.make_private(folder) is True
    acl = subprocess.run(["icacls", str(folder)], capture_output=True, text=True).stdout
    entries = [line.strip() for line in acl.splitlines()[:-2] if ":" in line]
    owners = {e.split(":")[-2].split("\\")[-1].split(" ")[-1].lower() for e in entries}
    assert owners <= {os.environ["USERNAME"].lower(), "system"}, acl          # ni "Usuarios" ni "Todos"
    assert (folder / ".carpeta_privada").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="en Linux/Mac se usan permisos 700")
def test_private_folder_on_unix_is_700(tmp_path):
    folder = tmp_path / "informes"
    assert data_paths.make_private(folder) is True
    assert (folder.stat().st_mode & 0o777) == 0o700


@pytest.mark.parametrize("raw,state", [("1", "on"), ("3", "on"), ("2", "off"), ("5", "off"), ("", "unknown")])
def test_disk_encryption_reads_the_bitlocker_property(monkeypatch, raw, state):
    monkeypatch.setattr(data_paths.sys, "platform", "win32")
    monkeypatch.setattr(data_paths, "_disk_encryption_cache", {})
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=raw + "\n"))
    assert data_paths.disk_encryption("C:/x") == state
    assert bool(data_paths.disk_encryption_warning("C:/x")) == (state == "off")
