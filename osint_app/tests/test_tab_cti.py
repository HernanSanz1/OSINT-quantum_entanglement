"""Pestaña CTI: ejecución de los scripts del módulo CTI (sin abrir la GUI)."""
import os
import sys

import pytest

pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
from osint_app.gui import tab_cti  # noqa: E402


def _script(folder, name, body):
    (folder / name).write_text(body, encoding="utf-8")


def test_run_cti_script_uses_current_python_and_utf8(tmp_path):
    # "python3" no existe en Windows; los acentos/emojis rompían en cp1252.
    _script(tmp_path, "eco.py",
            "import os, sys\n"
            "print(sys.executable)\n"
            "print(os.environ['PYTHONPATH'].split(os.pathsep)[0])\n"
            "print('Ecuador ñ ✅')\n")
    result = tab_cti._run_cti_script(tmp_path, "eco.py", [], timeout=60)
    exe, pythonpath, text = result.stdout.strip().splitlines()
    assert result.returncode == 0
    assert os.path.samefile(exe, sys.executable)
    assert pythonpath == str(tmp_path)
    assert text == "Ecuador ñ ✅"


def _run_thread(thread):
    out = {}
    thread.finished_ok.connect(lambda r: out.setdefault("ok", r))
    thread.error.connect(lambda e: out.setdefault("error", e))
    thread.run()  # síncrono, sin QApplication
    return out


def test_render_uses_most_recent_dossier(tmp_path):
    # Por orden alfabético ganaba "dossier-2026-W39.json" aunque se acabara
    # de generar "dossier-2026-W39-CER.json".
    store = tmp_path / "store"
    store.mkdir()
    old, new = store / "dossier-2026-W39.json", store / "dossier-2026-W39-CER.json"
    old.write_text("{}"); new.write_text("{}")
    os.utime(old, (1_000_000, 1_000_000))
    os.utime(new, (2_000_000, 2_000_000))
    _script(tmp_path, "render.py", "import sys\nprint(sys.argv[1])\n")

    out = _run_thread(tab_cti.RenderThread(tmp_path))
    assert out.get("ok", "").endswith("dossier-2026-W39-CER.json"), out


def test_render_without_dossier_reports_error(tmp_path):
    (tmp_path / "store").mkdir()
    _script(tmp_path, "render.py", "print('no debería ejecutarse')\n")
    out = _run_thread(tab_cti.RenderThread(tmp_path))
    assert "No hay dossier" in out.get("error", "")


def test_dossier_thread_passes_client(tmp_path):
    _script(tmp_path, "dossier.py", "import sys\nprint(' '.join(sys.argv[1:]))\n")
    assert _run_thread(tab_cti.DossierThread(tmp_path, "CER"))["ok"].strip() == "--resumen --cliente CER"
    assert _run_thread(tab_cti.DossierThread(tmp_path, "GLOBAL"))["ok"].strip() == "--resumen"
