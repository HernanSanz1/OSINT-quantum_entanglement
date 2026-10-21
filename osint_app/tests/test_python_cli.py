"""Herramientas de pip lanzadas con el Python de SENTINEL (sin su .exe, que Windows puede bloquear)."""
import subprocess
import sys

import pytest

from osint_app.tools import social_tools
from osint_app.utils import python_cli
from osint_app.utils.python_cli import blocked_by_windows, pip_tool_command


def _installed(module):
    import importlib.util
    return importlib.util.find_spec(module) is not None


@pytest.mark.skipif(not _installed("maigret"), reason="maigret no instalado en este entorno")
def test_real_maigret_runs_through_the_signed_python_not_its_exe():
    command = pip_tool_command("maigret")
    assert command[:2] == [sys.executable, "-c"]
    out = subprocess.run(command + ["--version"], capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=120)
    assert out.returncode == 0 and "maigret" in out.stdout.lower()


@pytest.mark.skipif(not _installed("sherlock_project"), reason="sherlock no instalado en este entorno")
def test_real_sherlock_runs_through_python():
    out = subprocess.run(pip_tool_command("sherlock") + ["--version"], capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=120)
    assert out.returncode == 0 and "sherlock" in out.stdout.lower()


def test_unknown_tool_falls_back_to_path_or_nothing(monkeypatch):
    monkeypatch.setattr(python_cli.shutil, "which", lambda name: None)
    assert pip_tool_command("no-existe-esta-herramienta") == []
    monkeypatch.setattr(python_cli.shutil, "which", lambda name: f"C:/pipx/{name}.exe")
    assert pip_tool_command("no-existe-esta-herramienta") == ["C:/pipx/no-existe-esta-herramienta.exe"]


def _windows_error(code):
    err = OSError("bloqueado")
    err.winerror = code
    return err


def test_windows_block_is_explained_in_plain_words():
    msg = blocked_by_windows("Maigret", _windows_error(4551))
    assert msg.startswith("❌ Maigret: Windows (Smart App Control") and "firma digital" in msg
    assert blocked_by_windows("Maigret", _windows_error(5)) == ""          # otro error: no se disfraza
    assert blocked_by_windows("Maigret", OSError("sin código")) == ""


def test_social_run_reports_a_windows_block_instead_of_crashing(monkeypatch):
    def blocked(cmd, **kw):
        raise _windows_error(4551)
    monkeypatch.setattr(social_tools.subprocess, "run", blocked)
    out, code = social_tools._run(["sherlock.exe", "x"], label="Sherlock")
    assert code == -1 and out.startswith("❌ Sherlock: Windows")


def test_heavy_tools_report_a_windows_block_in_plain_words(monkeypatch):
    from osint_app.tools import heavy_tools
    from osint_app.tools.heavy_tools import MaigretTool, _run, _tool_failed

    def blocked(cmd, **kw):
        raise _windows_error(4551)
    monkeypatch.setattr(heavy_tools.subprocess, "Popen", blocked)
    tool, seen = MaigretTool(), []
    tool._progress_cb = seen.append
    out, rc = _run(tool, ["maigret", "x"])
    assert _tool_failed(tool, "Maigret", out, rc) is True
    assert seen[-1].startswith("❌ Maigret: Windows (Smart App Control") and "Excepción" not in seen[-1]
