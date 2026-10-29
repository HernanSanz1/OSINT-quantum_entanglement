"""Registro de herramientas y detección de disponibilidad (--check-tools)."""
import pytest

from osint_app.tools import ALL_TOOLS, build_tool_registry
from osint_app.tools import heavy_tools
from osint_app.tools.heavy_tools import (
    AmassTool, MaigretTool, SpiderFootTool, SubfinderTool,
)


@pytest.fixture
def nothing_installed(tmp_path, monkeypatch):
    """Simula un equipo sin binarios en el PATH y con ~/go/bin vacío."""
    monkeypatch.setattr(heavy_tools.shutil, "which", lambda name: None)
    from osint_app.utils import python_cli
    monkeypatch.setattr(python_cli, "_entry_point_command", lambda name: [])   # ni instaladas en el Python de SENTINEL
    monkeypatch.setattr(heavy_tools.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(heavy_tools, "SPIDERFOOT_PATH", tmp_path / "spiderfoot" / "sf.py")
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "datos"))    # ni en las carpetas de SENTINEL
    return tmp_path


def test_every_tool_class_is_registered():
    # Una herramienta que falla al instanciarse desaparecía en silencio
    # (así se perdió IpWhoisTool).
    registry = build_tool_registry()
    assert len(registry) == len(ALL_TOOLS)
    assert "ipwhois" in registry


@pytest.mark.parametrize("tool_cls", [SubfinderTool, AmassTool, SpiderFootTool, MaigretTool])
def test_missing_binary_is_reported_unavailable(nothing_installed, tool_cls):
    tool = tool_cls()
    assert tool.is_available is False
    assert tool.check_available() is False


@pytest.mark.parametrize("tool_cls", [SubfinderTool, AmassTool, SpiderFootTool, MaigretTool])
def test_registry_does_not_override_unavailable(nothing_installed, monkeypatch, tool_cls):
    # Antes, build_tool_registry() pisaba is_available con el True por defecto.
    monkeypatch.setattr("osint_app.tools.ALL_TOOLS", [tool_cls])
    registry = build_tool_registry()
    assert all(t.is_available is False for t in registry.values())


@pytest.mark.parametrize("name,tool_cls", [("subfinder", SubfinderTool), ("amass", AmassTool)])
@pytest.mark.parametrize("filename", ["{}", "{}.exe"])
def test_go_binary_in_home_is_detected(nothing_installed, name, tool_cls, filename):
    go_bin = nothing_installed / "go" / "bin"
    go_bin.mkdir(parents=True)
    (go_bin / filename.format(name)).write_text("")
    assert tool_cls().check_available() is True


def test_spiderfoot_detected_when_cloned(nothing_installed):
    heavy_tools.SPIDERFOOT_PATH.parent.mkdir(parents=True)
    heavy_tools.SPIDERFOOT_PATH.write_text("")
    assert SpiderFootTool().check_available() is True


def test_maigret_detected_on_path(nothing_installed, monkeypatch):
    monkeypatch.setattr(heavy_tools.shutil, "which",
                        lambda name: "/usr/bin/maigret" if name == "maigret" else None)
    assert MaigretTool().check_available() is True


def test_ipwhois_rejects_invalid_ip_without_network():
    from osint_app.core.models import QueryParameters
    from osint_app.tools.network_tools import IpWhoisTool
    assert IpWhoisTool().execute(QueryParameters(ip="no-es-una-ip")) == []
    assert IpWhoisTool().execute(QueryParameters(ip="")) == []


@pytest.mark.parametrize("name,tool_cls", [("subfinder.exe", SubfinderTool), ("amass.exe", AmassTool)])
def test_exe_in_sentinel_bin_folder_is_detected(nothing_installed, name, tool_cls):
    # El .exe publicado por el autor, copiado en la carpeta de SENTINEL: sin instalar Go ni tocar el PATH
    from osint_app.utils.data_paths import tools_bin_dir
    tools_bin_dir().mkdir(parents=True)
    (tools_bin_dir() / name).write_text("")
    assert tool_cls().check_available() is True


@pytest.mark.parametrize("folder,script,tool_name", [("theHarvester", "theHarvester.py", "TheHarvester"),
                                                      ("spiderfoot", "sf.py", "SpiderFoot"),
                                                      ("recon-ng", "recon-ng", "Recon-ng")])
def test_cloned_tool_found_in_sentinel_tools_folder_with_its_own_python(nothing_installed, folder, script, tool_name):
    # Antes se buscaban en la carpeta desde la que se abría SENTINEL ("theHarvester/theHarvester.py")
    from osint_app.utils.data_paths import tools_dir
    code = tools_dir() / folder
    (code / ".venv" / "Scripts").mkdir(parents=True)
    (code / script).write_text("")
    assert build_tool_registry()[tool_name].check_available() is True
    assert heavy_tools.tool_python(code / script) == heavy_tools.sys.executable     # sin python.exe en .venv
    (code / ".venv" / "Scripts" / "python.exe").write_text("")
    assert heavy_tools.tool_python(code / script) == str(code / ".venv" / "Scripts" / "python.exe")


def test_install_guides_do_not_point_to_another_computer():
    # Las guías decían "Abre la terminal en IAprototipe" (la carpeta de otro equipo)
    for tool in build_tool_registry().values():
        guide = str(getattr(tool, "_install_cmd", "") or "") + str(tool.diagnose_status().get("install_cmd", ""))
        assert "IAprototipe" not in guide and "gabysanz" not in guide, tool.name
