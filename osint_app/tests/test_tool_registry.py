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
    monkeypatch.setattr(heavy_tools.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(heavy_tools, "SPIDERFOOT_PATH", tmp_path / "spiderfoot" / "sf.py")
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
