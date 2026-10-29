"""Orquestador (framework), compatibilidad y base de las herramientas, con herramientas falsas y sin red."""
import json

import pytest

from osint_app import framework as framework_module
from osint_app.core.base_tool import OSINTTool
from osint_app.core.models import CompatibilityStatus, SearchResult, TargetData, ToolRequirements
from osint_app.framework import OSINTFramework
from osint_app.utils.compatibility import DataCompatibilityEngine


class FakeTool(OSINTTool):
    """Herramienta de prueba: devuelve lo que se le diga, o falla."""

    def __init__(self, name="FakeDomain", mandatory=("domain",), optional=("email",), results=None, boom=None, heavy=False):
        super().__init__(name, "falsa", ToolRequirements(mandatory=list(mandatory), optional=list(optional), produces=["domain"]))
        self._results, self._boom = results, boom
        self.is_heavy = heavy
        self.received = []
        self.progress_seen = None

    def execute(self, query_params):
        self.received.append(query_params)
        self.progress_seen = self._progress_cb
        self._report_progress("trabajando…")
        if self._boom:
            raise self._boom
        return self._results if self._results is not None else []


def result(title="r", snippet="", category="Web", url=""):
    return SearchResult(title=title, url=url, snippet=snippet, source_tool="FakeDomain", category=category)


@pytest.fixture
def case_id(temp_db):
    from osint_app.case_manager import CaseManager
    cid = CaseManager().create("caso", "").id
    temp_db.add_target_data(TargetData(case_id=cid, field_type="domain", value="empresa.com", confidence=90))
    return cid


@pytest.fixture
def fw(temp_db, monkeypatch, tmp_path):
    monkeypatch.setattr(framework_module, "CONFIG_PATH", tmp_path / "osint_config.json")
    monkeypatch.setattr(framework_module.vault, "get", lambda name: "")
    f = OSINTFramework()
    f.tools = {"FakeDomain": FakeTool(results=[result("Hallazgo", "contacto juan@empresa.com ip 8.8.8.8", "Network")])}
    return f


# ── compatibilidad ───────────────────────────────────────────────────────────

def td(ft, value, conf=50):
    return TargetData(case_id=1, field_type=ft, value=value, confidence=conf)


def test_compatibility_green_yellow_red():
    engine, tool = DataCompatibilityEngine(), FakeTool()
    green = engine.check_tool(tool, [td("domain", "x.com"), td("email", "a@x.com")])
    yellow = engine.check_tool(tool, [td("domain", "x.com")])
    red = engine.check_tool(tool, [td("email", "a@x.com")])
    assert [r.status for r in (green, yellow, red)] == [CompatibilityStatus.GREEN, CompatibilityStatus.YELLOW, CompatibilityStatus.RED]
    assert green.available == ["domain", "email"] and yellow.missing_optional == ["email"] and red.missing_mandatory == ["domain"]
    assert red.can_run is False and yellow.can_run and "domain" in red.missing_hints
    assert yellow.auto_params.domain == "x.com"                                             # los datos del caso llegan a la herramienta


def test_compatibility_of_an_uninstalled_tool_is_red_with_a_clear_hint():
    tool = FakeTool(name="Binaria")
    tool.is_available = False
    result_ = DataCompatibilityEngine().check_tool(tool, [td("domain", "x.com")])
    assert result_.status == CompatibilityStatus.RED and "Binaria no está instalada" in result_.hint and not result_.can_run


def test_compatibility_extra_args_reach_the_params():
    r = DataCompatibilityEngine().check(FakeTool().requirements, [td("domain", "x.com")], extra_args="--rapido")
    assert r.auto_params.extra_args == "--rapido"


# ── base de las herramientas ─────────────────────────────────────────────────

def test_diagnose_ready():
    d = FakeTool().diagnose_status()
    assert d["status"] == "ready" and d["icon"] == "✅" and d["install_cmd"] == ""


def test_diagnose_system_dependency_missing(monkeypatch):
    tool = FakeTool(name="ConGo")
    tool._system_deps = [("go", "https://go.dev/dl/")]
    monkeypatch.setattr("osint_app.core.base_tool.shutil.which", lambda b: None)
    d = tool.diagnose_status()
    assert d["status"] == "not_installed" and "'go'" in d["message"] and "https://go.dev/dl/" in d["install_cmd"]


def test_diagnose_binary_missing():
    tool = FakeTool(name="Sherlock")
    tool.is_available, tool._binary_names, tool._install_cmd = False, ["sherlock"], "pip install sherlock-project"
    d = tool.diagnose_status()
    assert d["status"] == "not_installed" and "Sherlock no está instalado" in d["message"] and "PATH" not in d["message"] and d["install_cmd"] == "pip install sherlock-project"


def test_diagnose_python_package_missing():
    tool = FakeTool(name="ConPaquete")
    tool._python_pkgs = ["paquete_que_no_existe_xyz"]
    d = tool.diagnose_status()
    assert d["status"] == "python_pkg_missing" and d["install_cmd"] == "pip install paquete-que-no-existe-xyz"
    tool._install_cmd = "pip install otra-cosa"
    assert tool.diagnose_status()["install_cmd"] == "pip install otra-cosa"


def test_diagnose_missing_api_key_points_to_the_set_key_command():
    tool = FakeTool(name="Hunter.io")
    tool.requires_api_key = True
    d = tool.diagnose_status()
    assert d["status"] == "needs_key" and "--set-key Hunter.io" in d["install_cmd"]
    assert ".osint_v2_keys" not in d["message"] + d["install_cmd"]                           # el baúl va cifrado: no se edita a mano
    tool.set_api_key("abc")
    assert tool.diagnose_status()["status"] == "ready"


def test_progress_callback_errors_never_break_a_tool():
    tool = FakeTool()
    tool._report_progress("sin callback")                                                    # sin callback: no hace nada
    tool._progress_cb = lambda m: 1 / 0
    tool._report_progress("callback roto")                                                   # un fallo de la interfaz no tumba la herramienta
    seen = []
    tool._progress_cb = seen.append
    tool._report_progress("hola")
    assert seen == ["hola"]


def test_stop_flag_and_default_availability():
    tool = FakeTool()
    assert tool._is_cancelled is False and tool.check_available() is True
    tool.stop()
    assert tool._is_cancelled is True


# ── framework: comprobar herramientas ────────────────────────────────────────

def test_check_tool_and_check_all(fw, case_id):
    assert fw.check_tool("FakeDomain", case_id).status == CompatibilityStatus.YELLOW
    assert list(fw.check_all_tools(case_id)) == ["FakeDomain"]
    with pytest.raises(ValueError, match="no existe"):
        fw.check_tool("no existe", case_id)


# ── framework: ejecutar una herramienta ──────────────────────────────────────

def test_run_tool_saves_the_report_and_extracts_entities(fw, case_id, temp_db):
    msgs = []
    report = fw.run_tool("FakeDomain", case_id, progress_cb=msgs.append)
    assert report.status == "ok" and report.results_count == 1 and report.summary.startswith("1 resultados.") and "Network: 1" in report.summary
    saved = temp_db.get_reports(case_id)[0]
    assert saved.id == report.id and json.loads(saved.raw_json)[0]["title"] == "Hallazgo"
    extracts = fw.get_extracted_entities(report.id)
    assert extracts["email"] == ["juan@empresa.com"] and extracts["ip"] == ["8.8.8.8"]
    assert msgs[0] == "Iniciando FakeDomain…" and "trabajando…" in msgs and msgs[-1].startswith("✅ FakeDomain finalizado — 1 resultados")


def test_run_tool_passes_case_data_and_cleans_up_the_progress_callback(fw, case_id):
    tool = fw.tools["FakeDomain"]
    fw.run_tool("FakeDomain", case_id, progress_cb=lambda m: None, extra_args="--rapido")
    assert tool.received[0].domain == "empresa.com" and tool.received[0].extra_args == "--rapido"
    assert callable(tool.progress_seen) and tool._progress_cb is None


def test_run_tool_can_use_only_selected_data(fw, case_id, temp_db):
    other = temp_db.add_target_data(TargetData(case_id=case_id, field_type="domain", value="otra.com", confidence=95))
    fw.run_tool("FakeDomain", case_id, target_data_ids=[other])
    assert fw.tools["FakeDomain"].received[0].domain == "otra.com"
    fw.run_tool("FakeDomain", case_id)
    assert fw.tools["FakeDomain"].received[1].domain == "otra.com"                             # sin filtro manda la de mayor confianza


def test_run_tool_refuses_when_mandatory_data_is_missing(fw, temp_db):
    from osint_app.case_manager import CaseManager
    empty = CaseManager().create("vacío", "").id
    with pytest.raises(RuntimeError, match="faltan datos obligatorios: domain"):
        fw.run_tool("FakeDomain", empty)
    assert temp_db.get_reports(empty) == []                                                     # no se guarda un reporte de algo que no corrió
    with pytest.raises(ValueError, match="not registered"):
        fw.run_tool("no existe", empty)


def test_a_failing_tool_is_reported_with_its_reason(fw, case_id, temp_db):
    fw.tools["FakeDomain"]._boom = RuntimeError("el servicio devolvió 500")
    msgs = []
    report = fw.run_tool("FakeDomain", case_id, progress_cb=msgs.append)
    assert report.status == "error" and report.results_count == 0
    assert report.summary == "Error: RuntimeError: el servicio devolvió 500"                   # antes: "0 resultados." sin motivo
    assert temp_db.get_reports(case_id)[0].summary == report.summary and fw.get_extracted_entities(report.id) == {}
    assert msgs[-1].startswith("❌ FakeDomain falló") and "el servicio devolvió 500" in msgs[-1]
    assert not any("✅" in m for m in msgs)                                                      # ya no dice "finalizado" si falló
    assert fw.tools["FakeDomain"]._progress_cb is None                                          # se limpia aunque falle


def test_a_tool_with_no_results_is_ok_and_long_errors_are_truncated(fw, case_id):
    fw.tools["FakeDomain"]._results = []
    assert fw.run_tool("FakeDomain", case_id).summary.startswith("0 resultados.")
    fw.tools["FakeDomain"]._boom = ValueError("x" * 1000)
    assert len(fw.run_tool("FakeDomain", case_id).summary) < 260


def test_heavy_tool_warns_when_the_system_is_overloaded(fw, case_id, monkeypatch):
    fw.tools["FakeDomain"].is_heavy = True
    monkeypatch.setattr(fw.resource, "is_overloaded", lambda: True)
    msgs = []
    fw.run_tool("FakeDomain", case_id, progress_cb=msgs.append)
    assert any("Sistema bajo carga" in m for m in msgs)
    monkeypatch.setattr(fw.resource, "is_overloaded", lambda: False)
    msgs.clear()
    fw.run_tool("FakeDomain", case_id, progress_cb=msgs.append)
    assert not any("Sistema bajo carga" in m for m in msgs)


# ── framework: pasar entidades al caso ───────────────────────────────────────

def test_add_entities_to_case(fw, case_id, temp_db):
    fw.add_entities_to_case(case_id, {"email": ["a@x.com", "b@x.com"], "ip": ["8.8.8.8"]}, source="tool:T", selected=["a@x.com", "8.8.8.8"])
    added = {(d.field_type, d.value, d.source, d.confidence) for d in temp_db.get_target_data(case_id) if d.source == "tool:T"}
    assert added == {("email", "a@x.com", "tool:T", 70), ("ip", "8.8.8.8", "tool:T", 70)}      # solo lo seleccionado


def test_adding_entities_twice_does_not_duplicate(fw, case_id, temp_db):
    entities = {"email": ["A@X.com"], "domain": ["empresa.com"]}                                # el dominio ya está en el caso
    fw.add_entities_to_case(case_id, entities, "tool:T")
    fw.add_entities_to_case(case_id, entities, "tool:T")
    fw.add_entities_to_case(case_id, {"email": ["a@x.com "]}, "tool:T")                         # mismo correo con otra forma
    values = [(d.field_type, d.value.strip().lower()) for d in temp_db.get_target_data(case_id)]
    assert sorted(values) == [("domain", "empresa.com"), ("email", "a@x.com")]                  # antes: cada clic repetía todo


# ── framework: configuración ─────────────────────────────────────────────────

def test_save_and_load_server_urls(fw, tmp_path):
    fw.tools["FakeDomain"].BASE_URL = "https://original"
    fw.save_config({"FakeDomain": "https://mi-servidor:9000", "Desconocida": "https://x"})
    cfg = json.loads((tmp_path / "osint_config.json").read_text())
    assert cfg["server_urls"] == {"FakeDomain": "https://mi-servidor:9000", "Desconocida": "https://x"}
    assert fw.tools["FakeDomain"].BASE_URL == "https://mi-servidor:9000"
    fw.save_config({"Otra": "https://y"})                                                         # se acumula, no se pisa
    assert set(json.loads((tmp_path / "osint_config.json").read_text())["server_urls"]) == {"FakeDomain", "Desconocida", "Otra"}
    fw.tools["FakeDomain"].BASE_URL = "cambiada"
    fw._load_config()
    assert fw.tools["FakeDomain"].BASE_URL == "https://mi-servidor:9000"


def test_corrupt_config_does_not_break_startup(fw, tmp_path):
    (tmp_path / "osint_config.json").write_text("{esto no es json", encoding="utf-8")
    fw._load_config()                                                                              # solo registra el error


def test_api_keys_from_the_vault_reach_the_tools(fw, monkeypatch):
    tool = fw.tools["FakeDomain"]
    tool.requires_api_key = True
    monkeypatch.setattr(framework_module.vault, "get", lambda name: "clave-de-prueba" if name == "FakeDomain" else "")
    fw._load_config()
    assert tool.api_key == "clave-de-prueba"
    tool.requires_api_key = False
    tool.api_key = ""
    fw._load_config()
    assert tool.api_key == ""                                                                      # solo a las que la necesitan
