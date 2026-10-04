"""Núcleo de datos: base de datos, casos y modelos (sin red; cada test usa su propia base temporal)."""
import sqlite3

import pytest

from osint_app.case_manager import CaseManager
from osint_app.core.models import (
    Case, CaseStatus, CompatibilityResult, CompatibilityStatus, QueryParameters, TargetData, ToolReport,
    ToolRequirements,
)
from osint_app.db.feedback_db import Database


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "datos" / "casos.db")          # la carpeta no existe: se crea


def make_case(db, name="Caso", description="d"):
    return db.create_case(Case(name=name, description=description))


# ── base de datos ────────────────────────────────────────────────────────────

def test_database_creates_folder_and_schema_idempotently(tmp_path):
    path = tmp_path / "a" / "b" / "x.db"
    first = Database(path)
    case_id = make_case(first)
    Database(path)                                              # reabrir no borra nada
    assert Database(path).get_case(case_id).name == "Caso"
    with sqlite3.connect(path) as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"cases", "target_data", "tool_reports", "data_extracts"} <= tables


def test_case_crud_roundtrip(db):
    cid = make_case(db, "Perfil: Juan", "investigación")
    case = db.get_case(cid)
    assert (case.id, case.name, case.description, case.status) == (cid, "Perfil: Juan", "investigación", CaseStatus.OPEN)
    db.update_case(cid, "Perfil: Juan Pérez", "otra")
    assert db.get_case(cid).name == "Perfil: Juan Pérez" and db.get_case(cid).description == "otra"
    assert db.get_case(999) is None
    assert [c.id for c in db.get_cases()] == [cid]


def test_cases_are_listed_newest_first(db):
    old = db.create_case(Case(name="viejo", created_at="2026-01-01T00:00:00"))
    new = db.create_case(Case(name="nuevo", created_at="2026-06-01T00:00:00"))
    assert [c.id for c in db.get_cases()] == [new, old]


def test_target_data_roundtrip_ordering_and_update(db):
    cid = make_case(db)
    low = db.add_target_data(TargetData(case_id=cid, field_type="email", value="b@x.com", confidence=40))
    high = db.add_target_data(TargetData(case_id=cid, field_type="email", value="a@x.com", confidence=95, source="seed"))
    data = db.get_target_data(cid)
    assert [d.id for d in data] == [high, low]                  # la de mayor confianza primero
    assert (data[0].value, data[0].source, data[0].confidence) == ("a@x.com", "seed", 95)
    db.update_target_data(low, "phone", "+593987654321", 80)
    updated = {d.id: d for d in db.get_target_data(cid)}[low]
    assert (updated.field_type, updated.value, updated.confidence) == ("phone", "+593987654321", 80)
    db.delete_target_data(low)
    assert [d.id for d in db.get_target_data(cid)] == [high]


def test_reports_roundtrip_and_update(db):
    cid = make_case(db)
    rid = db.save_report(ToolReport(case_id=cid, tool_name="WebSearch", raw_json='[{"title":"x"}]', summary="1 resultado",
                                    status="ok", execution_time=1.5, results_count=1))
    report = db.get_reports(cid)[0]
    assert (report.id, report.tool_name, report.status, report.execution_time, report.results_count) == (rid, "WebSearch", "ok", 1.5, 1)
    db.update_report_json(rid, "[]")
    assert db.get_reports(cid)[0].raw_json == "[]"


def test_extracts_group_by_type_and_follow_their_report(db):
    cid = make_case(db)
    rid = db.save_report(ToolReport(case_id=cid, tool_name="T", raw_json="[]"))
    db.save_extracts(rid, cid, {"email": ["a@x.com", "b@x.com"], "ip": ["8.8.8.8"], "phone": []})
    assert db.get_extracts(rid) == {"email": ["a@x.com", "b@x.com"], "ip": ["8.8.8.8"]}
    assert db.get_extracts(12345) == {}
    db.delete_report(rid)
    assert db.get_reports(cid) == [] and db.get_extracts(rid) == {}                       # sus extractos se van con él


def test_delete_case_removes_everything_of_that_case_only(db):
    keep, drop = make_case(db, "se queda"), make_case(db, "se borra")
    for cid in (keep, drop):
        db.add_target_data(TargetData(case_id=cid, field_type="email", value=f"{cid}@x.com"))
        rid = db.save_report(ToolReport(case_id=cid, tool_name="T", raw_json="[]"))
        db.save_extracts(rid, cid, {"ip": ["1.1.1.1"]})
    db.delete_case(drop)
    assert db.get_case(drop) is None and db.get_target_data(drop) == [] and db.get_reports(drop) == []
    assert db.get_case(keep).name == "se queda" and len(db.get_target_data(keep)) == 1 and len(db.get_reports(keep)) == 1
    with sqlite3.connect(db.db_path) as c:
        assert c.execute("SELECT COUNT(*) FROM data_extracts WHERE case_id=?", (drop,)).fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM data_extracts WHERE case_id=?", (keep,)).fetchone()[0] == 1


def test_hostile_text_is_stored_literally_not_executed(db):
    evil = "x'); DROP TABLE cases; --"
    cid = db.create_case(Case(name=evil, description=evil))
    db.add_target_data(TargetData(case_id=cid, field_type="note", value=evil, source=evil))
    assert db.get_case(cid).name == evil and db.get_target_data(cid)[0].value == evil
    with sqlite3.connect(db.db_path) as c:
        assert c.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 1               # la tabla sigue ahí


def test_unicode_and_emoji_survive(db):
    cid = db.create_case(Case(name="José Muñoz — ✓ 🔎", description="ñandú"))
    assert db.get_case(cid).name == "José Muñoz — ✓ 🔎"


# ── gestor de casos ──────────────────────────────────────────────────────────

def test_case_manager_full_cycle(temp_db):
    cm = CaseManager()
    case = cm.create("Caso A", "desc")
    assert case.id and cm.get(case.id).name == "Caso A"
    cm.update(case.id, "Caso A2", "desc2")
    assert cm.get(case.id).name == "Caso A2"
    assert [c.id for c in cm.list_all()] == [case.id]
    cm.close(case.id)
    assert cm.get(case.id).status == CaseStatus.CLOSED
    cm.delete(case.id)
    assert cm.get(case.id) is None and cm.list_all() == []


def test_case_manager_close_unknown_case_is_harmless(temp_db):
    CaseManager().close(424242)


# ── modelos ──────────────────────────────────────────────────────────────────

def test_models_to_dict():
    assert Case(name="c", id=3).to_dict()["status"] == "open"
    td = TargetData(case_id=1, field_type="email", value="a@x.com", confidence=70, id=9).to_dict()
    assert td["value"] == "a@x.com" and td["id"] == 9
    rp = ToolReport(case_id=1, tool_name="T", raw_json="[]", status="error", id=2).to_dict()
    assert rp["status"] == "error" and "raw_json" not in rp                                 # el JSON pesado no va en el resumen


def _td(ft, value, conf=50):
    return TargetData(case_id=1, field_type=ft, value=value, confidence=conf)


def test_query_parameters_pick_the_most_confident_value():
    qp = QueryParameters.from_target_data([
        _td("name", "Juan Pérez", 100), _td("name", "Otro Nombre", 60),
        _td("email", "jperez@empresa.com", 90), _td("email", "x@gmail.com", 90),
        _td("domain", "empresa.com"), _td("phone", "+593987654321"), _td("username", "jperez"),
        _td("company", "Banco X"), _td("location", "Quito"), _td("university", "UTPL"),
    ], extra_args="--fast")
    assert (qp.target_name, qp.domain, qp.phone, qp.username) == ("Juan Pérez", "empresa.com", "+593987654321", "jperez")
    assert (qp.company, qp.location, qp.university, qp.extra_args) == ("Banco X", "Quito", "UTPL", "--fast")
    assert qp.email == "x@gmail.com"                                                         # a igual confianza, el personal gana


def test_query_parameters_prefer_username_without_spaces_and_collect_notes():
    qp = QueryParameters.from_target_data([_td("username", "juan perez", 50), _td("username", "jperez", 50),
                                           _td("note", "corta"), _td("note", "una nota bastante más larga")])
    assert qp.username == "jperez" and qp.role == "una nota bastante más larga" and qp.keywords == ["corta", "una nota bastante más larga"]


def test_query_parameters_ignore_discovered_data_and_empty_case():
    qp = QueryParameters.from_target_data([_td("found_name", "Pedro Gómez", 99), _td("found_email", "p@x.com", 99), _td("name", "Juan", 10)])
    assert qp.target_name == "Juan" and qp.email == ""                                      # lo hallado no cambia el objetivo
    empty = QueryParameters.from_target_data([])
    assert empty.target_name == "" and empty.observable == "" and empty.keywords == []


def test_case_context_is_not_lost_when_running_a_tool_from_the_case():
    # Perfilamiento guarda contexto, país y ciudad como datos sueltos: antes se perdían al ejecutar una herramienta
    qp = QueryParameters.from_target_data([_td("name", "Juan"), _td("context", "ingeniero UDLA"), _td("country", "Ecuador"), _td("location", "Quito")])
    assert qp.context == "ingeniero UDLA Ecuador Quito"
    assert qp.observable == ""                    # el contexto NO se mezcla con el observable (ver los tests de abajo)
    explicit = QueryParameters.from_target_data([_td("observable", "1.2.3.4"), _td("context", "x")])
    assert explicit.observable == "1.2.3.4" and explicit.context == "x"


def test_case_context_never_becomes_an_observable_for_threat_or_social_tools():
    # Las herramientas de amenazas exigen un observable: el texto de contexto de una PERSONA no debe enviarse a un servidor
    # externo como si fuera un indicador, ni dejar a Instaloader con un "perfil" como "ingeniero UDLA Ecuador".
    from osint_app.tools import build_tool_registry
    from osint_app.utils.compatibility import DataCompatibilityEngine
    case = [_td("name", "Juan"), _td("context", "ingeniero UDLA"), _td("country", "Ecuador")]
    registry = build_tool_registry()
    engine = DataCompatibilityEngine()
    for name in ("IntelOwl", "OpenCTI", "MISP", "Cortex"):
        verdict = engine.check(registry[name].requirements, case)
        assert verdict.status == CompatibilityStatus.RED and verdict.missing_mandatory == ["observable"], name
    assert QueryParameters.from_target_data(case).observable == ""


def test_web_searches_do_use_the_case_context(monkeypatch):
    from osint_app.tools.web_search import WebSearchTool
    tool = WebSearchTool()
    asked = []
    monkeypatch.setattr(tool, "_search_duckduckgo", lambda q, max_results=20: asked.append(q) or [])
    monkeypatch.setattr("osint_app.tools.web_search.time.sleep", lambda s: None)
    qp = QueryParameters.from_target_data([_td("name", "Juan Pérez"), _td("context", "ingeniero UDLA"), _td("country", "Ecuador")])
    tool.execute(qp)
    assert '"Juan Pérez" ingeniero UDLA Ecuador' in asked                                     # la herramienta suelta busca igual que el perfilamiento


def test_query_parameters_to_dict_has_every_field():
    d = QueryParameters(target_name="x", university="u").to_dict()
    assert d["target_name"] == "x" and d["university"] == "u" and {"email", "domain", "keywords", "hash_value"} <= set(d)


def test_requirements_hints_for_missing_fields():
    hints = ToolRequirements(mandatory=["domain", "ip", "algo_raro"], optional=[], produces=[]).how_to_get()
    assert set(hints) == {"domain", "ip", "algo_raro"} and "dnspython" in hints["ip"] and hints["algo_raro"] == "Ingresa manualmente"


@pytest.mark.parametrize("status,can_run,fragment", [
    (CompatibilityStatus.GREEN, True, "Listo para ejecutar con: domain"),
    (CompatibilityStatus.YELLOW, True, "faltan (opcionales): email"),
    (CompatibilityStatus.RED, False, "faltan datos obligatorios: ip"),
])
def test_compatibility_result_messages(status, can_run, fragment):
    result = CompatibilityResult(status=status, available=["domain"], missing_mandatory=["ip"], missing_optional=["email"],
                                 missing_hints={"ip": "pista de ip", "email": "pista de email"})
    assert result.can_run is can_run and fragment in result.user_message()
    if status == CompatibilityStatus.RED:
        assert "pista de ip" in result.user_message()
    if status == CompatibilityStatus.YELLOW:
        assert "pista de email" in result.user_message() and "pista de ip" not in result.user_message()
