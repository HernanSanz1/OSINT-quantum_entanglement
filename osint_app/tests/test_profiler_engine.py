"""ProfilerEngine y su interacción con las herramientas (sin red).

Integración 4.1: context/country llegan a las herramientas vía `observable`,
sin que SpiderFoot escanee ese texto libre como objetivo.
"""
import pytest

from osint_app.core.models import QueryParameters
from osint_app.profiler_engine import (
    ProfilerEngine, SeedData, enrich_seed_from_candidates,
)
from osint_app.tools.heavy_tools import SpiderFootTool, _looks_like_observable


def _engine_with_applicable(monkeypatch, applicable):
    """ProfilerEngine sin construir el registro; get_tools_for_seed fijo."""
    eng = ProfilerEngine.__new__(ProfilerEngine)
    eng.progress_callback = lambda _msg: None
    monkeypatch.setattr(eng, "get_tools_for_seed", lambda seed: list(applicable))
    return eng


# ── SeedData.to_query_params (bug 4) ──────────────────────────────────────────

def test_context_and_country_reach_observable():
    qp = SeedData(name="Juan Perez", context="UDLA Ecuador 2006",
                  country="Ecuador").to_query_params()
    assert qp.observable == "UDLA Ecuador 2006 Ecuador"
    assert qp.target_name == "Juan Perez"


def test_observable_empty_when_no_context():
    qp = SeedData(name="Juan Perez").to_query_params()
    assert qp.observable == ""


def test_other_fields_still_mapped():
    qp = SeedData(name="X", email="a@b.com", domain="b.com",
                  username="u", company="C", phone="+593999").to_query_params()
    assert (qp.email, qp.domain, qp.username, qp.company, qp.phone) == \
           ("a@b.com", "b.com", "u", "C", "+593999")


# ── _looks_like_observable ────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [
    ("example.com", True),
    ("8.8.8.8", True),
    ("juan@example.com", True),
    ("UDLA Ecuador 2006", False),   # texto libre con espacios
    ("Ecuador", False),             # una palabra que no es dominio/ip/email
    ("", False),
    ("juan@", False),               # email incompleto
])
def test_looks_like_observable(value, expected):
    assert _looks_like_observable(value) is expected


# ── SpiderFoot no escanea el contexto como objetivo ───────────────────────────

def test_spiderfoot_ignores_freetext_observable():
    # El perfilador pone el contexto en observable; SpiderFoot debe usar el
    # dominio, no "UDLA Ecuador 2006".
    qp = QueryParameters(target_name="Juan Perez", domain="example.com",
                         observable="UDLA Ecuador 2006")
    assert SpiderFootTool._pick_target(qp) == "example.com"


def test_spiderfoot_uses_real_observable():
    qp = QueryParameters(observable="target.com", domain="other.com")
    assert SpiderFootTool._pick_target(qp) == "target.com"


def test_spiderfoot_falls_back_to_name():
    qp = QueryParameters(target_name="Juan Perez", observable="contexto libre")
    assert SpiderFootTool._pick_target(qp) == "Juan Perez"


# ── Selección de herramientas (bug 1) ─────────────────────────────────────────

APPLICABLE = ["Google Dorks", "GitHubOSINT", "WebSearch", "UsernameVariants"]


def test_no_selection_runs_all(monkeypatch):
    eng = _engine_with_applicable(monkeypatch, APPLICABLE)
    seed = SeedData(name="Juan Perez")
    assert eng._select_tools_to_run(seed, None) == APPLICABLE
    assert eng._select_tools_to_run(seed, []) == APPLICABLE   # lista vacía = todas


def test_selection_runs_only_chosen(monkeypatch):
    eng = _engine_with_applicable(monkeypatch, APPLICABLE)
    seed = SeedData(name="Juan Perez")
    got = eng._select_tools_to_run(seed, ["WebSearch", "GitHubOSINT"])
    assert got == ["GitHubOSINT", "WebSearch"]   # respeta el orden de aplicables


def test_selected_but_not_applicable_is_skipped(monkeypatch):
    eng = _engine_with_applicable(monkeypatch, APPLICABLE)
    seed = SeedData(name="Juan Perez")
    # "Sherlock" no está entre las aplicables (p.ej. no instalada) → se omite
    got = eng._select_tools_to_run(seed, ["WebSearch", "Sherlock"])
    assert got == ["WebSearch"]


# ── Guardado en caso (bug 2) ──────────────────────────────────────────────────

def _engine_with_results(results):
    eng = ProfilerEngine.__new__(ProfilerEngine)
    eng.progress_callback = lambda _msg: None
    eng.results = results
    return eng


def test_save_to_case_persists_seed_and_reports(temp_db):
    from osint_app.core.models import SearchResult
    from osint_app.profiler_engine import ToolResult

    hits = [SearchResult(title="The Octocat", url="https://github.com/octocat",
                         snippet="perfil", source_tool="GitHubOSINT", category="GitHub")]
    eng = _engine_with_results([ToolResult(tool_name="GitHubOSINT", status="ok",
                                           results=hits, duration_seconds=1.5)])
    seed = SeedData(name="Juan Perez", context="UDLA", country="Ecuador",
                    email="j@x.com", username="jperez")

    case_id = eng.save_to_case(seed)

    # La semilla se guardó como datos del caso
    stored = {(d.field_type, d.value) for d in temp_db.get_target_data(case_id)}
    assert ("name", "Juan Perez") in stored
    assert ("email", "j@x.com") in stored
    assert ("country", "Ecuador") in stored

    # El reporte de la herramienta se guardó con sus resultados
    reports = temp_db.get_reports(case_id)
    assert len(reports) == 1
    assert reports[0].tool_name == "GitHubOSINT"
    assert reports[0].results_count == 1
    assert "octocat" in reports[0].raw_json


def test_save_to_case_promotes_github_profile_fields(temp_db):
    # Migrado de profiler.py: al guardar, los campos estructurados de un perfil
    # de GitHub pasan a ser datos del caso.
    from osint_app.core.models import SearchResult
    from osint_app.profiler_engine import ToolResult

    profile = SearchResult(
        title="GitHub: Juan", url="https://github.com/jperez", snippet="",
        source_tool="GitHubOSINT", category="GitHub Profile",
        extra_data={"name": "Juan Perez", "email": "juan@empresa.com",
                    "company": "@empresa", "location": "Quito, Ecuador",
                    "twitter": "jperez_tw"},
    )
    eng = _engine_with_results([ToolResult(tool_name="GitHubOSINT", status="ok",
                                           results=[profile])])
    case_id = eng.save_to_case(SeedData(name="Juan Perez"))

    stored = {(d.field_type, d.value) for d in temp_db.get_target_data(case_id)}
    assert ("company", "@empresa") in stored
    assert ("location", "Quito, Ecuador") in stored
    assert ("twitter", "@jperez_tw") in stored          # normaliza la @
    assert ("email", "juan@empresa.com") in stored


def test_promote_profile_fields_dedups(temp_db):
    from osint_app.core.models import SearchResult
    from osint_app.profiler_engine import ToolResult
    from osint_app.case_manager import CaseManager

    case = CaseManager().create("c", "")
    profile = SearchResult(title="", url="", snippet="", source_tool="GitHubOSINT",
                           category="GitHub Profile",
                           extra_data={"location": "Quito"})
    eng = _engine_with_results([ToolResult(tool_name="GitHubOSINT", status="ok",
                                           results=[profile])])
    eng._promote_profile_fields(case.id)
    eng._promote_profile_fields(case.id)   # segunda vez: no debe duplicar
    locs = [d for d in temp_db.get_target_data(case.id) if d.field_type == "location"]
    assert len(locs) == 1


def test_save_to_case_reuses_given_case(temp_db):
    from osint_app.case_manager import CaseManager
    existing = CaseManager().create("Caso previo", "")
    eng = _engine_with_results([])
    seed = SeedData(name="Juan Perez")

    returned = eng.save_to_case(seed, case_id=existing.id)

    assert returned == existing.id
    # No debe duplicar la semilla en un caso existente
    assert temp_db.get_target_data(existing.id) == []


# ── Refinar: enriquecer la semilla con confirmados (bug 3) ────────────────────

def test_enrich_extracts_username_email_domain():
    seed = SeedData(name="Juan Perez")
    confirmed = [
        {"url": "https://github.com/jperez", "title": "Juan Perez", "snippet": ""},
        {"url": "", "title": "", "snippet": "contacto: juan@empresa.com"},
    ]
    out = enrich_seed_from_candidates(seed, confirmed)
    assert out.username == "jperez"
    assert out.email == "juan@empresa.com"
    assert out.domain == "empresa.com"


def test_enrich_never_overwrites_user_data():
    seed = SeedData(name="Juan Perez", username="original", email="mio@x.com")
    confirmed = [{"url": "https://github.com/otro", "snippet": "otro@y.com"}]
    out = enrich_seed_from_candidates(seed, confirmed)
    assert out.username == "original"
    assert out.email == "mio@x.com"


def test_enrich_ignores_github_reserved_paths():
    seed = SeedData(name="Juan Perez")
    confirmed = [{"url": "https://github.com/search?q=juan", "snippet": ""}]
    out = enrich_seed_from_candidates(seed, confirmed)
    assert out.username is None


def test_enrich_does_not_mutate_original():
    seed = SeedData(name="Juan Perez")
    enrich_seed_from_candidates(seed, [{"url": "https://github.com/jperez"}])
    assert seed.username is None


# ── Señal de homónimo (4.5, enfoque A) ────────────────────────────────────────

def _engine_from_results(results):
    eng = ProfilerEngine.__new__(ProfilerEngine)
    eng.progress_callback = lambda _msg: None
    eng.results = results
    eng.candidates = []
    return eng


def test_homonym_candidate_is_flagged_and_penalized():
    from osint_app.core.models import SearchResult
    from osint_app.profiler_engine import ToolResult

    good = SearchResult(title="Juan Perez - Quito", url="https://x/1",
                        snippet="Ecuador", source_tool="WebSearch", category="X")
    homonym = SearchResult(title="Juan Perez - Madrid, Spain", url="https://x/2",
                           snippet="España", source_tool="WebSearch", category="X")
    eng = _engine_from_results([ToolResult(tool_name="WebSearch", status="ok",
                                           results=[good, homonym])])
    seed = SeedData(name="Juan Perez", country="Ecuador")

    cands = {c.url: c for c in eng.extract_candidates(seed, min_confidence=0)}

    # El homónimo NO se elimina (enfoque A): sigue presente, pero avisado...
    assert set(cands) == {"https://x/1", "https://x/2"}
    assert cands["https://x/2"].warning        # tiene aviso
    assert not cands["https://x/1"].warning     # el bueno no
    # ...y penalizado, por lo que queda por debajo del bueno
    assert cands["https://x/2"].confidence < cands["https://x/1"].confidence
    assert eng.candidates[0].url == "https://x/1"   # ordenado: el bueno primero


def test_no_warning_without_country_signal():
    from osint_app.core.models import SearchResult
    from osint_app.profiler_engine import ToolResult
    sr = SearchResult(title="Juan Perez", url="https://x/1", snippet="ingeniero",
                      source_tool="WebSearch", category="X")
    eng = _engine_from_results([ToolResult(tool_name="WebSearch", status="ok", results=[sr])])
    cands = eng.extract_candidates(SeedData(name="Juan Perez", country="Ecuador"),
                                   min_confidence=0)
    assert cands[0].warning == ""
