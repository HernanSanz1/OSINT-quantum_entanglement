"""ProfilerEngine y su interacción con las herramientas (sin red).

Integración 4.1: context/country llegan a las herramientas vía `observable`,
sin que SpiderFoot escanee ese texto libre como objetivo.
"""
import pytest

from osint_app.core.models import QueryParameters
from osint_app.profiler_engine import ProfilerEngine, SeedData
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
