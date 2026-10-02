"""M2: semilla más rica (alias, otros correos/usuarios/teléfonos, ciudad, empleador, universidad)."""
import os
import sys

import pytest

from osint_app.core.models import QueryParameters, SearchResult
from osint_app.correlation_engine import CorrelationEngine
from osint_app.profiler_engine import ProfilerEngine, SeedData, ToolResult, parse_list, unique_values


# ── listas ───────────────────────────────────────────────────────────────────

def test_parse_list_splits_cleans_and_dedupes():
    assert parse_list("a@x.com, b@y.com; c@z.com") == ["a@x.com", "b@y.com", "c@z.com"]
    assert parse_list("a@x.com, , A@X.COM ;b@y.com") == ["a@x.com", "b@y.com"]
    assert parse_list("uno\ndos, tres") == ["uno", "dos", "tres"]
    assert parse_list("@charly, candrade, @CHARLY", strip_at=True) == ["charly", "candrade"]
    assert parse_list("") == [] and parse_list(None) == [] and parse_list(" , ; ") == []


def test_unique_values_keeps_first_spelling_and_order():
    assert unique_values(["Juan", None, "juan", " Ana ", "", "ANA"]) == ["Juan", "Ana"]


def test_seed_collects_primary_and_extras_without_repeating():
    seed = SeedData(name="Carlos Andrade", email="c@utpl.edu.ec", username="@cand", phone="+593 99 111 2222",
                    aliases=["Carlos Andrade León", "carlos andrade"], extra_emails=["otro@gmail.com", "C@UTPL.EDU.EC"],
                    extra_usernames=["@charly", "CAND"], extra_phones=["+593988888888"])
    assert seed.all_names() == ["Carlos Andrade", "Carlos Andrade León"]
    assert seed.all_emails() == ["c@utpl.edu.ec", "otro@gmail.com"]
    assert seed.all_usernames() == ["cand", "charly"]
    assert seed.all_phones() == ["+593 99 111 2222", "+593988888888"]


def test_query_params_carry_city_university_and_company():
    qp = SeedData(name="Juan", context="ingeniero", country="Ecuador", city="Loja", university="UTPL", company="Banco X").to_query_params()
    assert qp.location == "Loja" and qp.university == "UTPL" and qp.company == "Banco X"
    assert qp.observable == "ingeniero Ecuador Loja"                     # la ciudad también es contexto de búsqueda
    plain = SeedData(name="Juan", context="ingeniero", country="Ecuador").to_query_params()
    assert plain.observable == "ingeniero Ecuador" and plain.location == "" and plain.university == ""


# ── puntuación ───────────────────────────────────────────────────────────────

def score(seed, text, url=""):
    r = SearchResult(title=text, url=url, snippet="", source_tool="t")
    return ProfilerEngine()._calculate_confidence(r, seed)


def test_alias_matches_like_the_name():
    seed = SeedData(name="Carlos Andrade", aliases=["Carlos Andrade León", "Charly Andrade"])
    assert score(seed, "Perfil de Carlos Andrade León") == (40.0, ["name"])         # el principal también está contenido: gana
    pts, matched = score(seed, "Charly Andrade, ingeniero")
    assert pts == 40.0 and matched == ["alias"]
    assert score(seed, "Carlos Andrade, ingeniero") == (40.0, ["name"])         # el nombre principal gana si coincide igual
    assert score(SeedData(name="Carlos Andrade"), "Charly Andrade")[0] == 10.0   # sin alias, solo el apellido coincide


def test_alias_does_not_stack_with_name():
    seed = SeedData(name="Carlos Andrade", aliases=["Carlos Andrade León"])
    assert score(seed, "Carlos Andrade León")[0] == 40.0                          # una coincidencia, no 80


def test_extra_email_username_phone_match():
    seed = SeedData(name="Zzz Qqq", email="a@x.com", extra_emails=["otro@gmail.com"], username="user1",
                    extra_usernames=["charly"], phone="0987654321", extra_phones=["+593 98 111 2222"])
    assert score(seed, "escribe a otro@gmail.com") == (35.0, ["email"])
    assert score(seed, "perfil de charly en github") == (25.0, ["username"])
    assert score(seed, "tel 098-111-2222") == (30.0, ["phone"])
    assert score(seed, "nada que ver")[0] == 0.0


def test_employer_university_and_city_corroborate():
    seed = SeedData(name="Juan Perez", company="Banco Pichincha", university="UTPL", city="Loja")
    pts, matched = score(seed, "Juan Perez - Gerente en Banco Pichincha, egresado de la UTPL, vive en Loja")
    assert pts == 40 + 15 + 15 + 10 and matched == ["name", "company", "university", "city"]
    assert score(seed, "Juan Perez en Quito")[1] == ["name"]
    assert score(SeedData(name="Juan Perez", city="Lo"), "Juan Perez Lo")[1] == ["name"]       # texto demasiado corto: no cuenta
    assert "city" not in score(SeedData(name="Juan Perez", city="Loja"), "Juan Perez en Lojano")[1]    # palabra completa


def test_city_is_context_for_homonym_signals():
    seed = SeedData(name="Juan Perez", country="Ecuador", city="Loja")
    eng = ProfilerEngine()
    eng.results = [ToolResult("T", "ok", [SearchResult(title="Juan Perez en Guayaquil", url="https://a.com/1", snippet="",
                                                       source_tool="T", category="Web", relevance_score=70)])]
    cand = eng.extract_candidates(seed, min_confidence=0)[0]
    assert "guayaquil" in cand.warning and "loja" in cand.warning                  # menciona otra ciudad del mismo país


# ── rondas extra por identificador adicional ─────────────────────────────────

class FakeTool:
    is_available = True

    def __init__(self, calls, name):
        self.calls, self.name = calls, name

    def execute(self, qp):
        self.calls.append((self.name, qp.target_name, qp.username, qp.email, qp.phone))
        return []


def engine_with(*names):
    calls = []
    eng = ProfilerEngine()
    eng.tools = {n: FakeTool(calls, n) for n in names}
    return eng, calls


def test_extra_identifiers_run_the_right_tools_with_the_right_field():
    eng, calls = engine_with("GitHubOSINT", "Sherlock", "Maigret", "Holehe", "Google Dorks", "phonenumbers", "WebSearch", "UsernameVariants")
    seed = SeedData(name="Carlos Andrade", username="cand", email="a@x.com", phone="0987654321",
                    aliases=["Charly Andrade"], extra_emails=["otro@gmail.com"], extra_usernames=["charly"], extra_phones=["+593988888888"])
    res = eng.run_extra_identifiers(seed)
    assert {(c[0], c[2]) for c in calls if c[0] in ("GitHubOSINT", "Sherlock", "Maigret")} == {("GitHubOSINT", "charly"), ("Sherlock", "charly"), ("Maigret", "charly")}
    assert {c[0] for c in calls if c[3] == "otro@gmail.com"} == {"Holehe", "Google Dorks"}
    assert {c[0] for c in calls if c[4] == "+593988888888"} == {"phonenumbers", "Google Dorks"}
    assert {c[0] for c in calls if c[1] == "Charly Andrade"} == {"WebSearch", "UsernameVariants"}
    assert len(calls) == 3 + 2 + 2 + 2 and len(res) == len(calls) and len(eng.results) == len(calls)
    assert {r.tool_name for r in res} >= {"Sherlock:charly", "Holehe:otro@gmail.com", "WebSearch:Charly Andrade"}


def test_extra_identifiers_skip_primary_duplicates_and_are_capped():
    eng, calls = engine_with("Holehe")
    seed = SeedData(name="X Y", email="a@x.com", extra_emails=["A@X.COM", "b@x.com", "c@x.com", "d@x.com", "e@x.com"])
    eng.run_extra_identifiers(seed)
    assert [c[3] for c in calls] == ["b@x.com", "c@x.com", "d@x.com"]            # sin el principal, y solo 3


def test_extra_identifiers_respect_tool_selection_and_availability():
    eng, calls = engine_with("Holehe", "WebSearch")
    seed = SeedData(name="X Y", extra_emails=["b@x.com"], aliases=["Z Y"])
    eng.run_extra_identifiers(seed, only_tools=["Holehe"])
    assert {c[0] for c in calls} == {"Holehe"}
    eng, calls = engine_with("Holehe")
    eng.tools["Holehe"].is_available = False
    assert eng.run_extra_identifiers(seed) == [] and calls == []
    assert engine_with("Holehe")[0].run_extra_identifiers(SeedData(name="X Y")) == []      # sin datos adicionales no hace nada


def test_run_parallel_includes_extras_without_chain():
    eng, calls = engine_with("WebSearch", "Holehe")
    eng.run_parallel(SeedData(name="Carlos Andrade", email="a@x.com", extra_emails=["otro@gmail.com"]), only_tools=["WebSearch", "Holehe"])
    assert ("Holehe", "Carlos Andrade", "", "otro@gmail.com", "") in calls and ("Holehe", "Carlos Andrade", "", "a@x.com", "") in calls


# ── guardado en el caso ──────────────────────────────────────────────────────

def test_extras_are_saved_in_the_case_without_changing_the_target(temp_db):
    seed = SeedData(name="Carlos Andrade", context="ingeniero", country="Ecuador", email="a@x.com", city="Loja", university="UTPL",
                    aliases=["Carlos Andrade León"], extra_emails=["otro@gmail.com"], extra_usernames=["@charly"], extra_phones=["+593988888888"])
    case_id = ProfilerEngine().save_to_case(seed)
    stored = {(d.field_type, d.value, d.confidence) for d in temp_db.get_target_data(case_id)}
    assert {("name", "Carlos Andrade León", 95), ("email", "otro@gmail.com", 95), ("username", "charly", 95),
            ("phone", "+593988888888", 95), ("location", "Loja", 100), ("university", "UTPL", 100), ("name", "Carlos Andrade", 100)} <= stored
    params = QueryParameters.from_target_data(temp_db.get_target_data(case_id))
    assert params.target_name == "Carlos Andrade" and params.email == "a@x.com"            # el principal sigue mandando
    assert params.location == "Loja" and params.university == "UTPL"
    kinds = {c.relation_type for c in CorrelationEngine(case_id).correlations}
    assert "same_name" in kinds                                                              # el alias se une al nombre


# ── la pantalla ──────────────────────────────────────────────────────────────

def _real_tab():
    """La pestaña real, solo donde abrir Qt es seguro (Windows, o con SENTINEL_GUI_TESTS=1)."""
    if not (sys.platform == "win32" or os.environ.get("SENTINEL_GUI_TESTS") == "1"):
        pytest.skip("abrir Qt solo se prueba en Windows o con SENTINEL_GUI_TESTS=1")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    from types import SimpleNamespace
    try:
        from PySide6.QtWidgets import QApplication
        from osint_app.gui.tab_profiling import ProfilingTab
    except ImportError as e:
        pytest.skip(f"interfaz no disponible: {e}")
    QApplication.instance() or QApplication([])
    app = SimpleNamespace(toast=SimpleNamespace(show=lambda *a, **k: None), active_case_id=None, pages=[],
                          case_badge=SimpleNamespace(setText=lambda t: None))
    return ProfilingTab(app)


def test_real_tab_has_collapsible_extra_fields_and_builds_the_seed():
    tab = _real_tab()
    assert not tab.more_box.isVisibleTo(tab)
    tab.btn_more.setChecked(True)
    assert tab.more_box.isVisibleTo(tab) and tab.btn_more.text().startswith("▾")
    tab.input_name.setText("Carlos Andrade")
    tab.input_company.setText("Banco Pichincha")
    tab.input_university.setText("UTPL")
    tab.input_city.setText("Loja")
    tab.input_aliases.setText("Carlos Andrade León, Charly Andrade; carlos andrade león")
    tab.input_more_emails.setText("otro@gmail.com, , OTRO@gmail.com")
    tab.input_more_usernames.setText("@charly, candrade")
    tab.input_more_phones.setText("+593988888888")
    seed = tab._seed_from_inputs()
    assert (seed.company, seed.university, seed.city) == ("Banco Pichincha", "UTPL", "Loja")
    assert seed.aliases == ["Carlos Andrade León", "Charly Andrade"] and seed.extra_emails == ["otro@gmail.com"]
    assert seed.extra_usernames == ["charly", "candrade"] and seed.extra_phones == ["+593988888888"]
    tab._on_new_profile()
    assert not any(w.text() for w in (tab.input_company, tab.input_city, tab.input_aliases, tab.input_more_emails, tab.input_more_phones))


def test_real_tab_seed_without_extras_is_the_same_as_before():
    tab = _real_tab()
    tab.input_name.setText("Juan Perez")
    seed = tab._seed_from_inputs()
    assert seed.company is None and seed.city == "" and seed.aliases == [] and seed.extra_emails == []
