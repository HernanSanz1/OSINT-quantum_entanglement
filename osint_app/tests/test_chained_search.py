"""Búsqueda encadenada migrada de profiler.py (4.6): descubrir usernames y
lanzar la segunda ronda."""

from osint_app.core.models import SearchResult
from osint_app.profiler_engine import (
    ProfilerEngine, SeedData, ToolResult, extract_usernames_from_results,
)


def _sr(url, title="Juan Pérez"):
    # Por defecto el resultado habla de la persona: solo esos alimentan la búsqueda encadenada
    return SearchResult(title=title, url=url, snippet="", source_tool="GitHubOSINT", category="x")   # fuente estructurada


class _FakeTool:
    def __init__(self, available=True, results=None):
        self.is_available = available
        self._results = results or []

    def execute(self, query_params):
        return self._results


def _engine(tools):
    eng = ProfilerEngine.__new__(ProfilerEngine)
    eng.progress_callback = lambda _msg: None
    eng.tools = tools
    eng.results = []
    eng.warnings = {}
    return eng


def _record_execute(eng, monkeypatch):
    """Sustituye _execute_tool para no ejecutar herramientas reales."""
    calls = []

    def fake(tool_name, query_params, label=None):
        calls.append((tool_name, query_params.username, label))
        return ToolResult(tool_name=label or tool_name, status="ok", results=[])

    monkeypatch.setattr(eng, "_execute_tool", fake)
    return calls


def test_extract_github_linkedin_twitter():
    results = [
        _sr("https://github.com/octocat"),
        _sr("https://github.com/octocat/Spoon-Knife"),   # repo → mismo usuario
        _sr("https://www.linkedin.com/in/juan-perez"),
        _sr("https://twitter.com/jperez"),
        _sr("https://x.com/otro_user"),
    ]
    # LinkedIn ya no se encadena: sus identificadores no son usuarios reutilizables (prueba real con Jorge Ulloa)
    assert extract_usernames_from_results(results) == [
        "octocat", "jperez", "otro_user",
    ]


def test_excludes_reserved_paths():
    results = [
        _sr("https://github.com/search?q=juan"),
        _sr("https://github.com/users/foo"),      # ruta de sistema, no usuario
        _sr("https://twitter.com/i/timeline"),
        _sr("https://github.com/octocat"),
    ]
    assert extract_usernames_from_results(results) == ["octocat"]


def test_dedup_preserves_order():
    results = [_sr("https://github.com/a"), _sr("https://github.com/b"),
               _sr("https://github.com/a")]
    assert extract_usernames_from_results(results) == ["a", "b"]


def test_ignores_results_without_url():
    assert extract_usernames_from_results([_sr(""), _sr("https://example.com/x")]) == []


def test_accepts_dicts_too():
    assert extract_usernames_from_results([{"url": "https://github.com/octocat"}]) == ["octocat"]


# ── Segunda ronda encadenada (4.6b) ───────────────────────────────────────────

def _all_tools():
    return {t: _FakeTool(available=True) for t in ProfilerEngine.CHAINED_USERNAME_TOOLS}


def test_second_round_runs_username_tools_per_discovered(monkeypatch):
    eng = _engine(_all_tools())
    calls = _record_execute(eng, monkeypatch)
    seed = SeedData(name="Juan Perez")

    new = eng.run_second_round(seed, ["jperez", "otro"])

    # 2 usernames × 3 herramientas = 6 ejecuciones
    assert len(calls) == 6
    assert {c[0] for c in calls} == set(ProfilerEngine.CHAINED_USERNAME_TOOLS)
    assert {c[1] for c in calls} == {"jperez", "otro"}
    assert all(":" in c[2] for c in calls)          # etiqueta 'Tool:username'
    # los resultados se añaden a self.results
    assert eng.results == new and len(new) == 6


def test_second_round_excludes_seed_username(monkeypatch):
    eng = _engine(_all_tools())
    calls = _record_execute(eng, monkeypatch)
    seed = SeedData(name="Juan Perez", username="jperez")

    eng.run_second_round(seed, ["jperez", "nuevo"])   # jperez ya era la semilla

    assert {c[1] for c in calls} == {"nuevo"}


def test_second_round_caps_number_of_usernames(monkeypatch):
    eng = _engine(_all_tools())
    calls = _record_execute(eng, monkeypatch)
    many = [f"u{i}" for i in range(10)]

    eng.run_second_round(SeedData(name="X"), many)

    usernames = {c[1] for c in calls}
    assert len(usernames) == ProfilerEngine.MAX_CHAINED_USERNAMES


def test_second_round_skips_unavailable_tools(monkeypatch):
    tools = {"GitHubOSINT": _FakeTool(True), "Sherlock": _FakeTool(False),
             "Maigret": _FakeTool(False)}
    eng = _engine(tools)
    calls = _record_execute(eng, monkeypatch)

    eng.run_second_round(SeedData(name="X"), ["jperez"])

    assert {c[0] for c in calls} == {"GitHubOSINT"}


def test_second_round_respects_only_tools(monkeypatch):
    eng = _engine(_all_tools())
    calls = _record_execute(eng, monkeypatch)

    eng.run_second_round(SeedData(name="X"), ["jperez"], only_tools=["GitHubOSINT", "WebSearch"])

    assert {c[0] for c in calls} == {"GitHubOSINT"}


def test_second_round_no_usernames_is_noop(monkeypatch):
    eng = _engine(_all_tools())
    calls = _record_execute(eng, monkeypatch)
    assert eng.run_second_round(SeedData(name="X"), []) == []
    assert calls == []


def test_run_parallel_chain_triggers_second_round(monkeypatch):
    # run_parallel(chain=True): la ronda 1 descubre 'found' y la pasa a la 2ª.
    tool = _FakeTool(True, results=[_sr("https://github.com/found")])
    eng = _engine({"GitHubOSINT": tool})
    monkeypatch.setattr(eng, "_select_tools_to_run", lambda s, o: ["GitHubOSINT"])

    seen = {}
    monkeypatch.setattr(eng, "run_second_round",
                        lambda s, discovered, **kw: seen.setdefault("discovered", discovered) or [])

    eng.run_parallel(SeedData(name="Juan Pérez"), chain=True)
    assert seen["discovered"] == ["found"]


def test_chain_ignores_results_about_other_people(monkeypatch):
    # Caso real (Kent C. Dodds): github.com/kent y github.com/dodds eran OTRAS personas y se encadenaban
    tool = _FakeTool(True, results=[_sr("https://github.com/kent", title="GitHub encontrado: kent · Nombre: Kent Beck"),
                                    _sr("https://github.com/kentcdodds", title="GitHub: Kent C. Dodds")])
    eng = _engine({"GitHubOSINT": tool})
    monkeypatch.setattr(eng, "_select_tools_to_run", lambda s, o: ["GitHubOSINT"])
    seen = {}
    monkeypatch.setattr(eng, "run_second_round", lambda s, discovered, **kw: seen.setdefault("discovered", discovered) or [])
    eng.run_parallel(SeedData(name="Kent C. Dodds"), chain=True)
    assert seen["discovered"] == ["kentcdodds"]


def test_run_parallel_without_chain_skips_second_round(monkeypatch):
    tool = _FakeTool(True, results=[_sr("https://github.com/found")])
    eng = _engine({"GitHubOSINT": tool})
    monkeypatch.setattr(eng, "_select_tools_to_run", lambda s, o: ["GitHubOSINT"])

    called = {"n": 0}
    def spy(*a, **k):
        called["n"] += 1
        return []
    monkeypatch.setattr(eng, "run_second_round", spy)

    eng.run_parallel(SeedData(name="Juan"), chain=False)
    assert called["n"] == 0


def test_chained_flow_end_to_end(monkeypatch):
    # Sin mocks de orquestación: ejecuta ronda 1 + ronda 2 reales (con hilos),
    # solo con herramientas simuladas. La ronda 1 descubre 'discovered' y la
    # ronda 2 relanza las 3 herramientas de username sobre ese usuario.
    gh = _FakeTool(True, results=[_sr("https://github.com/discovered")])
    eng = _engine({
        "GitHubOSINT": gh,
        "Sherlock": _FakeTool(True, results=[_sr("https://sher/x")]),
        "Maigret": _FakeTool(True, results=[]),
    })
    monkeypatch.setattr(eng, "_select_tools_to_run", lambda s, o: ["GitHubOSINT"])

    eng.run_parallel(SeedData(name="Juan Pérez"), chain=True)

    labels = {tr.tool_name for tr in eng.results}
    assert "GitHubOSINT" in labels                    # ronda 1
    assert {"GitHubOSINT:discovered", "Sherlock:discovered",
            "Maigret:discovered"} <= labels            # ronda 2 encadenada
