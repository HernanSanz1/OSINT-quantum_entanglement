"""Listados de personas (directorios, buscadores) que no deben contar como candidatos."""
import pytest

from osint_app.core.models import SearchResult
from osint_app.profiler_engine import ProfilerEngine, SeedData, ToolResult
from osint_app.utils.directories import is_directory_result


@pytest.mark.parametrize("title,url,reason", [
    # casos reales de una búsqueda de "Carlos Andrade"
    ('600+ "Carlos Andrade" profiles | LinkedIn', "https://www.linkedin.com/pub/dir/CARLOS+/Andrade", "directorio de LinkedIn"),
    ('700+ "Carlos Andrade" profiles | LinkedIn', "https://www.linkedin.com/pub/dir/Carlos/Andrade/", "directorio de LinkedIn"),
    ('300+ "Carlos Andrade" profiles | LinkedIn', "https://www.linkedin.com/pub/dir/+/Carlos+andrade", "directorio de LinkedIn"),
    ("Directorio", "https://ec.linkedin.com/directory/people-c", "directorio de LinkedIn"),
    ("Juan Perez", "https://www.facebook.com/public/Juan-Perez", "directorio de Facebook"),
    ("Juan Perez - Spokeo", "https://www.spokeo.com/Juan-Perez", "buscador de personas"),
    ("Juan Perez", "https://www.whitepages.com/name/Juan-Perez", "buscador de personas"),
    ("Juan Perez", "https://www.truepeoplesearch.com/results?name=Juan", "buscador de personas"),
    # solo por el título
    ('1.200 perfiles de «Carlos Andrade»', "https://sitio.com/x", "listado de perfiles"),
    ("50 people named Juan Perez", "https://sitio.com/x", "listado de perfiles"),
    ("400+ profiles", "https://sitio.com/x", "listado de perfiles"),
    ("Perfiles de Juan Perez | LinkedIn", "https://sitio.com/x", "listado de perfiles"),
])
def test_listings_are_detected(title, url, reason):
    assert is_directory_result(title, url) == reason


@pytest.mark.parametrize("title,url", [
    ("Carlos Andrade - LinkedIn Ecuador", "https://ec.linkedin.com/in/carlosandradevalencia"),          # perfil real
    ("Carlos Andrade - Ingeniero Civil - LinkedIn Ecuador", "https://ec.linkedin.com/in/carlos-andrade-6b9379"),
    ("Carlos ANDRADE | Ingenieria Mecanica | Research profile", "https://www.researchgate.net/profile/Carlos-Andrade"),
    ("Juan Perez", "https://www.linkedin.com/pub/juan-perez/12/345/678"),                              # perfil antiguo de LinkedIn: no es /pub/dir/
    ("Juan Perez", "https://www.facebook.com/juan.perez.123"),
    ("Juan Perez", "https://www.facebook.com/people/Juan-Perez/100012345"),                            # página de persona, no el directorio /public/
    ("3 profiles of the Open Source community", "https://sitio.com/x"),                                # empieza con número pero no es un listado de personas
    ("Los 10 mejores perfiles de GitHub", "https://sitio.com/x"),
    ("Juan Perez trabaja con 200 personas", "https://sitio.com/x"),
    ("Perfil de Juan Perez", "https://sitio.com/juan"), ("", ""), (None, None),
])
def test_real_people_pages_are_not_listings(title, url):
    assert is_directory_result(title, url) == ""


def test_hosts_that_only_look_like_a_directory_are_kept():
    assert is_directory_result("x", "https://notspokeo.com/a") == ""
    assert is_directory_result("x", "https://evil.com/spokeo.com/a") == ""
    assert is_directory_result("x", "https://evil.com/linkedin.com/pub/dir/a") == ""


# ── integración con el perfilador ────────────────────────────────────────────

def _sr(title, url):
    return SearchResult(title=title, url=url, snippet="", source_tool="WebSearch", category="Web", relevance_score=70)


def test_listings_are_not_candidates_but_stay_in_the_results():
    logs = []
    eng = ProfilerEngine(progress_callback=logs.append)
    eng.results = [ToolResult("WebSearch", "ok", [
        _sr("Carlos Andrade - LinkedIn Ecuador", "https://ec.linkedin.com/in/carlosandrade1990"),
        _sr('600+ "Carlos Andrade" profiles | LinkedIn', "https://www.linkedin.com/pub/dir/CARLOS+/Andrade"),
        _sr('700+ "Carlos Andrade" profiles | LinkedIn', "https://www.linkedin.com/pub/dir/Carlos/Andrade/"),
        _sr("Carlos Andrade - Spokeo", "https://www.spokeo.com/Carlos-Andrade"),
    ])]
    cands = eng.extract_candidates(SeedData(name="Carlos Andrade", country="Ecuador"))
    assert [c.url for c in cands] == ["https://ec.linkedin.com/in/carlosandrade1990"]
    assert eng.skipped_listings == {"directorio de LinkedIn": 2, "buscador de personas": 1}
    assert len(eng.results[0].results) == 4                                              # nada se pierde de los reportes
    assert any("Omitidos 3 listados" in m and "siguen en los reportes" in m for m in logs)


def test_no_message_when_nothing_is_skipped():
    logs = []
    eng = ProfilerEngine(progress_callback=logs.append)
    eng.results = [ToolResult("WebSearch", "ok", [_sr("Carlos Andrade", "https://ec.linkedin.com/in/x")])]
    eng.extract_candidates(SeedData(name="Carlos Andrade"))
    assert eng.skipped_listings == {} and not any("Omitidos" in m for m in logs)


def test_listings_still_saved_in_the_case_reports(temp_db):
    eng = ProfilerEngine()
    eng.results = [ToolResult("WebSearch", "ok", [_sr('600+ "Carlos Andrade" profiles | LinkedIn', "https://www.linkedin.com/pub/dir/CARLOS+/Andrade")])]
    case_id = eng.save_to_case(SeedData(name="Carlos Andrade"))
    assert temp_db.get_reports(case_id)[0].results_count == 1
