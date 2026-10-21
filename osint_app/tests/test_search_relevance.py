"""Filtro de pertinencia de la búsqueda web: el nombre buscado entre comillas tiene que aparecer en el resultado."""
import pytest

from osint_app.utils import search_engine
from osint_app.utils.search_engine import mentions_all, required_words, web_search


@pytest.mark.parametrize("query,words", [
    ('"Jefferson Pérez" marchista', ["jefferson", "perez"]),
    ('"Glenda Morejón" (linkedin OR resume OR "curriculum vitae")', ["glenda", "morejon"]),
    ('("Ana Paz" OR x) "Luis Vera"', ["luis", "vera"]),          # lo de dentro de ( … OR … ) no es obligatorio
    ('site:x.com inurl:"foo bar" "Ana Paz"', ["ana", "paz"]),    # inurl:"…" no es un nombre
    ('"midudev" site:github.com', []),                           # usuario: puede aparecer escrito de otra forma
    ('"a@b.com" (password OR token)', []), ('"+593 99 123 4567"', []), ("Jefferson Pérez marchista", []),
])
def test_required_words_only_for_quoted_names(query, words):
    assert required_words(query) == words


def test_mentions_all_ignores_accents_and_reads_the_url():
    words = ["jefferson", "perez"]
    # resultados reales de Bing dentro de SearXNG para "Jefferson Pérez" marchista (21-10-2026)
    assert not mentions_all({"title": "Thomas Jefferson - Wikipedia",
                             "url": "https://en.wikipedia.org/wiki/Thomas_Jefferson"}, words)
    assert mentions_all({"title": "Jefferson Perez - Sitio Oficial", "url": "http://jeffersonperez.com/"}, words)
    assert mentions_all({"title": "x", "url": "https://es.wikipedia.org/wiki/Jefferson_P%C3%A9rez"}, words)


def _fake_engines(monkeypatch, engines):
    monkeypatch.setattr(search_engine, "_engines", lambda: engines)
    monkeypatch.setattr(search_engine, "_wait_turn", lambda name: None)
    monkeypatch.setattr(search_engine, "_cooldown_until", {})


def test_off_topic_results_are_dropped_and_the_next_engine_is_tried(monkeypatch):
    junk = [{"title": f"Thomas Jefferson {i}", "url": f"https://ejemplo.com/{i}", "snippet": ""} for i in range(10)]
    good = [{"title": "Jefferson Pérez, campeón olímpico", "url": "https://ejemplo.ec/jp", "snippet": ""}]
    _fake_engines(monkeypatch, [("searxng", lambda q, n: junk), ("yahoo", lambda q, n: good)])
    out = web_search('"Jefferson Pérez" marchista')
    assert [h["url"] for h in out.hits] == ["https://ejemplo.ec/jp"] and out.engine == "yahoo"
    assert out.attempts == [("searxng", "vacío"), ("yahoo", "ok")]   # descartar no es un bloqueo: sin pausa
    assert not search_engine._in_cooldown("searxng") and not out.incomplete


def test_searxng_is_asked_for_more_when_filtering(monkeypatch):
    asked = []
    _fake_engines(monkeypatch, [("searxng", lambda q, n: asked.append(n) or [])])
    web_search('"Glenda Morejón"', max_results=10)
    web_search('"midudev"', max_results=10)
    assert asked == [30, 10]
