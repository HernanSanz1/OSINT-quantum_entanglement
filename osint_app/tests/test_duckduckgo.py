"""Búsqueda en DuckDuckGo: parseo robusto + respaldo a lite (sin red)."""
import pytest

from osint_app.tools import web_search
from osint_app.tools.web_search import _ddg_unwrap, duckduckgo_search

HTML_OK = """
<div class="result"><a class="result__a" href="https://a.com">Titulo A</a>
  <a class="result__snippet">Snippet A</a></div>
<div class="result"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fb.com&rut=x">Titulo B</a>
  <a class="result__snippet">Snippet B</a></div>
"""

LITE_OK = """
<a class="result-link" href="https://c.com">Titulo C</a>
<span class="result-snippet">Snippet C</span>
<a class="result-link" href="https://d.com">Titulo D</a>
<span class="result-snippet">Snippet D</span>
"""


class _Resp:
    def __init__(self, status=200, text=""):
        self.status_code = status; self.text = text


def test_unwrap_redirect():
    assert _ddg_unwrap("//duckduckgo.com/l/?uddg=https%3A%2F%2Fx.com&a=1") == "https://x.com"
    assert _ddg_unwrap("https://direct.com/path") == "https://direct.com/path"
    assert _ddg_unwrap("//cdn.x/y") == "https://cdn.x/y"


def test_parses_html_results(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp(200, HTML_OK))
    hits = duckduckgo_search("algo")
    assert [h["title"] for h in hits] == ["Titulo A", "Titulo B"]
    assert hits[1]["url"] == "https://b.com"        # redirección deshecha
    assert hits[0]["snippet"] == "Snippet A"


def test_falls_back_to_lite_when_html_empty(monkeypatch):
    import requests
    calls = {"n": 0}
    def fake_post(url, *a, **k):
        calls["n"] += 1
        if "lite" in url:
            return _Resp(200, LITE_OK)
        return _Resp(200, "<html>sin resultados</html>")   # html vacío
    monkeypatch.setattr(requests, "post", fake_post)
    hits = duckduckgo_search("algo")
    assert calls["n"] == 2                            # intentó html y luego lite
    assert [h["title"] for h in hits] == ["Titulo C", "Titulo D"]
    assert hits[0]["snippet"] == "Snippet C"


def test_falls_back_to_lite_on_html_429(monkeypatch):
    import requests
    def fake_post(url, *a, **k):
        return _Resp(200, LITE_OK) if "lite" in url else _Resp(429, "")
    monkeypatch.setattr(requests, "post", fake_post)
    assert len(duckduckgo_search("algo")) == 2


def test_returns_empty_when_both_fail(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp(503, ""))
    assert duckduckgo_search("algo") == []
