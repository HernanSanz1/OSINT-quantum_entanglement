"""WebSearch y GitHub: clasificar bien las URLs y no presentar un error como 'no existe'."""
import io
import json
import urllib.error

import pytest

from osint_app.core.models import QueryParameters
from osint_app.tools import web_search as ws
from osint_app.tools.web_search import (
    GitHubOSINTTool, UsernameVariantsTool, classify_url, github_unavailable_hint, score_github_match,
)


# ── clasificación por dominio ────────────────────────────────────────────────

@pytest.mark.parametrize("url,category", [
    ("https://www.linkedin.com/in/jperez", "LinkedIn"), ("https://ec.linkedin.com/in/x", "LinkedIn"),
    ("https://github.com/user", "GitHub"), ("https://gist.github.com/u/1", "GitHub"),
    ("https://x.com/user", "Twitter/X"), ("https://mobile.twitter.com/a", "Twitter/X"),
    ("https://www.facebook.com/p", "Facebook"), ("https://www.instagram.com/p", "Instagram"),
    # antes marcados como Twitter/X por contener "x.com":
    ("https://www.linux.com/news", "Web"), ("https://box.com/x", "Web"), ("https://www.netflix.com/title", "Web"),
    ("https://notgithub.com/u", "Web"), ("https://evil.com/github.com/user", "Web"), ("", "Web"), ("no es url", "Web"),
])
def test_classify_url(url, category):
    assert classify_url(url)[0] == category


# ── GitHubOSINT: 404 no es lo mismo que un error ─────────────────────────────

def _http_error(code):
    return urllib.error.HTTPError("https://api.github.com/x", code, "msg", {}, io.BytesIO(b"{}"))


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status = payload, status

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urlopen(routes):
    """routes: {fragmento de URL: dato | excepción}. Lo no listado responde 404."""
    def fake(req, timeout=None, context=None):
        url = req.full_url
        for fragment, value in routes.items():
            if fragment in url:
                if isinstance(value, Exception):
                    raise value
                return _Resp(value)
        raise _http_error(404)
    return fake


@pytest.fixture
def github(monkeypatch):
    monkeypatch.setattr(ws.time, "sleep", lambda s: None)

    def install(routes):
        monkeypatch.setattr(ws.urllib.request, "urlopen", _fake_urlopen(routes))
    return install


def _run(tool_cls, **params):
    return tool_cls().execute(QueryParameters(**params))


def test_github_user_not_found_is_404(github):
    github({})
    res = _run(GitHubOSINTTool, username="nadie")
    assert len(res) == 1 and res[0].title == "Usuario no encontrado: nadie" and res[0].category == "GitHub"


@pytest.mark.parametrize("error,fragment", [
    (_http_error(403), "limitó"), (_http_error(429), "limitó"), (_http_error(500), "No se pudo contactar"),
    (OSError("sin red"), "sin conexión"),
])
def test_github_errors_are_not_reported_as_missing_user(github, error, fragment):
    github({"/users/jperez": error})
    res = _run(GitHubOSINTTool, username="jperez")
    assert len(res) == 1 and res[0].category == "Aviso" and "no encontrado" not in res[0].title.lower()
    assert fragment in res[0].snippet and "NO significa que el usuario no exista" in res[0].snippet


def test_github_existing_user_still_works(github):
    github({"/users/jperez/repos": [], "/users/jperez/events": [], "/users/jperez": {"login": "jperez", "name": "Juan Perez", "html_url": "https://github.com/jperez"}})
    res = _run(GitHubOSINTTool, username="jperez")
    assert res[0].category == "GitHub Profile" and res[0].extra_data["name"] == "Juan Perez"


def test_unavailable_hint_texts():
    assert "60 por hora" in github_unavailable_hint(403)
    assert "sin conexión" in github_unavailable_hint(0)


# ── UsernameVariants: puntuar por parecido y parar ante el límite ────────────

@pytest.mark.parametrize("target,profile,relevance,fragment", [
    ("Juan Perez", {"login": "jperez", "name": "Juan Pérez"}, 90, "coincide con el objetivo"),
    ("Juan Carlos Perez", {"login": "jperez", "name": "Juan Perez"}, 70, "en parte"),
    ("Juan Perez", {"login": "jperez", "name": "Juan Carlos Gomez"}, 40, "NO coincide"),   # solo comparte el nombre de pila
    ("Juan Perez", {"login": "jperez", "name": "Maria Lopez"}, 40, "NO coincide"),
    ("Juan Perez", {"login": "jperez", "name": None}, 55, "no tiene nombre"),
])
def test_score_github_match(target, profile, relevance, fragment):
    score, note = score_github_match(target, profile)
    assert score == relevance and fragment in note


def _variants(monkeypatch, names):
    monkeypatch.setattr(UsernameVariantsTool, "_generate_variants", lambda self, name, year=None, context="": names)


def test_variants_score_matches_by_name_not_always_90(github, monkeypatch):
    _variants(monkeypatch, ["jperez", "juanp", "perezj"])
    github({"/users/jperez": {"login": "jperez", "name": "Juan Perez", "public_repos": 3},
            "/users/juanp": {"login": "juanp", "name": "Otra Persona", "public_repos": 1}})
    res = _run(UsernameVariantsTool, target_name="Juan Perez")
    found = {r.title.split(": ")[1]: r.relevance_score for r in res if r.category == "GitHub Match"}
    assert found == {"jperez": 90, "juanp": 40}                      # "perezj" no existe: no aparece


def test_variants_stop_and_warn_when_github_limits(github, monkeypatch):
    _variants(monkeypatch, ["a1", "b2", "c3", "d4"])
    calls = []

    def fake(req, timeout=None, context=None):
        calls.append(req.full_url)
        if "/users/a1" in req.full_url:
            return _Resp({"login": "a1", "name": "Juan Perez"})
        raise _http_error(403)
    monkeypatch.setattr(ws.urllib.request, "urlopen", fake)
    monkeypatch.setattr(ws.time, "sleep", lambda s: None)
    res = _run(UsernameVariantsTool, target_name="Juan Perez")
    assert len(calls) == 2                                           # paró en el primer 403 (no siguió con c3 ni d4)
    warn = [r for r in res if r.category == "Aviso"][0]
    assert "Se revisaron 1 de 4 variantes" in warn.snippet and "NO significa" in warn.snippet
    assert any(r.category == "GitHub Match" for r in res)             # lo hallado antes del límite se conserva
