"""Búsqueda encadenada migrada de profiler.py (4.6): descubrir usernames."""
from osint_app.core.models import SearchResult
from osint_app.profiler_engine import extract_usernames_from_results


def _sr(url):
    return SearchResult(title="", url=url, snippet="", source_tool="t", category="x")


def test_extract_github_linkedin_twitter():
    results = [
        _sr("https://github.com/octocat"),
        _sr("https://github.com/octocat/Spoon-Knife"),   # repo → mismo usuario
        _sr("https://www.linkedin.com/in/juan-perez"),
        _sr("https://twitter.com/jperez"),
        _sr("https://x.com/otro_user"),
    ]
    assert extract_usernames_from_results(results) == [
        "octocat", "juan-perez", "jperez", "otro_user",
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
