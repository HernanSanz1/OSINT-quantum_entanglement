"""Herramienta crt.sh: parseo de subdominios y ejecución (sin red)."""
import pytest

from osint_app.core.models import QueryParameters
from osint_app.tools import crtsh
from osint_app.tools.crtsh import CrtShTool, parse_crtsh


# ── parse_crtsh (función pura) ────────────────────────────────────────────────

def test_parse_extracts_and_dedups():
    entries = [
        {"name_value": "www.example.com\nmail.example.com", "common_name": "example.com"},
        {"name_value": "*.example.com", "common_name": "www.example.com"},   # comodín + dup
        {"name_value": "vpn.example.com", "common_name": ""},
    ]
    subs = parse_crtsh(entries, "example.com")
    assert subs == ["example.com", "mail.example.com", "vpn.example.com", "www.example.com"]


def test_parse_filters_out_of_scope():
    # example.com.evil.com NO pertenece a example.com (acaba en .evil.com)
    entries = [{"name_value": "a.example.com\nintruso.otrodominio.com\nexample.com.evil.com"}]
    assert parse_crtsh(entries, "example.com") == ["a.example.com"]


def test_parse_strips_wildcards_and_trailing_dot():
    entries = [{"name_value": "*.sub.example.com\nfoo.example.com."}]
    assert parse_crtsh(entries, "example.com") == ["foo.example.com", "sub.example.com"]


def test_parse_empty_or_bad_input():
    assert parse_crtsh([], "example.com") == []
    assert parse_crtsh([{"name_value": "a.example.com"}], "") == []
    assert parse_crtsh(["no-soy-dict"], "example.com") == []


def test_parse_respects_cap(monkeypatch):
    monkeypatch.setattr(crtsh, "MAX_SUBDOMAINS", 3)
    entries = [{"name_value": "\n".join(f"s{i}.example.com" for i in range(10))}]
    assert len(parse_crtsh(entries, "example.com")) == 3


# ── execute() con HTTP simulado ───────────────────────────────────────────────

class _FakeResp:
    def __init__(self, status=200, payload=None, raise_exc=None):
        self.status_code = status
        self._payload = payload if payload is not None else []
        self._raise = raise_exc

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


@pytest.fixture
def tool(monkeypatch):
    t = CrtShTool()
    monkeypatch.setattr(t._rate, "wait_if_needed", lambda: None)   # sin esperas
    monkeypatch.setattr(crtsh.time, "sleep", lambda _s: None)      # sin backoff real
    return t


def test_execute_maps_subdomains_to_results(tool, monkeypatch):
    payload = [{"name_value": "www.example.com\nmail.example.com", "common_name": "example.com"}]
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: _FakeResp(200, payload))

    results = tool.execute(QueryParameters(domain="example.com"))

    titles = sorted(r.title for r in results)
    assert titles == ["example.com", "mail.example.com", "www.example.com"]
    assert all(r.source_tool == "crt.sh" and r.category == "Subdominio" for r in results)
    assert results[0].url.startswith("https://")


def test_execute_rejects_invalid_domain(tool, monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(crtsh.requests, "get",
                        lambda *a, **k: called.__setitem__("n", 1) or _FakeResp())
    assert tool.execute(QueryParameters(domain="no es un dominio")) == []
    assert tool.execute(QueryParameters(domain="")) == []
    assert called["n"] == 0   # ni siquiera intenta la petición


def test_execute_handles_network_error(tool, monkeypatch):
    def boom(*a, **k):
        raise crtsh.requests.RequestException("timeout")
    monkeypatch.setattr(crtsh.requests, "get", boom)
    assert tool.execute(QueryParameters(domain="example.com")) == []


def test_execute_gives_up_after_persistent_502(tool, monkeypatch):
    calls = {"n": 0}
    def always_502(*a, **k):
        calls["n"] += 1
        return _FakeResp(status=502)
    monkeypatch.setattr(crtsh.requests, "get", always_502)
    assert tool.execute(QueryParameters(domain="example.com")) == []
    assert calls["n"] == crtsh.MAX_RETRIES        # reintentó, no se rindió al primer 502


def test_execute_retries_502_then_succeeds(tool, monkeypatch):
    # 502, 502, 200 → debe acabar devolviendo resultados (crt.sh es intermitente)
    seq = [_FakeResp(502), _FakeResp(502),
           _FakeResp(200, [{"name_value": "www.example.com"}])]
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: seq.pop(0))
    results = tool.execute(QueryParameters(domain="example.com"))
    assert [r.title for r in results] == ["www.example.com"]


def test_execute_non_retry_http_error_returns_empty(tool, monkeypatch):
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: _FakeResp(status=403))
    assert tool.execute(QueryParameters(domain="example.com")) == []


def test_execute_uses_cache(tool, monkeypatch):
    payload = [{"name_value": "www.example.com"}]
    calls = {"n": 0}

    def counting_get(*a, **k):
        calls["n"] += 1
        return _FakeResp(200, payload)
    monkeypatch.setattr(crtsh.requests, "get", counting_get)

    tool.execute(QueryParameters(domain="example.com"))
    tool.execute(QueryParameters(domain="example.com"))   # 2ª vez: desde caché
    assert calls["n"] == 1


def test_tool_is_available_without_keys():
    t = CrtShTool()
    assert t.check_available() is True
    assert t.requires_api_key is False
