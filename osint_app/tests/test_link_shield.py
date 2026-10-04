"""Link Shield: análisis estático de URLs, seguimiento de acortadores y herramienta (sin red)."""
import pytest

from osint_app.core.models import QueryParameters
from osint_app.tools import file_metadata, link_shield as ls
from osint_app.tools.link_shield import (
    LinkShieldTool, analyze_url, edit_distance_le1, is_shortener, registrable, trace_redirects,
)


def texts(url):
    return " | ".join(t for _, t in analyze_url(url)["findings"])


# ── utilidades ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("host,dom", [
    ("www.empresa.com", "empresa.com"), ("a.b.c.empresa.com", "empresa.com"), ("empresa.com", "empresa.com"),
    ("login.banco.com.ec", "banco.com.ec"), ("www.bbc.co.uk", "bbc.co.uk"), ("x.sri.gob.ec", "sri.gob.ec"),
])
def test_registrable(host, dom):
    assert registrable(host) == dom


@pytest.mark.parametrize("a,b,ok", [
    ("google", "google", True), ("googl", "google", True), ("gooogle", "google", True), ("goagle", "google", True),
    ("gogle", "google", True), ("gxxgle", "google", False), ("goo", "google", False),
])
def test_edit_distance_le1(a, b, ok):
    assert edit_distance_le1(a, b) is ok


def test_is_shortener():
    assert is_shortener("https://bit.ly/abc") and is_shortener("tinyurl.com/x") and is_shortener("http://www.t.co/x")
    assert not is_shortener("https://empresa.com/bit.ly") and not is_shortener("https://notbit.ly.evil.com/")


# ── análisis estático ────────────────────────────────────────────────────────

LEVEL = {"bajo": 0, "medio": 1, "alto": 2}


@pytest.mark.parametrize("url", [
    "https://www.google.com/", "https://accounts.google.com/signin", "https://www.paypal.com/signin",
    "https://www.bancopichincha.com/", "https://amazon.es/", "https://www.google.de/", "https://mercadolibre.com.ar/",
    "https://googleapis.com/x", "https://media-amazon.com/", "https://www.sri.gob.ec/", "https://github.com/user/repo",
    "https://es.wikipedia.org/wiki/Quito", "https://docs.python.org/3/",
])
def test_legitimate_urls_are_low_risk(url):
    assert analyze_url(url)["level"] == "bajo", texts(url)


@pytest.mark.parametrize("url,fragment", [
    ("https://user@evil.com@good.com/", "usuario antes de la arroba"),
    ("http://3232235777/", "número único"),
    ("http://0xC0A80001/", "hexadecimal"),
    ("https://paypal-secure-login.com/a", "paypal"),
    ("https://www.paypal.com.evil.top/signin", "paypal"),
    ("https://paypa1.com/", "paypal"),
    ("https://secure.microsoft.account-verify.net/", "microsoft"),
    ("https://xn--pypal-4ve.com/", "otro alfabeto"),
    ("https://аpple.com/", "otro alfabeto"),
    ("https://xn--80ak6aa92e.com/", "otro alfabeto"),
])
def test_high_risk_patterns(url, fragment):
    a = analyze_url(url)
    assert a["level"] == "alto" and fragment in texts(url), texts(url)


@pytest.mark.parametrize("url,fragment", [
    ("https://mi-pagina.pages.dev/", "pages.dev"),
    ("http://45.12.3.4/login.php", "dirección IP"),
    ("https://robiox.com.gr/users/1", "roblox"),
    ("https://nuevo.xyz/", ".xyz"),
    ("https://sitio.com/descarga/setup.exe", ".exe"),
    ("https://sitio.com/a?uid=victima@correo.com", "correo"),
    ("https://xn--l3ca4b6dsc1b.com/", "punycode"),
    ("https://paypal.net/", "otra extensión"),
])
def test_medium_risk_patterns(url, fragment):
    a = analyze_url(url)
    assert a["level"] == "medio" and fragment in texts(url), texts(url)


def test_low_signals_do_not_escalate_alone():
    a = analyze_url("http://sitio.com/")
    assert a["level"] == "bajo" and a["score"] == 8 and "HTTPS" in texts("http://sitio.com/")
    assert analyze_url("http://sitio.com:8080/")["level"] == "bajo"


def test_free_hosting_root_page_and_official_are_not_brand_flags():
    assert "tiktok" not in texts("https://tiktokv.com/")
    assert "paypal" not in texts("https://www.paypal.com/")
    assert "microsoft" not in texts("https://login.microsoftonline.com/")


def test_scheme_missing_is_analyzed_and_garbage_is_safe():
    assert analyze_url("paypal-login-seguro.com/x")["level"] == "alto"
    for bad in ["", "   ", "http://", "http://[::1", "javascript:alert(1)"]:
        a = analyze_url(bad)
        assert isinstance(a["findings"], list) and a["score"] <= 100


def test_score_is_capped_and_level_thresholds():
    a = analyze_url("http://user@paypal-secure-login-verify.top:8080/login/update/account.exe?uid=a@b.com")
    assert a["score"] == 100 and a["level"] == "alto"


# ── seguimiento de acortadores ───────────────────────────────────────────────

class _Resp:
    def __init__(self, status=200, location=None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def net(monkeypatch):
    monkeypatch.setattr(file_metadata, "host_is_public", lambda h: not h.startswith("interno"))
    calls = []

    def install(*responses):
        it = iter(responses)

        def fake_get(url, **kw):
            calls.append((url, kw.get("allow_redirects"), kw.get("stream")))
            item = next(it)
            if isinstance(item, Exception):
                raise item
            return item
        monkeypatch.setattr(ls.requests, "get", fake_get)
        return calls
    return install


def test_trace_follows_chain_without_following_automatically(net):
    calls = net(_Resp(301, "https://mid.com/x"), _Resp(302, "/final"), _Resp(200))
    chain, err = trace_redirects("https://bit.ly/a")
    assert chain == ["https://bit.ly/a", "https://mid.com/x", "https://mid.com/final"] and err == ""
    assert all(c[1] is False and c[2] is True for c in calls)        # sin allow_redirects y sin descargar cuerpo


def test_trace_blocks_private_destination_and_reports_errors(net):
    calls = net(_Resp(302, "http://interno.local/admin"))
    chain, err = trace_redirects("https://bit.ly/a")
    assert chain[-1] == "http://interno.local/admin" and "no permitido" in err and len(calls) == 1
    net(_Resp(404))
    assert trace_redirects("https://bit.ly/a")[1] == "HTTP 404"
    net(*[_Resp(302, "https://bit.ly/b")] * 8)
    assert "demasiadas" in trace_redirects("https://bit.ly/a")[1]
    import requests
    net(requests.ConnectionError("x"))
    assert "error de red" in trace_redirects("https://bit.ly/a")[1]


# ── herramienta ──────────────────────────────────────────────────────────────

@pytest.fixture
def tool(monkeypatch):
    t = LinkShieldTool()
    monkeypatch.setattr(t, "_domain_age", lambda host: None)         # sin RDAP salvo en los tests de antigüedad
    monkeypatch.setattr("osint_app.tools.ip_reputation.feed_hits", lambda urls: [])   # listas de amenazas: verificadas en real
    monkeypatch.setattr(t._rate, "wait_if_needed", lambda: None)
    return t


def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("un enlace que no es acortador no debe visitarse")
    monkeypatch.setattr(ls.requests, "get", boom)


def test_execute_static_never_touches_network(tool, monkeypatch):
    no_network(monkeypatch)
    results = tool.execute(QueryParameters(url="https://paypal-secure-login.com/a"))
    main, alerts = results[0], results[1:]
    assert main.category == "Enlace" and "Riesgo alto" in main.snippet and main.relevance_score == 90
    assert alerts and all(a.category == "Alerta" for a in alerts)
    assert alerts[0].relevance_score == 88                      # primero la más grave
    assert main.raw_data["level"] == "alto" and main.raw_data["domain"] == "paypal-secure-login.com"


def test_execute_clean_url_says_so(tool, monkeypatch):
    no_network(monkeypatch)
    results = tool.execute(QueryParameters(url="https://www.python.org/downloads/"))
    assert len(results) == 1 and "Riesgo bajo" in results[0].snippet and "Sin señales" in results[0].snippet


def test_execute_shortener_analyzes_final_destination(tool, net):
    net(_Resp(301, "https://paypal-verify-cuenta.top/login"), _Resp(200))
    results = tool.execute(QueryParameters(url="https://bit.ly/abc"))
    main = results[0]
    assert "Destino final: https://paypal-verify-cuenta.top/login" in main.snippet
    assert main.raw_data["chain"][-1] == "https://paypal-verify-cuenta.top/login" and main.raw_data["level"] == "alto"
    assert any("Destino final:" in a.snippet for a in results[1:])
    assert not any("Acortador" in a.snippet and "Destino final" in a.snippet for a in results[1:])


def test_execute_shortener_trace_failure_still_returns_static(tool, net):
    net(_Resp(404))
    main = tool.execute(QueryParameters(url="https://bit.ly/abc"))[0]
    assert "No se pudo seguir el acortador: HTTP 404" in main.snippet and main.raw_data["chain"] == ["https://bit.ly/abc"]


def test_execute_invalid_input_and_cache(tool, monkeypatch):
    no_network(monkeypatch)
    for bad in ["", "dos palabras", "http://"]:
        assert tool.execute(QueryParameters(url=bad)) == []
    first = tool.execute(QueryParameters(url="https://nuevo.xyz/"))
    assert tool.execute(QueryParameters(url="https://nuevo.xyz/")) == first


def test_tool_registered_and_available():
    from osint_app.tools import build_tool_registry
    reg = build_tool_registry()
    assert "Link Shield" in reg and reg["Link Shield"].is_available
    assert reg["Link Shield"].requirements.mandatory == ["url"]


# ── antigüedad del dominio (RDAP) ────────────────────────────────────────────

@pytest.mark.parametrize("host,expected", [
    ("nuevo-sitio.com", True), ("www.empresa.com.ec", True), ("a.b.empresa.xyz", True),
    ("45.12.3.4", False), ("3232235777", False), ("bit.ly", False), ("mi-pagina.pages.dev", False),
    ("usuario.github.io", False), ("accounts.google.com", False), ("www.bancopichincha.com", False), ("", False),
])
def test_should_check_age(host, expected):
    assert ls.should_check_age(host) is expected


@pytest.mark.parametrize("days,sev", [
    (0, "alta"), (ls.NEW_DOMAIN_DAYS - 1, "alta"), (ls.NEW_DOMAIN_DAYS, "media"),
    (ls.YOUNG_DOMAIN_DAYS - 1, "media"), (ls.YOUNG_DOMAIN_DAYS, None), (4000, None), (None, None), (-5, None),
])
def test_age_findings(days, sev):
    found = ls.age_findings(days)
    assert (found[0][0] if found else None) == sev


def test_new_domain_makes_clean_looking_link_high_risk(tool, monkeypatch):
    monkeypatch.setattr(tool, "_domain_age", lambda host: {"age_days": 3, "registered": "2026-09-28", "registrar": "X"})
    results = tool.execute(QueryParameters(url="https://webwds.com/"))
    main = results[0]
    assert main.raw_data["level"] == "alto" and main.raw_data["domain_age"]["age_days"] == 3
    assert "registrado el 2026-09-28, hace 3 días" in main.snippet
    assert any("solo 3 días" in a.snippet for a in results[1:])


def test_old_domain_adds_no_alert_and_is_mentioned(tool, monkeypatch):
    monkeypatch.setattr(tool, "_domain_age", lambda host: {"age_days": 9000, "registered": "1995-03-27", "registrar": "Gandi"})
    main = tool.execute(QueryParameters(url="https://www.python.org/"))[0]
    assert main.raw_data["level"] == "bajo" and "ni en la antigüedad" in main.snippet and len(tool.execute(QueryParameters(url="https://www.python.org/"))) == 1


def test_age_unknown_changes_nothing(tool):
    main = tool.execute(QueryParameters(url="https://www.python.org/"))[0]
    assert main.raw_data["domain_age"] is None and "ni en la antigüedad" not in main.snippet


def test_age_of_shortener_target_uses_final_host(tool, net, monkeypatch):
    asked = []
    monkeypatch.setattr(tool, "_domain_age", lambda host: asked.append(host))
    net(_Resp(301, "https://destino-raro.com/x"), _Resp(200))
    tool.execute(QueryParameters(url="https://bit.ly/abc"))
    assert asked == ["destino-raro.com"]


def test_domain_age_uses_whois_lookup_and_survives_failures():
    t = LinkShieldTool()
    t._whois.lookup = lambda dom: ({"age_days": 12, "registered": "2026-09-19", "registrar": "R"}, dom, 200)
    assert t._domain_age("www.sitio.com") == {"age_days": 12, "registered": "2026-09-19", "registrar": "R"}
    t._whois.lookup = lambda dom: (None, dom, 404)
    assert t._domain_age("sitio.com") is None
    t._whois.lookup = lambda dom: ({"age_days": None}, dom, 200)
    assert t._domain_age("sitio.com") is None

    def boom(dom):
        raise RuntimeError("RDAP caído")
    t._whois.lookup = boom
    assert t._domain_age("sitio.com") is None                       # no rompe el análisis estático
    t._whois.lookup = lambda dom: pytest.fail("no debe consultarse")
    assert t._domain_age("pages.dev") is None and t._domain_age("1.2.3.4") is None


def test_extension_without_rdap_is_reported_not_hidden(tool, monkeypatch):
    monkeypatch.setattr(tool, "_domain_age", lambda host: {"age_days": None, "note": "antigüedad no disponible: la extensión .io no publica datos RDAP"})
    main = tool.execute(QueryParameters(url="https://www.python.org/"))[0]
    assert "Antigüedad no disponible: la extensión .io no publica datos RDAP" in main.snippet
    assert "ni en la antigüedad" not in main.snippet and main.raw_data["level"] == "bajo"


def test_domain_age_flags_no_rdap_extension():
    t = LinkShieldTool()
    t._whois.lookup = lambda dom: (None, dom, "no-rdap")
    assert "no publica datos RDAP" in t._domain_age("sitio.io")["note"] and t._domain_age("sitio.io")["age_days"] is None
