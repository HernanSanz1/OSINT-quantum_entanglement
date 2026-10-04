"""Detección de tecnologías (3): firmas puras y ejecución (sin red)."""
import pytest

from osint_app.core.models import QueryParameters
from osint_app.tools.tech_detect import TechDetectTool, detect_technologies


# ── detect_technologies (función pura) ────────────────────────────────────────

def test_detect_server_and_cms_from_headers_and_html():
    headers = {"Server": "nginx", "X-Powered-By": "PHP/8.1"}
    html = '<meta name="generator" content="WordPress 6.4"> ... wp-content/...'
    techs = detect_technologies(headers, html)
    assert "nginx" in techs and "PHP" in techs and "WordPress" in techs


def test_detect_dedups_wordpress_signals():
    html = '<meta name="generator" content="WordPress"> wp-content wp-includes'
    assert detect_technologies({}, html).count("WordPress") == 1


def test_detect_security_vendors_align_with_cti():
    # F5, Imperva, Fortinet, Cloudflare → nombres que cruzan con vendors del CTI
    assert "F5 BIG-IP" in detect_technologies({"Set-Cookie": "BIGipServer~x=1"})
    assert "Imperva" in detect_technologies({"Set-Cookie": "visid_incap_1=abc"})
    assert "Fortinet" in detect_technologies({"X-FortiGate": "1"})
    assert "Cloudflare" in detect_technologies({"Server": "cloudflare", "CF-Ray": "x"})


def test_detect_iis_and_aspnet():
    techs = detect_technologies({"Server": "Microsoft-IIS/10.0", "X-AspNet-Version": "4.0"})
    assert "Microsoft IIS" in techs and "Microsoft ASP.NET" in techs


def test_detect_empty_when_no_signatures():
    assert detect_technologies({"Server": "cosa-rara"}, "<html></html>") == []


def test_detect_case_insensitive():
    assert "nginx" in detect_technologies({"SERVER": "NGINX/1.25"})


# ── TechDetectTool.execute (HTTP simulado) ────────────────────────────────────

@pytest.fixture
def tool():
    return TechDetectTool()


def test_execute_maps_techs_to_results(tool, monkeypatch):
    def fake_fetch(_self, _target):
        return {"Server": "nginx"}, '<meta name="generator" content="Drupal 10">'
    monkeypatch.setattr(TechDetectTool, "_fetch", fake_fetch)

    results = tool.execute(QueryParameters(domain="example.com"))
    titles = {r.title for r in results}
    assert titles == {"nginx", "Drupal 10"}                     # la versión expuesta se muestra (dato útil en CTI)
    assert all(r.category == "Technology" for r in results)
    assert results[0].raw_data["technology"] in {"nginx", "Drupal"}


def test_execute_rejects_invalid_domain(tool, monkeypatch):
    monkeypatch.setattr(TechDetectTool, "_fetch",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no debe llamar")))
    assert tool.execute(QueryParameters(domain="no es dominio")) == []
    assert tool.execute(QueryParameters(domain="")) == []


def test_execute_handles_unreachable_site(tool, monkeypatch):
    monkeypatch.setattr(TechDetectTool, "_fetch", lambda *a, **k: (None, None))
    assert tool.execute(QueryParameters(domain="example.com")) == []


def test_execute_strips_scheme_from_url(tool, monkeypatch):
    seen = {}
    def fake_fetch(_self, target):
        seen["target"] = target
        return {"Server": "apache"}, ""
    monkeypatch.setattr(TechDetectTool, "_fetch", fake_fetch)
    tool.execute(QueryParameters(url="https://example.com/path"))
    assert seen["target"].startswith("example.com")


def test_tool_available_without_keys():
    t = TechDetectTool()
    assert t.check_available() is True and t.requires_api_key is False
