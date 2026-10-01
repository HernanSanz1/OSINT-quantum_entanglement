"""Mail Health: análisis de MX/SPF/DMARC/DKIM (DNS simulado, sin red)."""
import pytest

from osint_app.core.models import QueryParameters
from osint_app.tools.mail_health import (
    MailHealthTool, build_findings, count_spf_lookups, detect_provider, is_null_mx,
    parse_dmarc, parse_mx, parse_spf, spoofing_risk,
)


# ── funciones puras ──────────────────────────────────────────────────────────

def test_parse_mx_sorted_and_normalized():
    mx = parse_mx(["20 ALT1.aspmx.l.google.com.", "10 aspmx.l.google.com.", "basura"])
    assert [m["priority"] for m in mx] == [10, 20]
    assert mx[0]["host"] == "aspmx.l.google.com"


def test_null_mx():
    assert is_null_mx(parse_mx(["0 ."]))
    assert not is_null_mx(parse_mx(["10 mail.empresa.com."]))


@pytest.mark.parametrize("host,provider", [
    ("aspmx.l.google.com", "Google Workspace"),
    ("empresa-com.mail.protection.outlook.com", "Microsoft 365"),
    ("mx.zoho.com", "Zoho Mail"),
    ("mail.empresa.com", ""),
    ("evilgoogle.com", ""),            # sufijo parcial no cuenta
])
def test_detect_provider(host, provider):
    assert detect_provider([{"priority": 10, "host": host}]) == provider


def test_parse_spf():
    s = parse_spf("v=spf1 ip4:1.2.3.0/24 include:_spf.google.com mx -all")
    assert s["all"] == "-"
    assert s["includes"] == ["_spf.google.com"]
    assert not s["uses_ptr"]
    assert parse_spf("v=spf1 +all")["all"] == "+"
    assert parse_spf("v=spf1 a ~all")["all"] == "~"
    assert parse_spf("v=spf1 a")["all"] == ""
    assert parse_spf("v=spf1 redirect=_spf.empresa.com")["redirect"] == "_spf.empresa.com"
    assert parse_spf("v=spf1 ptr -all")["uses_ptr"]


def test_spf_lookup_counting_recursive():
    spfs = {"a.com": "v=spf1 include:b.com mx -all", "b.com": "v=spf1 include:c.com a -all", "c.com": "v=spf1 ip4:1.1.1.1 -all"}
    n = count_spf_lookups(parse_spf("v=spf1 include:a.com -all"), spfs.get)
    assert n == 5      # include a + (include b + mx) + (include c + a)


def test_spf_lookup_loop_is_bounded():
    loop = {"a.com": "v=spf1 include:a.com -all"}
    assert count_spf_lookups(parse_spf("v=spf1 include:a.com -all"), loop.get) > 10


def test_parse_dmarc():
    d = parse_dmarc("v=DMARC1; p=Reject; pct=50; rua=mailto:x@y.com")
    assert d == {"policy": "reject", "subdomain_policy": "", "pct": 50, "rua": "mailto:x@y.com"}
    assert parse_dmarc("v=DMARC1; pct=abc")["pct"] == 100


def _info(**over):
    base = {"mx": [{"priority": 10, "host": "mx.empresa.com"}], "null_mx": False, "spf_count": 1,
            "spf": parse_spf("v=spf1 -all"), "spf_lookups": 1,
            "dmarc": parse_dmarc("v=DMARC1; p=reject"), "dmarc_domain": "empresa.com"}
    base.update(over)
    return base


def _sev(info):
    return {s for s, _ in build_findings(info)}


def test_healthy_domain_has_no_findings():
    info = _info()
    assert build_findings(info) == [] and spoofing_risk(info) == "bajo"


def test_missing_spf_and_dmarc_is_high_risk():
    info = _info(spf_count=0, spf=None, dmarc=None)
    assert _sev(info) == {"alta"} and len(build_findings(info)) == 2
    assert spoofing_risk(info) == "alto"


def test_no_mail_domain_is_not_flagged():
    # un dominio sin MX no recibe correo: no se le exige SPF/DMARC
    info = _info(mx=[], spf_count=0, spf=None, dmarc=None)
    assert build_findings(info) == [] and spoofing_risk(info) == "n/a"
    null = _info(mx=[{"priority": 0, "host": ""}], null_mx=True, spf_count=0, spf=None, dmarc=None)
    assert build_findings(null) == []


@pytest.mark.parametrize("spf,expected", [
    ("v=spf1 +all", "alta"), ("v=spf1 ?all", "media"), ("v=spf1 a", "media"), ("v=spf1 ptr -all", "baja"),
])
def test_spf_weaknesses(spf, expected):
    assert _sev(_info(spf=parse_spf(spf))) == {expected}


def test_soft_fail_spf_is_acceptable():
    assert build_findings(_info(spf=parse_spf("v=spf1 a ~all"))) == []


def test_spf_too_many_lookups_and_duplicates():
    assert _sev(_info(spf_lookups=12)) == {"media"}
    assert _sev(_info(spf_count=2)) == {"alta"}


@pytest.mark.parametrize("dmarc,expected,risk", [
    ("v=DMARC1; p=none", {"media"}, "medio"),
    ("v=DMARC1; p=quarantine; pct=25", {"baja"}, "bajo"),
    ("v=DMARC1; rua=mailto:a@b.com", {"media"}, "medio"),
])
def test_dmarc_weaknesses(dmarc, expected, risk):
    info = _info(dmarc=parse_dmarc(dmarc))
    assert _sev(info) == expected and spoofing_risk(info) == risk


# ── herramienta con DNS simulado ─────────────────────────────────────────────

def _dns(records):
    """Devuelve un _query falso: {(nombre, tipo): [registros]}; ausente = sin registros."""
    return lambda self, name, rtype: records.get((name, rtype), [])


GOOD = {
    ("empresa.com", "MX"): ["10 aspmx.l.google.com."],
    ("empresa.com", "TXT"): ["google-site-verification=abc", "v=spf1 include:_spf.google.com -all"],
    ("_spf.google.com", "TXT"): ["v=spf1 ip4:1.2.3.0/24 -all"],
    ("_dmarc.empresa.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@empresa.com"],
    ("google._domainkey.empresa.com", "TXT"): ["v=DKIM1; k=rsa; p=MIGf"],
}


@pytest.fixture
def tool(monkeypatch):
    monkeypatch.setattr(MailHealthTool, "_nxdomain", lambda self, d: False)
    return MailHealthTool()


def test_execute_nonexistent_domain_returns_nothing(monkeypatch):
    monkeypatch.setattr(MailHealthTool, "_nxdomain", lambda self, d: True)
    monkeypatch.setattr(MailHealthTool, "_query", lambda self, n, t: [])
    assert MailHealthTool().execute(QueryParameters(domain="noexiste-zzq.com")) == []


def test_execute_healthy_domain(tool, monkeypatch):
    monkeypatch.setattr(MailHealthTool, "_query", _dns(GOOD))
    results = tool.execute(QueryParameters(domain="empresa.com"))
    assert len(results) == 1
    main = results[0]
    assert main.category == "Network" and main.source_tool == "Mail Health"
    for frag in ("Google Workspace", "-all", "p=reject", "google", "suplantación: bajo"):
        assert frag in main.snippet
    assert main.raw_data["spf"]["includes"] == ["_spf.google.com"]
    assert main.raw_data["dkim_selectors"] == ["google"]


def test_execute_unprotected_domain_emits_alerts(tool, monkeypatch):
    monkeypatch.setattr(MailHealthTool, "_query", _dns({("debil.com", "MX"): ["10 mail.debil.com."]}))
    results = tool.execute(QueryParameters(domain="debil.com"))
    alerts = [r for r in results if r.category == "Alerta"]
    assert len(alerts) == 2 and all(a.relevance_score == 88 for a in alerts)
    assert "suplantación: alto" in results[0].snippet


def test_execute_subdomain_inherits_parent_dmarc(tool, monkeypatch):
    recs = dict(GOOD)
    recs[("hr.empresa.com", "MX")] = ["10 aspmx.l.google.com."]
    recs[("hr.empresa.com", "TXT")] = ["v=spf1 -all"]
    monkeypatch.setattr(MailHealthTool, "_query", _dns(recs))
    main = tool.execute(QueryParameters(domain="hr.empresa.com"))[0]
    assert "heredado de empresa.com" in main.snippet
    assert main.raw_data["dmarc_domain"] == "empresa.com"


def test_execute_dns_down_returns_nothing(tool, monkeypatch):
    monkeypatch.setattr(MailHealthTool, "_query", lambda self, n, t: None)
    assert tool.execute(QueryParameters(domain="empresa.com")) == []


@pytest.mark.parametrize("bad", ["", "empresa", "a..com", "x.com; rm -rf /"])
def test_execute_invalid_domain_no_dns(tool, monkeypatch, bad):
    def boom(self, n, t):
        raise AssertionError("no debe consultar DNS")
    monkeypatch.setattr(MailHealthTool, "_query", boom)
    assert tool.execute(QueryParameters(domain=bad)) == []


def test_execute_caches(tool, monkeypatch):
    calls = {"n": 0}

    def counting(self, name, rtype):
        calls["n"] += 1
        return GOOD.get((name, rtype), [])
    monkeypatch.setattr(MailHealthTool, "_query", counting)
    first = tool.execute(QueryParameters(domain="empresa.com"))
    n = calls["n"]
    assert tool.execute(QueryParameters(domain="empresa.com")) == first and calls["n"] == n


def test_tool_registered_and_available():
    from osint_app.tools import build_tool_registry
    reg = build_tool_registry()
    assert "Mail Health" in reg and reg["Mail Health"].is_available
    assert reg["Mail Health"].requirements.mandatory == ["domain"]
