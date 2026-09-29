"""Herramienta Domain WHOIS (RDAP): parseo, alertas y ejecución (sin red)."""
from datetime import datetime, timezone

import pytest

from osint_app.core.models import QueryParameters
from osint_app.tools import domain_whois
from osint_app.tools.domain_whois import (
    DomainWhoisTool, build_alerts, candidate_domains, parse_rdap,
)

NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)


def _rdap(**over):
    data = {
        "ldhName": "EXAMPLE.COM",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "2007-10-09T18:20:50Z"},
            {"eventAction": "expiration", "eventDate": "2028-10-09T18:20:50Z"},
            {"eventAction": "last changed", "eventDate": "2026-09-07T09:22:52Z"},
        ],
        "nameservers": [{"ldhName": "NS2.EXAMPLE.NET"}, {"ldhName": "ns1.example.net."},
                        {"ldhName": "NS1.EXAMPLE.NET"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {"roles": ["registrar"],
             "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]]},
            {"roles": ["registrant"],
             "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"],
                                      ["org", {}, "text", "REDACTED FOR PRIVACY"]]]},
            {"roles": ["administrative"],
             "vcardArray": ["vcard", [["fn", {}, "text", "Ana Perez"],
                                      ["org", {}, "text", "ACME S.A."],
                                      ["email", {}, "text", "ana@acme.ec"],
                                      ["adr", {}, "text", ["", "", "Calle 1"]]]]},
        ],
    }
    data.update(over)
    return data


# ── parse_rdap ────────────────────────────────────────────────────────────────

def test_parse_basic_fields():
    info = parse_rdap(_rdap(), now=NOW)
    assert info["domain"] == "example.com"
    assert info["registrar"] == "MarkMonitor Inc."
    assert info["registered"] == "2007-10-09"
    assert info["expires"] == "2028-10-09"
    assert info["last_changed"] == "2026-09-07"
    assert info["dnssec"] is True
    assert info["status"] == ["client transfer prohibited"]
    assert info["age_days"] > 365 * 18
    assert info["days_to_expiry"] > 365


def test_nameservers_normalized_sorted_deduped():
    info = parse_rdap(_rdap(), now=NOW)
    assert info["nameservers"] == ["ns1.example.net", "ns2.example.net"]


def test_redacted_contacts_are_dropped_and_real_ones_kept():
    info = parse_rdap(_rdap(), now=NOW)
    assert [c["role"] for c in info["contacts"]] == ["administrative"]
    c = info["contacts"][0]
    assert c == {"role": "administrative", "name": "Ana Perez", "org": "ACME S.A.", "email": "ana@acme.ec"}
    assert "REDACTED" not in str(info["contacts"])


def test_parse_tolerates_missing_and_malformed_data():
    assert parse_rdap({}, now=NOW)["registrar"] == ""
    assert parse_rdap("no-soy-dict", now=NOW) == {}
    info = parse_rdap({"ldhName": "X.COM", "events": [{"eventAction": "registration", "eventDate": "basura"},
                                                       "roto", {"eventAction": "expiration"}],
                       "entities": ["roto", {"roles": None}], "nameservers": ["roto"]}, now=NOW)
    assert info["registered"] == "" and info["age_days"] is None
    assert info["dnssec"] is False and info["nameservers"] == []


def test_parse_without_secure_dns_is_false():
    data = _rdap()
    del data["secureDNS"]
    assert parse_rdap(data, now=NOW)["dnssec"] is False


# ── alertas ───────────────────────────────────────────────────────────────────

def test_alert_recently_registered():
    data = _rdap(events=[{"eventAction": "registration", "eventDate": "2026-09-20T00:00:00Z"}])
    alerts = build_alerts(parse_rdap(data, now=NOW))
    assert len(alerts) == 1 and "9 días" in alerts[0]


def test_alert_expiring_and_expired():
    soon = _rdap(events=[{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
                         {"eventAction": "expiration", "eventDate": "2026-10-10T00:00:00Z"}])
    assert "vence en 11 días" in build_alerts(parse_rdap(soon, now=NOW))[0]
    gone = _rdap(events=[{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
                         {"eventAction": "expiration", "eventDate": "2026-09-19T00:00:00Z"}])
    assert "VENCIDO hace 10 días" in build_alerts(parse_rdap(gone, now=NOW))[0]


def test_no_alerts_for_old_healthy_domain():
    assert build_alerts(parse_rdap(_rdap(), now=NOW)) == []


# ── candidate_domains ─────────────────────────────────────────────────────────

def test_candidate_domains_climbs_to_parent_without_bare_tld():
    assert candidate_domains("a.b.empresa.com") == ["a.b.empresa.com", "b.empresa.com", "empresa.com"]
    assert candidate_domains("empresa.com") == ["empresa.com"]


# ── execute() con HTTP simulado ───────────────────────────────────────────────

class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


@pytest.fixture
def tool(monkeypatch):
    t = DomainWhoisTool()
    monkeypatch.setattr(t._rate, "wait_if_needed", lambda: None)
    monkeypatch.setattr(domain_whois.time, "sleep", lambda _s: None)
    return t


def test_execute_maps_to_main_result_and_contacts(tool, monkeypatch):
    monkeypatch.setattr(domain_whois.requests, "get", lambda *a, **k: _Resp(200, _rdap()))
    results = tool.execute(QueryParameters(domain="example.com"))
    cats = [r.category for r in results]
    assert cats == ["Network", "Contacto"]
    main = results[0]
    assert main.title == "WHOIS: example.com" and main.source_tool == "Domain WHOIS"
    assert "MarkMonitor" in main.snippet and "DNSSEC: sí" in main.snippet
    assert main.raw_data["nameservers"] == ["ns1.example.net", "ns2.example.net"]


def test_execute_adds_alert_result_for_new_domain(tool, monkeypatch):
    fresh = _rdap(events=[{"eventAction": "registration",
                           "eventDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}])
    monkeypatch.setattr(domain_whois.requests, "get", lambda *a, **k: _Resp(200, fresh))
    results = tool.execute(QueryParameters(domain="nuevo.com"))
    assert "Alerta" in [r.category for r in results]


def test_execute_subdomain_falls_back_to_parent(tool, monkeypatch):
    calls = []

    def fake_get(url, **k):
        calls.append(url)
        return _Resp(400) if "mail.example.com" in url else _Resp(200, _rdap())
    monkeypatch.setattr(domain_whois.requests, "get", fake_get)
    results = tool.execute(QueryParameters(domain="mail.example.com"))
    assert results and results[0].title == "WHOIS: example.com"
    assert calls[0].endswith("/mail.example.com") and calls[-1].endswith("/example.com")


def test_execute_empty_stub_climbs_to_parent(tool, monkeypatch):
    stub = {"ldhName": "b.gob.ec", "notices": [{"title": "Prohibited String"}]}

    def fake_get(url, **k):
        return _Resp(200, stub) if url.endswith("/b.gob.ec") or url.endswith("/a.b.gob.ec") else _Resp(200, _rdap())
    monkeypatch.setattr(domain_whois.requests, "get", fake_get)
    results = tool.execute(QueryParameters(domain="a.b.gob.ec"))
    assert results and results[0].title == "WHOIS: example.com"


def test_execute_only_empty_stubs_returns_empty(tool, monkeypatch):
    monkeypatch.setattr(domain_whois.requests, "get", lambda *a, **k: _Resp(200, {"ldhName": "x.ec"}))
    assert tool.execute(QueryParameters(domain="x.gob.ec")) == []


def test_is_empty_record():
    assert domain_whois.is_empty_record(parse_rdap({"ldhName": "X.EC"}, now=NOW))
    assert not domain_whois.is_empty_record(parse_rdap(_rdap(), now=NOW))


def test_execute_parent_result_is_labelled_as_parent(tool, monkeypatch):
    def fake_get(url, **k):
        return _Resp(404) if "noexiste.example.com" in url else _Resp(200, _rdap())
    monkeypatch.setattr(domain_whois.requests, "get", fake_get)
    main = tool.execute(QueryParameters(domain="noexiste.example.com"))[0]
    assert main.raw_data["queried"] == "noexiste.example.com"
    assert "dominio padre" in main.snippet


def test_execute_exact_domain_has_no_parent_label(tool, monkeypatch):
    monkeypatch.setattr(domain_whois.requests, "get", lambda *a, **k: _Resp(200, _rdap()))
    main = tool.execute(QueryParameters(domain="example.com"))[0]
    assert "queried" not in main.raw_data and "padre" not in main.snippet


def test_execute_extension_without_rdap_is_reported_and_stops(tool, monkeypatch):
    calls = []

    class _NoRdap(_Resp):
        url = "https://rdap.org/domain/mit.edu"      # rdap.org no redirigió a ningún registro

    def fake_get(url, **k):
        calls.append(url)
        return _NoRdap(404)
    monkeypatch.setattr(domain_whois.requests, "get", fake_get)
    assert tool.execute(QueryParameters(domain="www.mit.edu")) == []
    assert len(calls) == 1                            # no subió al padre: no tiene sentido


def test_execute_nonexistent_domain_returns_empty(tool, monkeypatch):
    monkeypatch.setattr(domain_whois.requests, "get", lambda *a, **k: _Resp(404))
    assert tool.execute(QueryParameters(domain="noexiste-zzq.com")) == []


def test_execute_server_error_does_not_climb_and_retries(tool, monkeypatch):
    calls = {"n": 0}

    def always_503(*a, **k):
        calls["n"] += 1
        return _Resp(503)
    monkeypatch.setattr(domain_whois.requests, "get", always_503)
    assert tool.execute(QueryParameters(domain="a.b.example.com")) == []
    assert calls["n"] == domain_whois.MAX_RETRIES      # reintentó y NO subió al padre


def test_execute_network_error_returns_empty(tool, monkeypatch):
    def boom(*a, **k):
        raise domain_whois.requests.RequestException("timeout")
    monkeypatch.setattr(domain_whois.requests, "get", boom)
    assert tool.execute(QueryParameters(domain="example.com")) == []


def test_execute_invalid_json_returns_empty(tool, monkeypatch):
    monkeypatch.setattr(domain_whois.requests, "get", lambda *a, **k: _Resp(200, ValueError("x")))
    assert tool.execute(QueryParameters(domain="example.com")) == []


@pytest.mark.parametrize("bad", ["", "no es dominio", "1.2.3.4", "ex.com;rm -rf /", None])
def test_execute_rejects_invalid_domain_without_network(tool, monkeypatch, bad):
    called = {"n": 0}
    monkeypatch.setattr(domain_whois.requests, "get",
                        lambda *a, **k: called.__setitem__("n", 1) or _Resp())
    assert tool.execute(QueryParameters(domain=bad)) == []
    assert called["n"] == 0


def test_execute_uses_cache(tool, monkeypatch):
    calls = {"n": 0}

    def counting(*a, **k):
        calls["n"] += 1
        return _Resp(200, _rdap())
    monkeypatch.setattr(domain_whois.requests, "get", counting)
    first = tool.execute(QueryParameters(domain="example.com"))
    second = tool.execute(QueryParameters(domain="example.com"))
    assert first == second and calls["n"] == 1


def test_tool_registered_and_available():
    from osint_app.tools import build_tool_registry
    reg = build_tool_registry()
    assert "Domain WHOIS" in reg and reg["Domain WHOIS"].is_available
    assert reg["Domain WHOIS"].requirements.mandatory == ["domain"]
