"""Wayback, Hunter y herramientas de red (dnspython, ipwhois, CENSYS, TheHarvester, phonenumbers): sin red ni binarios."""
import logging
import subprocess
import sys
from types import SimpleNamespace

import pytest
import requests

from osint_app.core.models import QueryParameters
from osint_app.tools import hunter, network_tools, wayback
from osint_app.tools.hunter import HunterTool
from osint_app.tools.network_tools import (
    CensysTool, DnspythonTool, IpWhoisTool, PhoneNumbersTool, TheHarvesterTool,
)
from osint_app.tools.wayback import WaybackMachineTool


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status_code, self._payload = status, payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def progress_of(tool):
    seen = []
    tool._progress_cb = seen.append
    return seen


# ── Wayback Machine ──────────────────────────────────────────────────────────

CDX = [["original", "timestamp", "mimetype"],
       ["http://empresa.com/", "20200101120000", "text/html"],
       ["http://empresa.com/api/v1/users.json", "20210315093000", "application/json"],
       ["http://empresa.com/backup/clientes.sql", "20190607081500", "text/plain"],
       ["http://empresa.com/logo.png", "20180102", "image/png"],
       ["http://empresa.com/informe.PDF?download=1", "20221111111111", "application/pdf"]]


@pytest.fixture
def wb(monkeypatch):
    monkeypatch.setattr(wayback.time, "sleep", lambda s: None)
    sent = {}

    def install(response):
        def fake_get(url, params=None, headers=None, timeout=None):
            sent.update(url=url, params=params, headers=headers, timeout=timeout)
            if isinstance(response, Exception):
                raise response
            return response
        monkeypatch.setattr(wayback.requests, "get", fake_get)
        return sent
    return install


def test_wayback_classifies_and_sorts_snapshots(wb):
    wb(FakeResponse(200, CDX))
    results = WaybackMachineTool().execute(QueryParameters(domain="empresa.com"))
    assert [r.category for r in results] == ["Archivo Histórico Expuesto"] * 2 + ["API Endpoint", "Endpoint Histórico", "Página Web Archivada"]
    assert [r.relevance_score for r in results] == [90, 90, 75, 50, 40]                        # los archivos sensibles primero
    by_url = {r.raw_data["original"]: r for r in results}
    sql = by_url["http://empresa.com/backup/clientes.sql"]
    assert sql.category == "Archivo Histórico Expuesto" and sql.relevance_score == 90
    assert sql.url == "https://web.archive.org/web/20190607081500/http://empresa.com/backup/clientes.sql"
    assert "2019-06-07" in sql.title and sql.snippet == "Tipo: text/plain | Captura del 2019-06-07"
    assert by_url["http://empresa.com/informe.PDF?download=1"].category == "Archivo Histórico Expuesto"      # extensión sin importar mayúsculas ni parámetros
    assert by_url["http://empresa.com/api/v1/users.json"].category == "API Endpoint"
    assert by_url["http://empresa.com/"].category == "Página Web Archivada"
    assert by_url["http://empresa.com/logo.png"].category == "Endpoint Histórico" and "2018-01-02" in by_url["http://empresa.com/logo.png"].title
    assert [r.relevance_score for r in results] == sorted((r.relevance_score for r in results), reverse=True)


def test_wayback_uses_https_and_expands_a_domain(wb):
    sent = wb(FakeResponse(200, CDX))
    WaybackMachineTool().execute(QueryParameters(domain="empresa.com"))
    assert sent["url"].startswith("https://")                                                  # antes: http en claro, con el objetivo investigado
    assert sent["params"]["url"] == "empresa.com/*" and sent["params"]["limit"] == 300 and sent["params"]["filter"] == "statuscode:200"
    assert sent["timeout"] == 30 and "Mozilla" in sent["headers"]["User-Agent"]


def test_wayback_url_target_is_host_plus_path_and_beats_the_domain(wb):
    sent = wb(FakeResponse(200, CDX))
    WaybackMachineTool().execute(QueryParameters(url="https://empresa.com/docs/manual.pdf?x=1", domain="otra.com"))
    assert sent["params"]["url"] == "empresa.com/docs/manual.pdf"                              # un archivo concreto no se expande con /*
    WaybackMachineTool().execute(QueryParameters(url="empresa.com/zona"))
    assert sent["params"]["url"] == "empresa.com/zona"                                         # sin esquema también se entiende


def test_wayback_without_target_asks_nothing(wb):
    sent = wb(FakeResponse(200, CDX))
    tool = WaybackMachineTool()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters()) == [] and sent == {} and "No se proporcionó" in seen[0]


@pytest.mark.parametrize("response,message", [
    (FakeResponse(503), "Código 503"),
    (FakeResponse(200, ValueError("no es json")), "no JSON"),
    (FakeResponse(200, []), "No se encontraron snapshots"),
    (FakeResponse(200, [["original", "timestamp", "mimetype"]]), "No se encontraron snapshots"),        # solo la cabecera
    (FakeResponse(200, {"error": "rate limited"}), "formato inesperado"),                              # antes: fallo interno mudo
    (FakeResponse(200, ["texto", "suelto"]), "formato inesperado"),
    (requests.Timeout("lento"), "Timeout"),
    (requests.ConnectionError("sin red"), "Error de red"),
    (RuntimeError("fallo raro"), "error inesperado (RuntimeError)"),                                   # antes: sin ningún aviso
])
def test_wayback_failures_return_nothing_and_say_why(wb, response, message):
    wb(response)
    tool = WaybackMachineTool()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(domain="empresa.com")) == []
    assert any(message in m for m in seen), seen


def test_wayback_can_be_cancelled_midway(wb):
    wb(FakeResponse(200, CDX))
    tool = WaybackMachineTool()
    tool._is_cancelled = True
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(domain="empresa.com")) == [] and any("cancelada" in m for m in seen)


# ── Hunter.io ────────────────────────────────────────────────────────────────

SECRET = "hunter-clave-secreta-123"


@pytest.fixture
def hu(monkeypatch):
    tool = HunterTool()
    tool.api_key = SECRET
    calls = []

    def install(*responses):
        queue = list(responses)

        def fake_get(url, params=None, headers=None, timeout=None):
            calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {})})
            item = queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        monkeypatch.setattr(hunter.requests, "get", fake_get)
        return calls
    return tool, install


def test_hunter_without_key_does_nothing(hu):
    tool, install = hu
    tool.api_key = ""
    calls = install()
    assert tool.execute(QueryParameters(domain="empresa.com")) == [] and calls == []


def test_hunter_key_goes_in_a_header_never_in_the_url(hu):
    tool, install = hu
    calls = install(FakeResponse(200, {"data": {"emails": []}}))
    tool.execute(QueryParameters(domain="empresa.com"))
    assert calls[0]["headers"] == {"X-API-KEY": SECRET}
    assert "api_key" not in calls[0]["params"] and SECRET not in calls[0]["url"] and calls[0]["params"]["domain"] == "empresa.com"


def test_hunter_network_error_does_not_leak_the_key_in_logs_or_progress(hu, caplog):
    tool, install = hu
    install(requests.ConnectionError(f"Max retries exceeded with url: /v2/domain-search?domain=x&api_key={SECRET}"))
    seen = progress_of(tool)
    with caplog.at_level(logging.DEBUG):
        assert tool.execute(QueryParameters(domain="empresa.com")) == []
    assert SECRET not in caplog.text and SECRET not in " ".join(seen) and any("error de red (ConnectionError)" in m for m in seen)


@pytest.mark.parametrize("status,reason", [(401, "la clave de API no es válida"), (429, "se agotó el límite"), (403, "no tiene permiso"),
                                           (500, "respondió con un error")])
def test_hunter_http_errors_are_explained(hu, status, reason):
    tool, install = hu
    install(FakeResponse(status))
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(domain="empresa.com")) == []
    assert any(reason in m and f"HTTP {status}" in m for m in seen)                                  # antes: [] sin explicación


def test_hunter_invalid_json_is_reported(hu):
    tool, install = hu
    install(FakeResponse(200, ValueError("x")))
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(domain="empresa.com")) == [] and any("no es JSON" in m for m in seen)


def test_hunter_domain_search_results_and_null_fields(hu):
    tool, install = hu
    install(FakeResponse(200, {"data": {"emails": [
        {"value": "juan@empresa.com", "confidence": 91, "first_name": "Juan", "last_name": "Pérez", "position": "CTO"},
        {"value": "info@empresa.com", "confidence": None, "first_name": None, "last_name": None, "position": None},     # antes: TypeError
    ]}}))
    results = tool.execute(QueryParameters(domain="empresa.com"))
    assert [r.relevance_score for r in results] == [91, 0] and results[0].title == "Juan Pérez — CTO"
    assert results[0].snippet == "Email: juan@empresa.com  Confianza: 91%" and results[0].category == "Email"
    assert results[0].url == "https://hunter.io/verifier/juan@empresa.com" and results[0].raw_data["position"] == "CTO"


@pytest.mark.parametrize("payload", [{}, {"data": None}, {"data": {"emails": None}}])
def test_hunter_tolerates_empty_or_null_data(hu, payload):
    tool, install = hu
    install(FakeResponse(200, payload))
    assert tool.execute(QueryParameters(domain="empresa.com")) == []                                # antes: AttributeError con "data": null


@pytest.mark.parametrize("name,first,last", [
    ("Juan Pérez", "Juan", "Pérez"),
    ("Juan Carlos Pérez", "Juan", "Carlos Pérez"),
    ("Juan Carlos Pérez Mora", "Juan", "Pérez"),                      # N1 N2 A1 A2: el apellido es el 3.º (antes: "Carlos Pérez Mora")
    ("Madonna", "Madonna", ""),
])
def test_hunter_email_finder_splits_hispanic_names(hu, name, first, last):
    tool, install = hu
    calls = install(FakeResponse(200, {"data": {"value": "j@empresa.com", "score": 88}}))
    results = tool.execute(QueryParameters(target_name=name, company="Empresa"))
    assert calls[0]["params"] == {"first_name": first, "last_name": last, "company": "Empresa"}
    assert results[0].relevance_score == 88 and "j@empresa.com" in results[0].snippet


def test_hunter_runs_every_applicable_search_and_verifies_emails(hu):
    tool, install = hu
    calls = install(FakeResponse(200, {"data": {"emails": []}}),
                    FakeResponse(200, {"data": {"value": "j@e.com", "score": None}}),
                    FakeResponse(200, {"data": {"status": "valid", "result": "deliverable", "score": 95}}))
    results = tool.execute(QueryParameters(domain="e.com", target_name="Juan Pérez", company="E", email="j@e.com"))
    assert [c["url"].rsplit("/", 1)[-1] for c in calls] == ["domain-search", "email-finder", "email-verifier"]
    assert [r.category for r in results] == ["Email", "Email Verification"] and results[0].relevance_score == 0     # score None: ya no falla
    assert "valid" in results[1].snippet and results[1].relevance_score == 95
    assert HunterTool().execute(QueryParameters(target_name="Solo Nombre")) == []                               # sin clave, nada


def test_hunter_name_without_company_is_not_searched(hu):
    tool, install = hu
    calls = install()
    assert tool.execute(QueryParameters(target_name="Juan Pérez")) == [] and calls == []
    assert tool._find_email("   ", "Empresa") == []


# ── dnspython ────────────────────────────────────────────────────────────────

@pytest.fixture
def dns_records(monkeypatch):
    import dns.resolver

    def install(table):
        def fake_resolve(domain, rtype, lifetime=None):
            value = table.get(rtype)
            if isinstance(value, Exception):
                raise value
            if value is None:
                raise dns.resolver.NoAnswer()
            return value
        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    return install


def test_dnspython_returns_one_result_per_record(dns_records):
    dns_records({"A": ["93.184.216.34"], "MX": ["10 mail.empresa.com."], "NS": ["ns1.empresa.com.", "ns2.empresa.com."], "TXT": ['"v=spf1 -all"']})
    results = DnspythonTool().execute(QueryParameters(domain="empresa.com"))
    assert [(r.title, r.snippet) for r in results][:3] == [("DNS A: empresa.com", "93.184.216.34"), ("DNS MX: empresa.com", "10 mail.empresa.com."),
                                                           ("DNS NS: empresa.com", "ns1.empresa.com.")]
    assert len(results) == 5 and all(r.category == "DNS" and r.relevance_score == 70 for r in results)


def test_dnspython_skips_types_that_fail_and_validates_the_domain(dns_records):
    dns_records({"A": RuntimeError("timeout"), "MX": ["10 mail.x.com."]})
    assert [r.title for r in DnspythonTool().execute(QueryParameters(domain="x.com"))] == ["DNS MX: x.com"]
    for bad in ("", "x", "a b.com", "x.com; rm -rf /"):
        assert DnspythonTool().execute(QueryParameters(domain=bad)) == []


def test_dnspython_caps_the_number_of_results(dns_records):
    dns_records({"TXT": [f"registro-{i}" for i in range(500)]})
    assert len(DnspythonTool().execute(QueryParameters(domain="x.com"))) == network_tools.MAX_RESULTS


# ── ipwhois ──────────────────────────────────────────────────────────────────

def fake_ipwhois(monkeypatch, behavior):
    class IPWhois:
        def __init__(self, ip, timeout=None):
            self.ip = ip

        def lookup_rdap(self, depth=1):
            return behavior(self.ip)
    monkeypatch.setitem(sys.modules, "ipwhois", SimpleNamespace(IPWhois=IPWhois))


def test_ipwhois_result(monkeypatch):
    fake_ipwhois(monkeypatch, lambda ip: {"asn": "15169", "asn_description": "GOOGLE, US", "network": {"cidr": "8.8.8.0/24"}})
    (result,) = IpWhoisTool().execute(QueryParameters(ip="8.8.8.8"))
    assert result.title == "WHOIS: 8.8.8.8" and "ASN: 15169" in result.snippet and "GOOGLE, US" in result.snippet and "8.8.8.0/24" in result.snippet
    assert result.raw_data["asn"] == "15169" and result.category == "Network"


@pytest.mark.parametrize("ip", ["", "999.1.1.1", "no es ip", "8.8.8.8; ls"])
def test_ipwhois_rejects_invalid_ips_without_a_lookup(monkeypatch, ip):
    fake_ipwhois(monkeypatch, lambda i: pytest.fail("no debe consultar"))
    assert IpWhoisTool().execute(QueryParameters(ip=ip)) == []


def test_ipwhois_failures_return_nothing(monkeypatch):
    def boom(ip):
        raise RuntimeError("RDAP caído")
    fake_ipwhois(monkeypatch, boom)
    assert IpWhoisTool().execute(QueryParameters(ip="8.8.8.8")) == []
    monkeypatch.setitem(sys.modules, "ipwhois", None)                                              # paquete no instalado
    assert IpWhoisTool().execute(QueryParameters(ip="8.8.8.8")) == []


# ── CENSYS ───────────────────────────────────────────────────────────────────

def test_censys_availability_depends_on_the_package(monkeypatch):
    monkeypatch.setattr(network_tools.importlib.util, "find_spec", lambda name: None)
    tool = CensysTool()
    assert tool.is_available is False and tool.diagnose_status()["status"] == "not_installed"        # antes: aparecía lista para usar
    monkeypatch.setattr(network_tools.importlib.util, "find_spec", lambda name: object())
    assert tool.check_available() is True and CensysTool().is_available is True


def test_censys_without_key_says_so():
    tool = CensysTool()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(domain="empresa.com")) == [] and any("--set-key CENSYS" in m for m in seen)


def test_censys_old_api_missing_is_reported_not_silent(monkeypatch):
    monkeypatch.setitem(sys.modules, "censys", None)                                                # import censys.certificates -> ImportError
    tool = CensysTool()
    tool.api_key = "k"
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(domain="empresa.com")) == [] and any("API antigua" in m for m in seen)


def test_censys_results_and_errors(monkeypatch):
    class Certs:
        def search(self, query, fields=None, max_records=None):
            assert "empresa.com" in query and max_records == 50
            return [{"parsed.subject_dn": "CN=www.empresa.com", "parsed.names": ["www.empresa.com", "empresa.com"]}] * 3
    package = SimpleNamespace(certificates=SimpleNamespace(CensysCertificates=Certs))        # `import censys.certificates` enlaza `censys`
    monkeypatch.setitem(sys.modules, "censys", package)
    monkeypatch.setitem(sys.modules, "censys.certificates", package.certificates)
    tool = CensysTool()
    tool.api_key = "k"
    results = tool.execute(QueryParameters(domain="empresa.com"))
    assert len(results) == 3 and results[0].title == "Certificado: CN=www.empresa.com" and "www.empresa.com" in results[0].snippet
    assert tool.execute(QueryParameters(domain="no es dominio")) == []

    class Broken:
        def search(self, *a, **k):
            raise RuntimeError("401")
    package.certificates = SimpleNamespace(CensysCertificates=Broken)
    monkeypatch.setitem(sys.modules, "censys.certificates", package.certificates)
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(domain="empresa.com")) == [] and any("falló la consulta (RuntimeError)" in m for m in seen)


# ── TheHarvester ─────────────────────────────────────────────────────────────

HARVESTER_OUTPUT = """\
*******************************************************************
* theHarvester 4.6.0                                              *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
* cmartorella@edge-security.com                                   *
*******************************************************************
[*] Target: empresa.com
[*] Searching Duckduckgo.
[*] Emails found: 3
----------------------
juan@empresa.com
maria.lopez@empresa.com
juan@empresa.com
cmartorella@edge-security.com

[*] Hosts found: 3
---------------------
www.empresa.com:93.184.216.34
mail.empresa.com
api.empresa.com:10.0.0.9
"""


@pytest.fixture
def harvester(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)                                                                     # sin theHarvester/ local
    state = {"cmd": None}

    def install(stdout="", which="/bin/theHarvester", error=None):
        monkeypatch.setattr(network_tools.shutil, "which", lambda name: which if name in ("theHarvester", "theharvester") and which else None)

        def fake_run(cmd, **kw):
            state["cmd"], state["kw"] = cmd, kw
            if error:
                raise error
            return SimpleNamespace(stdout=stdout, returncode=0)
        monkeypatch.setattr(network_tools.subprocess, "run", fake_run)
        return state
    return install


def test_harvester_parses_emails_and_hosts_without_the_banner(harvester):
    state = harvester(HARVESTER_OUTPUT)
    results = TheHarvesterTool().execute(QueryParameters(domain="empresa.com"))
    emails = [r.title for r in results if r.category == "Email"]
    hosts = {r.title: r for r in results if r.category == "Subdomain"}
    assert emails == ["Email: juan@empresa.com", "Email: maria.lopez@empresa.com"]                 # sin el correo del banner y sin repetidos
    assert set(hosts) == {"Host: www.empresa.com", "Host: mail.empresa.com", "Host: api.empresa.com"}
    assert "IP 93.184.216.34" in hosts["Host: www.empresa.com"].snippet and hosts["Host: www.empresa.com"].raw_data == {"host": "www.empresa.com", "ip": "93.184.216.34"}
    assert "IP" not in hosts["Host: mail.empresa.com"].snippet and hosts["Host: mail.empresa.com"].url == "https://mail.empresa.com"
    assert state["cmd"][:3] == ["/bin/theHarvester", "-d", "empresa.com"] and "-b" in state["cmd"] and state["kw"]["timeout"] == 300


def test_harvester_banner_email_is_not_a_finding_even_alone(harvester):
    harvester("* cmartorella@edge-security.com    *\ncmartorella@edge-security.com\n")
    assert TheHarvesterTool().execute(QueryParameters(domain="empresa.com")) == []                  # antes: salía como "Email" en cada ejecución


def test_harvester_extra_args_replace_the_defaults(harvester):
    state = harvester("")
    TheHarvesterTool().execute(QueryParameters(domain="empresa.com", extra_args="-b crtsh -l 50"))
    assert state["cmd"][-4:] == ["-b", "crtsh", "-l", "50"] and "duckduckgo,yahoo,crtsh,hackertarget" not in state["cmd"]


def test_harvester_caps_results(harvester):
    harvester("\n".join(f"h{i}@empresa.com" for i in range(300)))
    assert len(TheHarvesterTool().execute(QueryParameters(domain="empresa.com"))) == network_tools.MAX_RESULTS


@pytest.mark.parametrize("stdout", ["Traceback (most recent call last):\n  ...\nValueError", "ModuleNotFoundError: No module named 'x'"])
def test_harvester_reports_its_own_crash(harvester, stdout):
    harvester(stdout)
    (result,) = TheHarvesterTool().execute(QueryParameters(domain="empresa.com"))
    assert result.category == "Error" and "Error Crítico" in result.title and result.relevance_score == 100


def test_harvester_timeout_and_unexpected_errors_are_results_not_exceptions(harvester):
    harvester(error=subprocess.TimeoutExpired("theHarvester", 300))
    (timeout,) = TheHarvesterTool().execute(QueryParameters(domain="empresa.com"))
    assert timeout.category == "Error" and "Timeout" in timeout.title
    harvester(error=OSError("no se pudo lanzar"))
    (failure,) = TheHarvesterTool().execute(QueryParameters(domain="empresa.com"))
    assert failure.category == "Error" and "no se pudo lanzar" in failure.snippet


def test_harvester_validates_the_domain_and_needs_the_program(harvester):
    harvester("juan@empresa.com", which="/bin/theHarvester")
    for bad in ("", "x", "a b.com", "x.com; ls"):
        assert TheHarvesterTool().execute(QueryParameters(domain=bad)) == []
    harvester("juan@empresa.com", which=None)                                                        # ni en el PATH ni en la carpeta local
    assert TheHarvesterTool().execute(QueryParameters(domain="empresa.com")) == []


def test_harvester_uses_the_local_clone_when_not_in_path(harvester, tmp_path):
    state = harvester("juan@empresa.com", which=None)
    (tmp_path / "theHarvester").mkdir()
    (tmp_path / "theHarvester" / "theHarvester.py").write_text("print('x')")
    results = TheHarvesterTool().execute(QueryParameters(domain="empresa.com"))
    assert [r.title for r in results] == ["Email: juan@empresa.com"]
    assert state["cmd"][0] == sys.executable and state["cmd"][1].endswith("theHarvester.py")


def test_harvester_diagnose(harvester):
    harvester("", which="/bin/theHarvester")
    assert TheHarvesterTool().diagnose_status()["status"] == "ready"
    harvester("", which=None)
    d = TheHarvesterTool().diagnose_status()
    assert d["status"] == "not_installed" and "git clone https://github.com/laramies/theHarvester.git" in d["install_cmd"]


# ── phonenumbers (con la librería real) ──────────────────────────────────────

@pytest.mark.parametrize("phone,region,operator", [
    ("+593 99 123 4567", "Ecuador", "Claro"), ("0991234567", "Ecuador", "Claro"),                      # sin código de país: prueba EC primero
    ("+34 612 345 678", "España", ""), ("+593 2 299 3000", "Pichincha", ""),
])
def test_phone_valid_numbers(phone, region, operator):
    (r,) = PhoneNumbersTool().execute(QueryParameters(phone=phone))
    assert r.category == "Phone" and "Válido: True" in r.snippet and f"Región: {region}" in r.snippet and operator in r.snippet and r.relevance_score == 80


def test_phone_unrecognizable_or_without_data():
    (invalid,) = PhoneNumbersTool().execute(QueryParameters(phone="+99 999"))
    assert invalid.category == "Error" and "Teléfono Inválido" in invalid.title and invalid.relevance_score == 100
    (no_region,) = PhoneNumbersTool().execute(QueryParameters(phone="12345"))
    assert no_region.category == "Phone" and "Válido: False" in no_region.snippet and no_region.relevance_score == 50


def test_phone_garbage_input_is_cleaned_and_limited():
    tool = PhoneNumbersTool()
    assert tool.execute(QueryParameters(phone="")) == [] and tool.execute(QueryParameters(phone="abc")) == []
    (r,) = tool.execute(QueryParameters(phone="+593<script>99</script> 123 4567"))
    assert "<" not in r.title and ">" not in r.title                                                # solo caracteres de teléfono
    (long,) = tool.execute(QueryParameters(phone="+" + "9" * 200))
    assert len(long.title) < 60                                                                    # el texto se recorta a 20 caracteres
