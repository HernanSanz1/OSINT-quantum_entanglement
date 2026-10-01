"""Filtros compartidos de entidades y los dos extractores que los usan."""
import pytest

from osint_app.correlation_engine import EntityExtractor as CorrelationExtractor
from osint_app.utils import entity_filters
from osint_app.utils.entity_extractor import EntityExtractor as FrameworkExtractor
from osint_app.utils.entity_filters import has_known_tld, is_noise_domain, is_plausible_phone

WAYBACK_TEXT = (
    "https://web.archive.org/web/20000815065837/http://www.python.org/NEWS-152.txt "
    "ts 20000816002136 fecha 19980526 md5sum.py otro.zzzzz "
    "http://www.python.org:80/1.5/parsermodule.1.tx..."
)


@pytest.mark.parametrize("domain,expected", [
    ("python.org", True), ("gob.ec", True), ("EMPRESA.COM", True),
    ("NEWS-152.txt", False), ("parsermodule.1.tx", False), ("otro.zzzzz", False),
])
def test_has_known_tld(domain, expected):
    assert has_known_tld(domain) is expected


@pytest.mark.parametrize("domain,noise", [
    ("web.archive.org", True), ("crt.sh", True), ("logo.png", True), ("app.js", True), ("x.zzzzz", True),
    ("python.org", False), ("sub.empresa.com.ec", False),
])
def test_is_noise_domain(domain, noise):
    assert is_noise_domain(domain) is noise


@pytest.mark.parametrize("phone,ok", [
    ("20000815065837", False), ("19980526", False), ("123456", False), ("1234567890123456", False),
    ("151.101.64.223", False), ("+593 2 299 3000", True), ("0987654321", True),
])
def test_is_plausible_phone(phone, ok):
    assert is_plausible_phone(phone) is ok


def test_missing_tld_file_does_not_filter(monkeypatch, tmp_path):
    # si falta tlds.txt no se descarta ningún dominio (mejor ruido que perder datos)
    monkeypatch.setattr(entity_filters, "TLD_FILE", tmp_path / "no_existe.txt")
    entity_filters._tlds.cache_clear()
    try:
        assert has_known_tld("cualquiera.zzzzz") is True
    finally:
        entity_filters._tlds.cache_clear()


def test_correlation_extractor_filters_wayback_noise():
    found = {e.value for e in CorrelationExtractor.extract(WAYBACK_TEXT, "Wayback") if e.entity_type == "domain"}
    assert {d.replace("www.", "") for d in found} == {"python.org", "md5sum.py"}
    assert not [e for e in CorrelationExtractor.extract(WAYBACK_TEXT, "Wayback") if e.entity_type == "phone"]


def test_framework_extractor_filters_wayback_noise():
    out = FrameworkExtractor().extract(WAYBACK_TEXT)
    assert {d.replace("www.", "") for d in out["domain"]} == {"python.org", "md5sum.py"}
    assert out["phone"] == []


def test_framework_extractor_keeps_real_data():
    text = "Contacto juan@empresa.com, +593 2 299 3000, 10.0.0.5, https://sub.empresa.com.ec/x"
    out = FrameworkExtractor().extract(text)
    assert out["email"] == ["juan@empresa.com"]
    assert "+593 2 299 3000" in out["phone"]
    assert out["ip"] == ["10.0.0.5"]
    assert "sub.empresa.com.ec" in out["domain"]
    assert out["url"] == ["https://sub.empresa.com.ec/x"]


def test_path_file_is_not_a_domain_but_url_host_is():
    # md5sum.py es un archivo (".py" es TLD real); en "http://host" el host sí cuenta
    text = "http://www.python.org:80/1.5/md5sum.py https://web.archive.org/web/2000/http://www.python.org/x/tool.sh y empresa.com/ruta"
    for out in (
        {e.value for e in CorrelationExtractor.extract(text, "t") if e.entity_type == "domain"},
        set(FrameworkExtractor().extract(text)["domain"]),
    ):
        assert "md5sum.py" not in out and "tool.sh" not in out
        assert {"www.python.org", "empresa.com"} <= out


def test_tool_own_hosts_are_not_entities():
    text = "https://crt.sh/?q=empresa.com https://rdap.org/domain/empresa.com sub.empresa.com"
    out = {e.value for e in CorrelationExtractor.extract(text, "t") if e.entity_type == "domain"}
    assert out == {"sub.empresa.com", "empresa.com"}      # sin "mpresa.com" ni "crt.sh" ni "rdap.org"


MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def test_dns_txt_tokens_are_not_hashes_in_correlation(temp_db):
    import json
    from osint_app.case_manager import CaseManager
    from osint_app.correlation_engine import CorrelationEngine
    raw = json.dumps([
        {"title": "DNS TXT: empresa.com", "snippet": MD5},
        {"title": "DNS TXT: empresa.com", "snippet": "twilio-domain-verification=" + MD5[::-1]},
        {"title": "Malware conocido", "snippet": "sha256 de muestra " + "a" * 64 + " md5 " + "b" * 32},
    ])
    eng = CorrelationEngine(CaseManager().create("t", "").id)
    eng.process_tool_results("dnspython", raw)
    hashes = {e.value for e in eng.entities.values() if e.entity_type.startswith("hash_")}
    assert hashes == {"a" * 64, "b" * 32}       # los de un resultado normal se conservan


def test_dns_txt_tokens_are_not_hashes_in_framework_extractor():
    from types import SimpleNamespace as R
    results = [R(title="DNS TXT: empresa.com", snippet=MD5, url=""),
               R(title="Muestra", snippet="md5 " + "b" * 32, url="")]
    assert FrameworkExtractor().extract_from_results(results)["hash"] == ["b" * 32]
