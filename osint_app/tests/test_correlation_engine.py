"""Motor de correlación: normalización, extracción de entidades y correlaciones."""
import json

import pytest

from osint_app.correlation_engine import CorrelationEngine, Entity, EntityExtractor


# ── Entity ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("etype,raw,expected", [
    ("email", "  Juan@Empresa.COM ", "juan@empresa.com"),
    ("domain", "WWW.Example.com", "example.com"),
    ("phone", "+593 (99) 123-4567", "+593991234567"),
    ("username", "@Usuario_1", "usuario_1"),
])
def test_normalized(etype, raw, expected):
    assert Entity(etype, raw, "test").normalized() == expected


def test_fingerprint_ignores_formatting_but_not_type():
    a = Entity("domain", "www.example.com", "a")
    b = Entity("domain", "EXAMPLE.com", "b")
    c = Entity("username", "example.com", "c")
    assert a.fingerprint() == b.fingerprint()
    assert a.fingerprint() != c.fingerprint()


# ── EntityExtractor ───────────────────────────────────────────────────────────

def _by_type(entities):
    out = {}
    for e in entities:
        out.setdefault(e.entity_type, set()).add(e.value)
    return out


def test_extract_basic_entities():
    text = "Contacto: juan@empresa.com, servidor 10.0.0.5, usuario @juanito en sub.example.org"
    found = _by_type(EntityExtractor.extract(text, "test"))
    assert found["email"] == {"juan@empresa.com"}
    assert "10.0.0.5" in found["ip"]
    assert "@juanito" in found["username"]
    assert "sub.example.org" in found["domain"]


def test_extract_skips_image_and_asset_filenames():
    found = _by_type(EntityExtractor.extract("logo.png style.css app.js", "test"))
    assert "domain" not in found


def test_extract_deduplicates():
    found = EntityExtractor.extract("a@b.com a@b.com A@B.COM", "test")
    assert [e.value for e in found if e.entity_type == "email"] == ["a@b.com"]


def test_extract_hashes():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    found = _by_type(EntityExtractor.extract(f"{md5} {sha}", "test"))
    assert found["hash_md5"] == {md5}
    assert found["hash_sha256"] == {sha}


def test_extract_from_nested_json():
    data = {"a": ["x@y.com", {"b": "host 8.8.8.8"}], "n": 5}
    found = _by_type(EntityExtractor.extract_from_json(data, "test"))
    assert found["email"] == {"x@y.com"}
    assert "8.8.8.8" in found["ip"]


# ── _check_correlation (no usa BD) ────────────────────────────────────────────

@pytest.fixture
def engine():
    eng = CorrelationEngine.__new__(CorrelationEngine)
    eng.entities, eng.correlations = {}, []
    return eng


@pytest.mark.parametrize("a,b,relation", [
    (("email", "juan@empresa.com"), ("domain", "empresa.com"), "owns"),
    (("email", "jriofrio@gmail.com"), ("username", "@jriofrio"), "same_person"),
    (("domain", "mail.example.com"), ("domain", "example.com"), "subdomain_of"),
    (("domain", "www.example.com"), ("domain", "example.com"), "same_entity"),
])
def test_correlations_detected(engine, a, b, relation):
    corr = engine._check_correlation(Entity(*a, "t"), Entity(*b, "t"))
    assert corr is not None and corr.relation_type == relation


@pytest.mark.parametrize("a,b", [
    (("email", "juan@otra.com"), ("domain", "empresa.com")),
    (("domain", "notexample.com"), ("domain", "example.com")),  # no es subdominio
    (("ip", "1.1.1.1"), ("ip", "8.8.8.8")),
])
def test_no_false_correlations(engine, a, b):
    assert engine._check_correlation(Entity(*a, "t"), Entity(*b, "t")) is None


# ── CorrelationEngine con BD temporal ─────────────────────────────────────────

def test_engine_persists_and_dedups(temp_db):
    from osint_app.case_manager import CaseManager
    case = CaseManager().create("test", "")
    eng = CorrelationEngine(case.id)

    assert eng.add_entity(Entity("domain", "example.com", "manual", confidence=50)) is True
    assert eng.add_entity(Entity("email", "a@example.com", "toolA")) is True
    # Misma entidad desde otra fuente: no se duplica, sube la confianza
    assert eng.add_entity(Entity("domain", "WWW.example.com", "toolB")) is False
    assert eng.entities[Entity("domain", "example.com", "").fingerprint()].confidence == 60

    assert any(c.relation_type == "owns" for c in eng.correlations)
    stored = {(d.field_type, d.value) for d in temp_db.get_target_data(case.id)}
    assert {("domain", "example.com"), ("email", "a@example.com")} <= stored

    # Un motor nuevo sobre el mismo caso recarga lo guardado
    assert len(CorrelationEngine(case.id).entities) == 2


def test_process_tool_results_json_and_text(temp_db):
    from osint_app.case_manager import CaseManager
    case = CaseManager().create("test", "")
    eng = CorrelationEngine(case.id)
    raw = json.dumps([{"snippet": "x@example.org"}, "host 9.9.9.9"])
    assert eng.process_tool_results("tool", raw) >= 2
    assert eng.process_tool_results("tool", "texto plano con z@example.net") >= 1
