"""Puente CTI ↔ casos: lector e índice del almacén CTI (2a)."""
import json
from pathlib import Path

import pytest

from osint_app import cti_link
from osint_app.cti_link import CtiStore, normalize_cves


# ── normalize_cves ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [
    (["CVE-2026-93952"], ["CVE-2026-93952"]),
    ("['CVE-2026-1234', 'cve-2026-5678']", ["CVE-2026-1234", "CVE-2026-5678"]),
    ("texto CVE-2024-1234 y más", ["CVE-2024-1234"]),
    (["CVE-2026-1111", "cve-2026-1111"], ["CVE-2026-1111"]),   # dedup + mayúsculas
    ("CVE-2026-12", []),      # < 4 dígitos: no es un CVE válido
    ("", []),
    (None, []),
])
def test_normalize_cves(value, expected):
    assert normalize_cves(value) == expected


# ── CtiStore ──────────────────────────────────────────────────────────────────

SAMPLE = [
    {"cves": ["CVE-2026-93952"], "titulo": "Arista VeloCloud", "vendor": "Arista",
     "product": "VeloCloud Orchestrator", "fuente": "CISA KEV", "url": "http://x",
     "kev": True, "ransomware": False},
    {"cves": ["CVE-2026-94127"], "titulo": "F5 BIG-IP", "vendor": "F5",
     "product": "BIG-IP APM", "fuente": "MSRC", "kev": False, "exploited": True},
    {"cves": ["CVE-2026-0001"], "titulo": "Fortinet FortiOS", "vendor": "Fortinet",
     "product": "FortiGate", "kev": False, "ransomware": True},
]


@pytest.fixture
def store():
    return CtiStore(SAMPLE)


def test_len_and_cve_count(store):
    assert len(store) == 3
    assert store.cve_count == 3


def test_by_cve_exact_match(store):
    hits = store.by_cve("cve-2026-93952")   # sin distinguir mayúsculas
    assert len(hits) == 1
    assert hits[0].vendor == "Arista" and hits[0].kev is True
    assert hits[0].actively_exploited is True


def test_by_cve_not_found(store):
    assert store.by_cve("CVE-1999-9999") == []


def test_exploited_and_ransomware_flags(store):
    assert store.by_cve("CVE-2026-94127")[0].actively_exploited is True   # exploited
    assert store.by_cve("CVE-2026-0001")[0].ransomware is True


def test_search_tech_by_vendor_and_product(store):
    assert store.search_tech("fortinet")[0].cve == "CVE-2026-0001"
    assert store.search_tech("big-ip")[0].vendor == "F5"
    assert store.search_tech("noexiste") == []


def test_search_tech_ignores_short_terms(store):
    assert store.search_tech("f5") == []   # < 3 caracteres, evita ruido


def test_load_missing_file_is_empty(tmp_path):
    s = CtiStore.load(tmp_path / "no-existe.jsonl")
    assert len(s) == 0 and s.by_cve("CVE-2026-1") == []


def test_load_from_jsonl(tmp_path):
    p = tmp_path / "items.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in SAMPLE) + "\n", encoding="utf-8")
    s = CtiStore.load(p)
    assert len(s) == 3 and s.by_cve("CVE-2026-0001")[0].vendor == "Fortinet"


def test_load_skips_bad_lines(tmp_path):
    p = tmp_path / "items.jsonl"
    p.write_text('{"cves":["CVE-2026-1"]}\nlínea rota\n\n{"cves":["CVE-2026-2"]}\n',
                 encoding="utf-8")
    assert len(CtiStore.load(p)) == 2


@pytest.mark.skipif(not cti_link.DEFAULT_STORE.exists(),
                    reason="almacén CTI real no presente")
def test_real_store_loads_and_indexes():
    s = CtiStore.load()
    assert len(s) > 100 and s.cve_count > 100


# ── Cruce entidades del caso ↔ CTI (2b) ───────────────────────────────────────

from osint_app.cti_link import correlate_entities_with_cti  # noqa: E402
from osint_app.correlation_engine import Entity, EntityExtractor  # noqa: E402


def test_entity_extractor_now_finds_cves():
    ents = EntityExtractor.extract("Reporte: afectado por CVE-2026-0001 y cve-2026-94127.", "t")
    cves = sorted(e.value.upper() for e in ents if e.entity_type == "cve")
    assert cves == ["CVE-2026-0001", "CVE-2026-94127"]


def test_cve_entity_normalized_uppercase():
    assert Entity("cve", "cve-2026-0001", "t").normalized() == "CVE-2026-0001"


def test_correlate_matches_case_cve_with_cti(store):
    entities = [Entity("cve", "cve-2026-0001", "report"),   # está en el CTI (ransomware)
                Entity("domain", "example.com", "manual"),
                Entity("cve", "CVE-1999-9999", "report")]   # no está en el CTI
    result = correlate_entities_with_cti(entities, store)
    assert result["total_cve_matches"] == 1
    m = result["cve_matches"][0]
    assert m["cve"] == "CVE-2026-0001" and m["ransomware"] is True


def test_correlate_flags_actively_exploited(store):
    result = correlate_entities_with_cti([Entity("cve", "CVE-2026-93952", "r")], store)
    assert result["actively_exploited"] == 1     # es KEV


def test_correlate_dedups_repeated_cves(store):
    ents = [Entity("cve", "CVE-2026-0001", "a"), Entity("cve", "cve-2026-0001", "b")]
    assert correlate_entities_with_cti(ents, store)["total_cve_matches"] == 1


def test_correlate_tech_terms(store):
    result = correlate_entities_with_cti([], store, tech_terms=["Fortinet", "noexiste"])
    assert result["total_tech_matches"] == 1
    assert result["tech_matches"][0]["term"] == "fortinet"


def test_correlate_empty_case(store):
    result = correlate_entities_with_cti([], store)
    assert result["total_cve_matches"] == 0 and result["total_tech_matches"] == 0


def test_correlation_engine_method_uses_injected_store(store, temp_db):
    from osint_app.case_manager import CaseManager
    from osint_app.correlation_engine import CorrelationEngine
    case = CaseManager().create("c", "")
    eng = CorrelationEngine(case.id)
    eng.add_entity(Entity("cve", "CVE-2026-0001", "report"))
    result = eng.correlate_with_cti(store=store)
    assert result["total_cve_matches"] == 1


# ── Recoger tecnologías de los reportes (3c) ──────────────────────────────────

from osint_app.cti_link import collect_tech_terms_from_reports  # noqa: E402


class _Rep:
    def __init__(self, raw_json): self.raw_json = raw_json


def test_collect_tech_terms_from_reports():
    import json as _json
    reports = [
        _Rep(_json.dumps([
            {"title": "Fortinet", "category": "Technology", "raw_data": {"technology": "Fortinet"}},
            {"title": "nginx", "category": "Technology", "raw_data": {"technology": "nginx"}},
            {"title": "otra cosa", "category": "GitHub Repo"},
        ])),
        _Rep(_json.dumps([{"title": "Fortinet", "category": "Technology",
                           "raw_data": {"technology": "Fortinet"}}])),  # dup
    ]
    assert collect_tech_terms_from_reports(reports) == ["Fortinet", "nginx"]


def test_collect_tech_terms_handles_bad_json():
    assert collect_tech_terms_from_reports([_Rep("no es json")]) == []
    assert collect_tech_terms_from_reports([]) == []


def test_store_summary_counts(store):
    s = store.summary()
    assert s["items"] == 3 and s["cves"] == 3
    assert s["kev"] == 1          # solo el primero es KEV
    assert s["ransomware"] == 1   # solo el tercero
    assert s["vendors"] == 3
