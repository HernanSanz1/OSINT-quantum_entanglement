"""Perfiladores: variantes de username, scoring y reglas de rechazo.

Solo se prueba la lógica local; ningún test hace peticiones HTTP.
"""
import subprocess
import sys

import pytest

from osint_app.core.models import SearchResult
from osint_app.profiler_engine import ProfilerEngine, SeedData
from osint_app.smart_profiler import CandidateProfile, ProfileSeed, SmartProfiler
from osint_app.tools.web_search import UsernameVariantsTool


@pytest.fixture
def sp():
    # Sin __init__: evita crear CaseManager (BD) para probar funciones puras
    obj = SmartProfiler.__new__(SmartProfiler)
    obj.candidates, obj.rejected = [], []
    return obj


def cand(display_name="", username="", location="", company="", bio=""):
    return CandidateProfile(platform="GitHub", url="", username=username,
                            display_name=display_name, location=location,
                            company=company, bio=bio)


# ── SmartProfiler: semilla y variantes ────────────────────────────────────────

def test_enrich_seed_detects_country_and_year(sp):
    seed = sp._enrich_seed(ProfileSeed(name="Juan Riofrio", context="UDLA Ecuador nacido 2006"))
    assert seed.country == "Ecuador"
    assert seed.year_hint == "2006"


def test_smart_variants(sp):
    v = sp._generate_smart_variants(ProfileSeed(name="Juan Riofrio", year_hint="2006"))
    assert len(v) <= 20 and len(v) == len(set(v))
    assert v[0] == "juanriofrio2006"          # con año van primero
    assert "juanriofrio06" in v


def test_smart_variants_known_username_first(sp):
    v = sp._generate_smart_variants(ProfileSeed(name="Juan Riofrio", username="jdr2006"))
    assert v[0] == "jdr2006"


def test_smart_variants_single_word_name(sp):
    assert sp._generate_smart_variants(ProfileSeed(name="Madonna")) == ["madonna"]


# ── SmartProfiler: scoring ────────────────────────────────────────────────────

def test_name_score_exact_and_disjoint(sp):
    seed = ProfileSeed(name="Juan Riofrio")
    assert sp._calculate_name_score(cand("Juan Riofrio"), seed) == 1.0
    assert sp._calculate_name_score(cand("Pedro Gomez"), seed) == 0.0


def test_last_name_bonus_uses_real_last_name(sp):
    # "Carlos" es el segundo nombre, no el apellido: no debe recibir bonus.
    seed = ProfileSeed(name="Juan Carlos Riofrio")
    assert sp._calculate_name_score(cand("Pedro Carlos"), seed) == pytest.approx(1 / 3)
    assert sp._calculate_name_score(cand("Pedro Riofrio"), seed) == pytest.approx(1 / 3 + 0.2)


def test_name_score_is_deterministic_across_processes():
    # Regresión: el apellido salía de list(set(...))[-1] y variaba con PYTHONHASHSEED.
    code = (
        "from osint_app.smart_profiler import SmartProfiler, ProfileSeed, CandidateProfile;"
        "sp=SmartProfiler.__new__(SmartProfiler);"
        "c=CandidateProfile(platform='',url='',username='x',display_name='Pedro Carlos');"
        "print(sp._calculate_name_score(c, ProfileSeed(name='Juan Carlos Riofrio')))"
    )
    outputs = {
        subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env={**__import__("os").environ, "PYTHONHASHSEED": str(seed)}).stdout.strip()
        for seed in range(6)
    }
    assert len(outputs) == 1, outputs


@pytest.mark.parametrize("username,expected", [
    ("juanriofrio", 0.7), ("jriofrio99", 0.7), ("jdriofrio", 0.7),
    ("riofrio_x", 0.5), ("juan_x", 0.3), ("zzz", 0.0),
])
def test_username_to_name_score(sp, username, expected):
    assert sp._username_to_name_score(username, "Juan Riofrio") == expected


def test_context_score(sp):
    seed = ProfileSeed(name="x", context="estudiante UDLA Quito", country="Ecuador")
    assert sp._calculate_context_score(cand(location="Quito, Ecuador", bio="Estudiante en UDLA"), seed) > 0.5
    assert sp._calculate_context_score(cand(location="Madrid, Spain"), seed) == 0.0


# ── SmartProfiler: reglas de rechazo ──────────────────────────────────────────

def test_reject_different_name(sp):
    seed = ProfileSeed(name="Juan Riofrio")
    assert "Nombre no coincide" in sp._check_rejection_rules(cand("Pedro Gomez", "pgomez"), seed)
    # Nombre distinto pero el apellido está en el username: no se rechaza por nombre
    assert sp._check_rejection_rules(cand("JR", "jriofrio"), seed) is None


def test_reject_other_country(sp):
    seed = ProfileSeed(name="Juan Riofrio", country="Ecuador")
    reason = sp._check_rejection_rules(cand("Juan Riofrio", location="Madrid, Spain"), seed)
    assert "Ubicación" in reason


def test_reject_big_company_for_student(sp):
    seed = ProfileSeed(name="Juan Riofrio", context="estudiante universidad UDLA")
    assert "estudiante" in sp._check_rejection_rules(cand("Juan Riofrio", company="Google"), seed)


def test_evaluate_candidate_sorts_into_lists(sp):
    seed = ProfileSeed(name="Juan Riofrio", country="Ecuador")
    sp._evaluate_candidate(cand("Juan Riofrio", location="Quito, Ecuador"), seed)
    sp._evaluate_candidate(cand("Juan Riofrio", location="Madrid, Spain"), seed)
    assert len(sp.candidates) == 1 and sp.candidates[0].total_score > 0.5
    assert len(sp.rejected) == 1 and sp.rejected[0].total_score == 0


# ── UsernameVariantsTool ──────────────────────────────────────────────────────

def test_username_variants_order_and_limit():
    v = UsernameVariantsTool()._generate_variants("Iván Ortiz", "1995")
    assert len(v) == 200 and len(v) == len(set(v))
    # Las más probables primero (solo se consultan las 10 primeras en GitHub)
    assert v[:4] == ["ivanortiz", "ivan.ortiz", "ivan_ortiz", "ivan-ortiz"]
    assert all("á" not in x for x in v)


def test_username_variants_are_deterministic():
    code = ("from osint_app.tools.web_search import UsernameVariantsTool as U;"
            "print(U()._generate_variants('Ivan Ortiz','1995'))")
    outputs = {
        subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env={**__import__("os").environ, "PYTHONHASHSEED": str(seed)}).stdout
        for seed in range(4)
    }
    assert len(outputs) == 1


def test_username_variants_empty_name():
    assert UsernameVariantsTool()._generate_variants("   ") == []


# ── ProfilerEngine: confianza de un resultado ─────────────────────────────────

def test_profiler_engine_confidence():
    eng = ProfilerEngine.__new__(ProfilerEngine)
    seed = SeedData(name="Juan Riofrio", email="juan@example.com", country="Ecuador")
    hit = SearchResult(title="Juan Riofrio - Quito, Ecuador", url="",
                       snippet="contacto juan@example.com", source_tool="t", category="x")
    miss = SearchResult(title="Otra persona", url="", snippet="nada", source_tool="t", category="x")
    score, matched = eng._calculate_confidence(hit, seed)
    assert score == 85 and {"name", "email", "country"} <= set(matched)
    assert eng._calculate_confidence(miss, seed) == (0, [])
