"""Perfilador: variantes de username y confianza de un resultado.

Solo se prueba la lógica local; ningún test hace peticiones HTTP.
(Antes este archivo también probaba smart_profiler.py, eliminado por estar duplicado y sin uso; lo que tenía de
valioso se rescató en UsernameVariants, handle_matches_name y name_match, con sus propios tests.)
"""
import subprocess
import sys

import pytest

from osint_app.core.models import SearchResult
from osint_app.profiler_engine import ProfilerEngine, SeedData
from osint_app.tools.web_search import UsernameVariantsTool


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


def test_username_variants_single_word_name():
    assert "madonna" in UsernameVariantsTool()._generate_variants("Madonna")


@pytest.mark.parametrize("variant", [
    # inicial + apellido + año del objetivo: antes el bloque de años nunca llegaba a estos (rescatado de smart_profiler)
    "jriofrio2006", "jriofrio06", "j.riofrio2006", "j_riofrio06", "juanr2006", "juanr06", "riofrioj2006", "riofrioj06",
    "juanriofrio2006", "juanriofrio06",
])
def test_username_variants_combine_the_target_year_with_initial_patterns(variant):
    assert variant in UsernameVariantsTool()._generate_variants("Juan Riofrio", "2006", "UDLA Ecuador 2006")


def test_username_variants_with_middle_name_and_without_year():
    with_year = UsernameVariantsTool()._generate_variants("Juan Daniel Riofrio", "2006")
    assert "jdriofrio2006" in with_year and "jdriofrio06" in with_year          # inicial + inicial del 2.º nombre + año
    without = UsernameVariantsTool()._generate_variants("Juan Riofrio", None)
    assert "jriofrio2006" not in without and "jriofrio" in without              # sin año del objetivo no se inventa uno


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
