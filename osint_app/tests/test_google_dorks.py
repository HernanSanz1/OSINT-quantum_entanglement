"""Generación de consultas de Google Dorks (sin red).

Cubre las búsquedas migradas del antiguo osint_collector_legacy:
reutilización de username, contexto limpio (sin agregadores) y registros EC.
"""
import pytest

from osint_app.core.models import QueryParameters
from osint_app.tools.google_dorks import (
    EC_REGISTRY_SITES, PEOPLE_SEARCH_NOISE, USERNAME_REUSE_SITES,
    GoogleDorksTool,
)


@pytest.fixture
def tool():
    return GoogleDorksTool()


def _by_intent(queries):
    out = {}
    for q in queries:
        out.setdefault(q["intent"], []).append(q["query"])
    return out


def test_username_reuse_across_platforms(tool):
    qs = _by_intent(tool._build_queries(QueryParameters(username="jperez")))
    reuse = " ".join(qs.get("Social/Username", []))
    assert '"jperez"' in reuse
    for site in USERNAME_REUSE_SITES:
        assert f"site:{site}" in reuse


def test_clean_context_excludes_people_search(tool):
    qs = _by_intent(tool._build_queries(
        QueryParameters(email="a@b.com", username="jperez")))
    clean = " ".join(qs.get("Identity/Clean", []))
    assert clean, "debe generar consultas de contexto limpio"
    for site in PEOPLE_SEARCH_NOISE:
        assert f"-site:{site}" in clean


def test_ecuador_registries_for_name_and_company(tool):
    qs = _by_intent(tool._build_queries(
        QueryParameters(target_name="Juan Perez", company="Mavesa")))
    ec = qs.get("Registros EC", [])
    assert len(ec) == 2  # una por nombre, otra por empresa
    joined = " ".join(ec)
    for site in EC_REGISTRY_SITES:
        assert f"site:{site}" in joined


def test_no_sensitive_category_dorks(tool):
    # Regresión: NO migrar dorks de categorías protegidas (LOPDP).
    qs = tool._build_queries(QueryParameters(
        target_name="Juan Perez", username="jperez", email="a@b.com"))
    blob = " ".join(q["query"].lower() for q in qs)
    for term in ("religion", "relig", "political", "politic", "medical",
                 "health", "salud", "dating", "divorce", "divorcio"):
        assert term not in blob, f"término sensible presente: {term}"


def test_budget_still_capped(tool):
    # Las consultas nuevas no deben romper el presupuesto máximo.
    qs = tool._build_queries(QueryParameters(
        target_name="Juan Perez", email="a@b.com", username="jperez",
        domain="x.com", company="Mavesa", phone="+593999999999"))
    assert len(qs) <= 25
