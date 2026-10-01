"""M3: lo que aporta un candidato confirmado pasa al caso y enriquece la búsqueda."""
from types import SimpleNamespace

import pytest

from osint_app.core.models import QueryParameters, TargetData
from osint_app.correlation_engine import CorrelationEngine
from osint_app.profiler_engine import (
    SeedData, enrich_seed_from_candidates, identity_from_candidate, promote_confirmed_to_case,
)

GITHUB = {"url": "https://github.com/kentcdodds", "title": "GitHub: Kent C. Dodds", "snippet": "", "source": "GitHubOSINT",
          "extra": {"name": "Kent C. Dodds", "company": "@epicweb-dev ", "location": "Utah, USA", "twitter": "kentcdodds"}}
LINKEDIN = {"url": "https://ec.linkedin.com/in/jperez", "title": "Juan Pérez - Ingeniero | LinkedIn", "snippet": "", "source": "WebSearch"}


# ── qué aporta un candidato ──────────────────────────────────────────────────

def test_identity_from_github_candidate():
    assert identity_from_candidate(GITHUB) == {
        "profile": "https://github.com/kentcdodds", "username": "kentcdodds", "name": "Kent C. Dodds",
        "company": "epicweb-dev", "location": "Utah, USA"}


def test_identity_from_linkedin_candidate_has_no_username():
    found = identity_from_candidate(LINKEDIN)
    assert found == {"profile": "https://linkedin.com/in/jperez", "name": "Juan Pérez"}      # el id de LinkedIn no es un usuario


@pytest.mark.parametrize("url,username", [
    ("https://x.com/dan_abramov", "dan_abramov"), ("https://www.instagram.com/maria.l/", "maria.l"),
    ("https://www.tiktok.com/@maria_l", "maria_l"), ("https://www.reddit.com/user/spez", "spez"),
    ("https://www.youtube.com/channel/UC123", None),                       # id de canal: no es un usuario
])
def test_username_from_other_platforms(url, username):
    assert identity_from_candidate({"url": url}).get("username") == username


def test_identity_email_rules():
    assert identity_from_candidate({"snippet": "escribe a juan@empresa.com"})["email"] == "juan@empresa.com"
    assert "email" not in identity_from_candidate({"snippet": "ventas@empresa.com info@empresa.com"})        # correos de rol
    assert "email" not in identity_from_candidate({"snippet": "logo@2x.png"})                                  # no es un correo
    assert identity_from_candidate({"snippet": "info@a.com y maria.lopez@a.com"})["email"] == "maria.lopez@a.com"
    assert identity_from_candidate({}) == {} and identity_from_candidate({"url": "https://diario.com/n/1"}) == {}


# ── enriquecer la semilla ────────────────────────────────────────────────────

def test_enrich_takes_company_and_other_platform_username():
    out = enrich_seed_from_candidates(SeedData(name="Kent"), [GITHUB])
    assert out.username == "kentcdodds" and out.company == "epicweb-dev"
    out = enrich_seed_from_candidates(SeedData(name="Dan"), [{"url": "https://x.com/dan_abramov"}])
    assert out.username == "dan_abramov"


def test_enrich_does_not_take_a_free_mail_provider_as_the_domain():
    assert enrich_seed_from_candidates(SeedData(name="Juan"), [{"snippet": "juan.perez@gmail.com"}]).domain is None   # antes: gmail.com
    out = enrich_seed_from_candidates(SeedData(name="Juan"), [{"snippet": "juan.perez@utpl.edu.ec"}])
    assert out.email == "juan.perez@utpl.edu.ec" and out.domain == "utpl.edu.ec"


def test_enrich_never_overwrites_company():
    out = enrich_seed_from_candidates(SeedData(name="Kent", company="Mi Empresa"), [GITHUB])
    assert out.company == "Mi Empresa"


# ── pasar al caso ────────────────────────────────────────────────────────────

@pytest.fixture
def case(temp_db):
    from osint_app.case_manager import CaseManager
    c = CaseManager().create("t", "")
    for ft, v in (("name", "Kent C. Dodds"), ("username", "@someone")):
        temp_db.add_target_data(TargetData(case_id=c.id, field_type=ft, value=v, source="seed", confidence=100))
    return c


def _stored(temp_db, case_id):
    return {(d.field_type, d.value, d.source, d.confidence) for d in temp_db.get_target_data(case_id)}


def test_promotion_adds_confirmed_data_with_provenance(temp_db, case):
    added = promote_confirmed_to_case(case.id, [GITHUB])
    assert dict(added) == {"profile": "https://github.com/kentcdodds", "username": "kentcdodds",
                           "company": "epicweb-dev", "location": "Utah, USA"}          # el nombre ya estaba: no se repite
    stored = _stored(temp_db, case.id)
    assert ("company", "epicweb-dev", "confirmado", 90) in stored and ("profile", "https://github.com/kentcdodds", "confirmado", 90) in stored


def test_promotion_is_idempotent_and_ignores_case_and_accents(temp_db, case):
    promote_confirmed_to_case(case.id, [GITHUB])
    assert promote_confirmed_to_case(case.id, [GITHUB]) == []
    twin = dict(GITHUB, extra={"name": "kent c dodds", "company": "EPICWEB-DEV", "location": "utah, usa"}, url="https://www.github.com/KentCDodds/")
    assert promote_confirmed_to_case(case.id, [twin]) == []
    assert promote_confirmed_to_case(case.id, [{"url": "https://x.com/someone"}]) == [("profile", "https://x.com/someone")]   # @someone ya estaba


def test_promotion_does_not_change_the_target_of_other_tools(temp_db, case):
    promote_confirmed_to_case(case.id, [LINKEDIN, GITHUB])
    params = QueryParameters.from_target_data(temp_db.get_target_data(case.id))
    assert params.target_name == "Kent C. Dodds"                   # una variante de nombre confirmada no sustituye al objetivo
    assert params.company == "epicweb-dev" and params.location == "Utah, USA"     # la empresa y la ubicación confirmadas sí se usan


def test_confirmed_value_is_added_even_if_only_found_before(temp_db, case):
    temp_db.add_target_data(TargetData(case_id=case.id, field_type="found_company", value="epicweb-dev", source="GitHubOSINT", confidence=55))
    assert ("company", "epicweb-dev") in promote_confirmed_to_case(case.id, [GITHUB])          # confirmar lo convierte en dato del caso


def test_promoted_profile_is_correlated_with_the_case(temp_db, case):
    promote_confirmed_to_case(case.id, [{"url": "https://x.com/someone"}, {"url": "https://github.com/someone"}])
    kinds = {c.relation_type for c in CorrelationEngine(case.id).correlations}
    assert {"profile_of", "same_handle"} <= kinds


# ── el botón Confirmar de la interfaz ────────────────────────────────────────

def _profiling_tab_class():
    """La clase de la pestaña, o salta la prueba si la parte gráfica no está disponible (p. ej. un servidor sin pantalla)."""
    pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    try:
        from osint_app.gui.tab_profiling import ProfilingTab
    except ImportError as e:
        pytest.skip(f"interfaz no disponible: {e}")
    return ProfilingTab


def _tab(case_id):
    logs, refreshed = [], []
    pages = [("Datos", SimpleNamespace(refresh=lambda: refreshed.append("Datos"))), ("Reportes", SimpleNamespace(refresh=lambda: refreshed.append("R")))]
    return SimpleNamespace(app=SimpleNamespace(active_case_id=case_id, pages=pages), _log=logs.append), logs, refreshed


def test_confirm_button_handler_promotes_and_refreshes(temp_db, case):
    ProfilingTab = _profiling_tab_class()
    tab, logs, refreshed = _tab(case.id)
    ProfilingTab._promote_to_case(tab, GITHUB)
    assert any("Añadido al caso" in m and "username=kentcdodds" in m for m in logs) and refreshed == ["Datos"]
    assert ("username", "kentcdodds", "confirmado", 90) in _stored(temp_db, case.id)


def test_confirm_button_handler_is_safe_without_case_or_on_error(temp_db):
    ProfilingTab = _profiling_tab_class()
    tab, logs, _ = _tab(None)
    ProfilingTab._promote_to_case(tab, GITHUB)
    assert logs == []                                                  # sin caso activo no hace nada
    tab, logs, _ = _tab(999999)                                        # caso inexistente: no debe romper la interfaz
    ProfilingTab._promote_to_case(tab, {"url": "https://x.com/someone"})
    assert all("Traceback" not in m for m in logs)
