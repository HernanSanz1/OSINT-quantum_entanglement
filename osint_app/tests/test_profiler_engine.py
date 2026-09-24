"""ProfilerEngine y su interacción con las herramientas (sin red).

Integración 4.1: context/country llegan a las herramientas vía `observable`,
sin que SpiderFoot escanee ese texto libre como objetivo.
"""
import pytest

from osint_app.core.models import QueryParameters
from osint_app.profiler_engine import SeedData
from osint_app.tools.heavy_tools import SpiderFootTool, _looks_like_observable


# ── SeedData.to_query_params (bug 4) ──────────────────────────────────────────

def test_context_and_country_reach_observable():
    qp = SeedData(name="Juan Perez", context="UDLA Ecuador 2006",
                  country="Ecuador").to_query_params()
    assert qp.observable == "UDLA Ecuador 2006 Ecuador"
    assert qp.target_name == "Juan Perez"


def test_observable_empty_when_no_context():
    qp = SeedData(name="Juan Perez").to_query_params()
    assert qp.observable == ""


def test_other_fields_still_mapped():
    qp = SeedData(name="X", email="a@b.com", domain="b.com",
                  username="u", company="C", phone="+593999").to_query_params()
    assert (qp.email, qp.domain, qp.username, qp.company, qp.phone) == \
           ("a@b.com", "b.com", "u", "C", "+593999")


# ── _looks_like_observable ────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [
    ("example.com", True),
    ("8.8.8.8", True),
    ("juan@example.com", True),
    ("UDLA Ecuador 2006", False),   # texto libre con espacios
    ("Ecuador", False),             # una palabra que no es dominio/ip/email
    ("", False),
    ("juan@", False),               # email incompleto
])
def test_looks_like_observable(value, expected):
    assert _looks_like_observable(value) is expected


# ── SpiderFoot no escanea el contexto como objetivo ───────────────────────────

def test_spiderfoot_ignores_freetext_observable():
    # El perfilador pone el contexto en observable; SpiderFoot debe usar el
    # dominio, no "UDLA Ecuador 2006".
    qp = QueryParameters(target_name="Juan Perez", domain="example.com",
                         observable="UDLA Ecuador 2006")
    assert SpiderFootTool._pick_target(qp) == "example.com"


def test_spiderfoot_uses_real_observable():
    qp = QueryParameters(observable="target.com", domain="other.com")
    assert SpiderFootTool._pick_target(qp) == "target.com"


def test_spiderfoot_falls_back_to_name():
    qp = QueryParameters(target_name="Juan Perez", observable="contexto libre")
    assert SpiderFootTool._pick_target(qp) == "Juan Perez"
