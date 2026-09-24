"""Señales de homónimo compartidas (utils/homonyms)."""
import pytest

from osint_app.utils import homonyms


@pytest.mark.parametrize("location,country,expected", [
    ("Madrid, Spain", "Ecuador", "spain"),
    ("San Francisco, USA", "Ecuador", "usa"),
    ("Quito, Ecuador", "Ecuador", None),      # mismo país, no es señal
    ("Madrid, España", "España", None),       # el país esperado ES España
    ("", "Ecuador", None),
])
def test_different_country(location, country, expected):
    assert homonyms.different_country(location, country) == expected


def test_is_same_region():
    assert homonyms.is_same_region("Quito, Ecuador", "Colombia") is True
    assert homonyms.is_same_region("Madrid, Spain", "Ecuador") is False


def test_homonym_warning_text():
    w = homonyms.homonym_warning("Perfil de Madrid, Spain", "Ecuador")
    assert w and "spain" in w.lower() and "Ecuador" in w


def test_homonym_warning_none_without_country():
    assert homonyms.homonym_warning("Madrid, Spain", "") is None


def test_smart_profiler_still_uses_shared_logic():
    # Regresión: smart_profiler delega en el módulo compartido sin cambiar
    # su comportamiento.
    from osint_app.smart_profiler import SmartProfiler
    sp = SmartProfiler.__new__(SmartProfiler)
    assert sp._is_different_country("madrid, spain", "ecuador") is True
    assert sp._is_different_country("quito, ecuador", "ecuador") is False
