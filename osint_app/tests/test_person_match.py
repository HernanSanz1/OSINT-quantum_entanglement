"""Comparación de nombres, teléfonos, usuarios y URLs (nombres hispanos)."""
import pytest

from osint_app.core.models import SearchResult
from osint_app.profiler_engine import ProfilerEngine, SeedData, ToolResult
from osint_app.utils.person_match import (
    name_match, name_tokens, normalize_text, normalize_url, phone_in_text, phone_key, username_in_text,
)


def test_normalize_text_strips_accents_and_symbols():
    assert normalize_text("  José Muñoz-Peña, S.A. ") == "jose munoz pena s a"
    assert normalize_text(None) == ""


def test_name_tokens_drop_particles_and_short_words():
    assert name_tokens("María de los Ángeles Pérez") == ["maria", "angeles", "perez"]


@pytest.mark.parametrize("name,text,points,kind", [
    ("Ana Paz", "Perfil de Mariana Pazmiño", 0, ""),                  # subcadena: no cuenta
    ("José Muñoz", "perfil de jose munoz", 40, "name"),               # sin tildes
    ("Riofrio Juan", "Juan Riofrio, ingeniero", 40, "name"),          # orden apellido-nombre
    ("Juan Pérez Mora", "Juan Perez en Quito", 25, "name_partial"),   # sin el segundo apellido
    ("Juan Carlos Pérez Mora", "Juan Perez", 25, "name_partial"),
    ("Juan Pérez", "solo Pérez trabaja aquí", 10, ""),                # solo el apellido: 10
    ("Juan Pérez", "solo Juan trabaja aquí", 5, ""),                   # solo el nombre de pila: 5
    ("Juan Carlos Riofrio", "Pedro Carlos", 5, ""),                    # "Carlos" es el segundo nombre, no el apellido
    ("Juan Carlos Riofrio", "Pedro Riofrio", 10, ""),
    ("Juan Carlos Pérez Mora", "Pedro Mora", 10, ""), ("Juan Carlos Pérez Mora", "Pedro Pérez", 10, ""),    # 4 palabras: dos apellidos
    ("Juan Carlos Pérez Mora", "Pedro Carlos", 5, ""),
    ("Juan Pérez", "otra persona", 0, ""),
    ("", "Juan Pérez", 0, ""),
    ("Li Wu", "Li Wu", 0, ""),                                        # palabras demasiado cortas: sin datos
])
def test_name_match(name, text, points, kind):
    assert name_match(name, text) == (points, kind)


@pytest.mark.parametrize("phone,text,expected", [
    ("+593 98 765 4321", "contacto 098-765-4321", True),
    ("0987654321", "llámame al +593 98 765 4321", True),
    ("0987654321", "(593) 987654321", True),
    ("022551234", "tel 02-255-1234", True),
    ("0987654321", "id 1234567890123", False),
    ("0987654321", "0987654322", False),
    ("123", "123", False),                                            # demasiado corto
    ("", "0987654321", False),
])
def test_phone_in_text(phone, text, expected):
    assert phone_in_text(phone, text) is expected


def test_phone_key_ignores_prefix_and_zero():
    assert phone_key("+593 98 765 4321") == phone_key("0987654321") == phone_key("593987654321") == "987654321"


@pytest.mark.parametrize("user,text,expected", [
    ("ana", "perfil de ana en github", True), ("ana", "banana split", False), ("@jriofrio", "github.com/jriofrio/repo", True),
    ("jr", "jr", True), ("j.perez", "usuario j.perez activo", True), ("", "x", False),
])
def test_username_in_text(user, text, expected):
    assert username_in_text(user, text) is expected


def test_normalize_url_merges_equivalent_pages():
    same = [
        "https://www.linkedin.com/in/jperez", "https://linkedin.com/in/jperez/", "http://www.linkedin.com/in/jperez?trk=abc",
        "HTTPS://LinkedIn.com/in/jperez#about", "https://linkedin.com/in/jperez?utm_source=x&fbclid=1",
    ]
    assert len({normalize_url(u) for u in same}) == 1
    assert normalize_url("https://x.com/a?id=1") != normalize_url("https://x.com/a?id=2")      # parámetros reales cuentan
    assert normalize_url("https://x.com/Perez") != normalize_url("https://x.com/perez2")


# ── integración con el perfilador ────────────────────────────────────────────

def _engine(results):
    eng = ProfilerEngine()
    eng.results = [ToolResult("T", "ok", results)]
    return eng


def _sr(title, url="", snippet=""):
    return SearchResult(title=title, url=url, snippet=snippet, source_tool="T", relevance_score=80)


def test_candidates_dedupe_same_page_written_differently():
    eng = _engine([_sr("Juan Perez", "https://www.linkedin.com/in/jperez"), _sr("Juan Perez", "https://linkedin.com/in/jperez/"),
                   _sr("Juan Perez", "http://www.linkedin.com/in/jperez?trk=x")])
    assert len(eng.extract_candidates(SeedData(name="Juan Perez"))) == 1


def test_candidates_without_url_are_not_merged():
    eng = _engine([_sr("Juan Perez es ingeniero", snippet="a"), _sr("Juan Perez en Quito", snippet="b"), _sr("Juan Perez tiene correo", snippet="c")])
    assert len(eng.extract_candidates(SeedData(name="Juan Perez"))) == 3          # antes: 1


def test_substring_name_is_no_longer_a_candidate():
    eng = _engine([_sr("Perfil de Mariana Pazmiño", "https://x.com/mp")])
    assert eng.extract_candidates(SeedData(name="Ana Paz")) == []


def test_username_and_phone_in_scoring():
    eng = ProfilerEngine()
    r = _sr("banana split 098-765-4321", "https://a.com")
    score, matched = eng._calculate_confidence(r, SeedData(name="Zzz Qqq", username="ana", phone="+593 98 765 4321"))
    assert "phone" in matched and "username" not in matched
