"""Identidad de personas: perfiles sociales, nombres y su relación con usuarios y correos (A2)."""
import json

import pytest

from osint_app.correlation_engine import CorrelationEngine, Entity, EntityExtractor
from osint_app.utils.identity import (
    find_profile_urls, handle_matches_name, looks_like_person_name, name_from_profile_title, parse_profile_url,
    profile_key,
)


# ── perfiles ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    ("https://www.linkedin.com/in/JPerez/", ("linkedin", "jperez", "https://linkedin.com/in/jperez")),
    ("https://ec.linkedin.com/in/jperez?trk=abc", ("linkedin", "jperez", "https://linkedin.com/in/jperez")),
    ("https://github.com/Torvalds/linux", ("github", "torvalds", "https://github.com/torvalds")),
    ("https://twitter.com/dan_abramov/status/1", ("x", "dan_abramov", "https://x.com/dan_abramov")),
    ("https://mobile.twitter.com/dan_abramov", ("x", "dan_abramov", "https://x.com/dan_abramov")),
    ("https://x.com/dan_abramov", ("x", "dan_abramov", "https://x.com/dan_abramov")),
    ("https://www.instagram.com/maria.lopez/", ("instagram", "maria.lopez", "https://instagram.com/maria.lopez")),
    ("https://www.facebook.com/juan.perez.123", ("facebook", "juan.perez.123", "https://facebook.com/juan.perez.123")),
    ("https://www.facebook.com/profile.php?id=100012345", ("facebook", "id100012345", "https://facebook.com/id100012345")),
    ("https://www.tiktok.com/@maria_l", ("tiktok", "maria_l", "https://tiktok.com/@maria_l")),
    ("https://www.youtube.com/@canalx", ("youtube", "canalx", "https://youtube.com/@canalx")),
    ("https://t.me/mi_usuario", ("telegram", "mi_usuario", "https://t.me/mi_usuario")),
    ("https://www.reddit.com/user/spez", ("reddit", "spez", "https://reddit.com/user/spez")),
    ("linkedin.com/in/jperez", ("linkedin", "jperez", "https://linkedin.com/in/jperez")),
])
def test_parse_profile_url(url, expected):
    assert parse_profile_url(url) == expected


@pytest.mark.parametrize("url", [
    "", "https://github.com/search?q=x", "https://github.com/orgs/acme", "https://x.com/search", "https://x.com/i/status/1",
    "https://www.linkedin.com/company/acme", "https://www.linux.com/news", "https://box.com/x", "https://netflix.com/title/1",
    "https://www.facebook.com/sharer/sharer.php?u=x", "https://www.instagram.com/p/ABC123/", "https://gist.github.com/u/1",
    "https://evil.com/linkedin.com/in/x", "https://t.me/joinchat/ABC", "no es url",
])
def test_not_a_profile(url):
    assert parse_profile_url(url) is None


def test_equivalent_profile_urls_share_a_key():
    keys = {profile_key(u) for u in ("https://twitter.com/Dan_Abramov", "http://www.x.com/dan_abramov/", "x.com/dan_abramov?s=20")}
    assert keys == {"x.com/dan_abramov"}


def test_find_profile_urls_in_free_text():
    text = "Mira https://github.com/jperez, su LinkedIn linkedin.com/in/jperez/ y (https://twitter.com/jperez). Repite github.com/jperez"
    got = [p[2] for p in find_profile_urls(text)]
    assert got == ["https://github.com/jperez", "https://linkedin.com/in/jperez", "https://x.com/jperez"]
    assert find_profile_urls("compra en box.com/x y linux.com/news") == []


# ── nombres ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("title,platform,name", [
    ("Juan Pérez - Ingeniero de Software - UTPL | LinkedIn", "linkedin", "Juan Pérez"),
    ("Dan Abramov (@dan_abramov) / X", "x", "Dan Abramov"),
    ("Maria Lopez (@maria.lopez) • Instagram photos and videos", "instagram", "Maria Lopez"),
    ("GitHub: Linus Torvalds", "github", ""),          # en GitHub el nombre sale del campo estructurado, no del título
    ("Juan Perez | Facebook", "facebook", "Juan Perez"),
    ("Replies by Linus Torvalds (@Linus__Torvalds) / X", "x", "Linus Torvalds"),          # hallado con una búsqueda real
    ("Posts by Maria Lopez (@marial) / X", "x", "Maria Lopez"),
    ("Publicaciones de María Pérez | Facebook", "facebook", "María Pérez"),
    ("LinkedIn", "linkedin", ""), ("Iniciar sesión | Facebook", "facebook", ""), ("jperez", "github", ""),
    ("Perfil de usuario - LinkedIn", "linkedin", ""), ("", "", ""), ("Juan 123 - X", "x", ""),
])
def test_name_from_profile_title(title, platform, name):
    assert name_from_profile_title(title, platform) == name


@pytest.mark.parametrize("text,ok", [
    ("Juan Pérez", True), ("Ana María de los Ángeles Pérez", False), ("María José Peña Mora", True),
    ("Juan", False), ("Juan 2", False), ("LinkedIn Perfil", False), ("a b c d e f", False),
])
def test_looks_like_person_name(text, ok):
    assert looks_like_person_name(text) is ok


@pytest.mark.parametrize("handle,name,ok", [
    ("jriofrio", "Juan Riofrio", True), ("juan.riofrio", "Juan Riofrio", True), ("riofrio.juan", "Juan Riofrio", True),
    ("juanriofrio", "Juan Riofrio", True), ("riofrioj", "Juan Riofrio", True), ("@jriofrio", "Juan Riofrio", True),
    ("jriofrio+tag", "Juan Riofrio", True), ("jperez", "Juan Carlos Pérez Mora", True), ("jmora", "Juan Carlos Pérez Mora", True), ("jgomez", "Juan Carlos Pérez Mora", False),
    ("riofrio", "Juan Riofrio", True),            # apellido largo solo
    ("juan", "Juan Riofrio", False),              # nombre corto solo: ambiguo
    ("jriofrio99", "Juan Riofrio", True), ("juan.riofrio2006", "Juan Riofrio", True), ("riofrio2006", "Juan Riofrio", True),
    ("riofrioj06", "Juan Riofrio", True),         # un año o número al final no cambia de quién es el usuario
    ("juan2006", "Juan Riofrio", False), ("2006", "Juan Riofrio", False), ("jriofrio_dev", "Juan Riofrio", False),
    ("jriofrio12345", "Juan Riofrio", False),     # más de 4 dígitos: ya no parece un año
    ("maria", "Juan Riofrio", False), ("admin", "Juan Riofrio", False), ("", "Juan Riofrio", False), ("jriofrio", "Juan", False),
])
def test_handle_matches_name(handle, name, ok):
    assert handle_matches_name(handle, name) is ok


# ── extracción de entidades de identidad ─────────────────────────────────────

def test_extract_finds_profiles_in_text():
    found = [(e.entity_type, e.value) for e in EntityExtractor.extract("ver https://linkedin.com/in/jperez y github.com/jperez", "t")]
    assert ("profile", "https://linkedin.com/in/jperez") in found and ("profile", "https://github.com/jperez") in found


def test_extract_identity_from_github_profile_result():
    item = {"title": "GitHub: Kent C. Dodds", "url": "https://github.com/kentcdodds", "category": "GitHub Profile",
            "extra_data": {"name": "Kent C. Dodds", "company": "@epicweb-dev", "location": "Utah, USA", "twitter": "kentcdodds"}}
    got = {(e.entity_type, e.value) for e in EntityExtractor.extract_identity(item, "GitHubOSINT")}
    assert got == {("profile", "https://github.com/kentcdodds"), ("name", "Kent C. Dodds"), ("company", "epicweb-dev"),
                   ("location", "Utah, USA"), ("profile", "https://x.com/kentcdodds")}


def test_extract_identity_name_from_search_title_and_ignores_non_profiles():
    item = {"title": "Juan Pérez - Ingeniero - UTPL | LinkedIn", "url": "https://ec.linkedin.com/in/jperez", "category": "LinkedIn"}
    names = [e for e in EntityExtractor.extract_identity(item, "WebSearch") if e.entity_type == "name"]
    assert len(names) == 1 and names[0].value == "Juan Pérez" and names[0].source == "WebSearch @ https://linkedin.com/in/jperez"
    assert EntityExtractor.extract_identity({"title": "Juan Pérez - Noticias", "url": "https://diario.com/n/1"}, "t") == []


# ── relaciones ───────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    eng = CorrelationEngine.__new__(CorrelationEngine)
    eng.entities, eng.correlations = {}, []
    return eng


def rel(engine, a, b):
    c = engine._check_correlation(a, b)
    return (c.relation_type, c.confidence) if c else None


def P(url):
    return Entity("profile", parse_profile_url(url)[2], "t")


def test_same_handle_across_platforms(engine):
    assert rel(engine, P("https://github.com/kentcdodds"), P("https://x.com/kentcdodds")) == ("same_handle", 70)
    assert rel(engine, P("https://x.com/kentcdodds"), P("https://github.com/kentcdodds")) == ("same_handle", 70)    # simétrica
    assert rel(engine, P("https://github.com/abc"), P("https://x.com/abc")) is None                                # muy corto
    assert rel(engine, P("https://github.com/kentcdodds"), P("https://x.com/otro_usuario")) is None


def test_profile_relations_with_username_and_email(engine):
    assert rel(engine, P("https://github.com/jriofrio"), Entity("username", "@jriofrio", "t")) == ("profile_of", 90)
    assert rel(engine, P("https://github.com/jriofrio"), Entity("email", "jriofrio@gmail.com", "t")) == ("same_person", 60)
    assert rel(engine, P("https://github.com/admin1"), Entity("email", "admin1@x.com", "t")) == ("same_person", 60)
    assert rel(engine, P("https://github.com/info"), Entity("email", "info@x.com", "t")) is None                   # buzón de rol
    assert rel(engine, P("https://github.com/otra"), Entity("username", "@jriofrio", "t")) is None


def test_name_found_in_profile_is_linked_to_that_profile_only(engine):
    name = Entity("name", "Juan Pérez", "WebSearch @ https://linkedin.com/in/jperez")
    assert rel(engine, P("https://www.linkedin.com/in/jperez"), name) == ("named_in", 85)
    assert rel(engine, P("https://github.com/jperez"), name) is None


def test_names_relations(engine):
    assert rel(engine, Entity("name", "Juan Pérez", "seed"), Entity("name", "Juan Carlos Perez Mora", "t")) == ("same_name", 60)
    assert rel(engine, Entity("name", "Juan Pérez", "seed"), Entity("name", "Pedro Pérez", "t")) is None
    assert rel(engine, Entity("name", "Juan Riofrio", "seed"), Entity("email", "jriofrio@utpl.edu.ec", "t")) == ("name_in_handle", 65)
    assert rel(engine, Entity("name", "Juan Riofrio", "seed"), Entity("username", "@juan.riofrio", "t")) == ("name_in_handle", 55)
    assert rel(engine, Entity("name", "Juan Riofrio", "seed"), Entity("email", "info@utpl.edu.ec", "t")) is None


def test_same_person_different_accents_is_one_entity():
    assert Entity("name", "José Muñoz", "a").fingerprint() == Entity("name", "jose munoz", "b").fingerprint()
    assert Entity("company", "UTPL", "a").fingerprint() == Entity("company", "utpl", "b").fingerprint()


# ── persistencia y aislamiento de lo descubierto ─────────────────────────────

def test_found_identity_is_stored_apart_and_restored(temp_db):
    from osint_app.case_manager import CaseManager
    from osint_app.core.models import QueryParameters, TargetData
    case = CaseManager().create("t", "")
    temp_db.add_target_data(TargetData(case_id=case.id, field_type="name", value="Juan Riofrio", source="seed", confidence=100))
    temp_db.add_target_data(TargetData(case_id=case.id, field_type="username", value="jriofrio", source="seed", confidence=100))
    eng = CorrelationEngine(case.id)
    eng.process_tool_results("WebSearch", json.dumps([
        {"title": "Pedro Gomez - Gerente | LinkedIn", "url": "https://linkedin.com/in/pgomez", "category": "LinkedIn"},
        {"title": "GitHub: Juan Riofrio", "url": "https://github.com/jriofrio", "category": "GitHub Profile",
         "extra_data": {"name": "Juan Riofrio", "company": "UTPL", "location": "Loja, Ecuador"}}]))

    stored = {(d.field_type, d.value) for d in temp_db.get_target_data(case.id)}
    assert ("found_name", "Pedro Gomez") in stored and ("found_profile", "https://github.com/jriofrio") in stored
    assert ("name", "Pedro Gomez") not in stored                                    # no se mezcla con los datos del investigador

    params = QueryParameters.from_target_data(temp_db.get_target_data(case.id))
    assert params.target_name == "Juan Riofrio"                                     # lo hallado no cambia el objetivo

    again = CorrelationEngine(case.id)                                              # reabrir el caso
    assert {"profile", "name", "company", "location", "username"} <= {e.entity_type for e in again.entities.values()}
    kinds = {c.relation_type for c in again.correlations}
    assert {"profile_of", "named_in", "name_in_handle"} <= kinds
    github_profile = "https://github.com/jriofrio"
    assert not any(c.relation_type == "named_in" and c.entity_a.value == github_profile and c.entity_b.value == "Pedro Gomez"
                   for c in again.correlations)


# ── errores hallados con una cuenta real de GitHub ───────────────────────────

def test_github_tool_generated_titles_are_not_names():
    for title in ("Lenguajes principales de kentcdodds", "Actividad reciente de kentcdodds", "Temas/Topics de kentcdodds", "GitHub: Kent C. Dodds"):
        item = {"title": title, "url": "https://github.com/kentcdodds", "category": "GitHub Analysis"}
        assert [e for e in EntityExtractor.extract_identity(item, "GitHubOSINT") if e.entity_type == "name"] == []
    assert name_from_profile_title("GitHub: Kent C. Dodds", "github") == ""        # en GitHub el nombre sale solo del campo estructurado


def test_title_containing_the_handle_is_not_a_name():
    assert name_from_profile_title("Resumen de jperez en X", "x", "jperez") == ""
    assert name_from_profile_title("Juan Perez - Ingeniero | LinkedIn", "linkedin", "jperez") == "Juan Perez"
    assert name_from_profile_title("Maria Lopez | Facebook", "facebook", "marialopez") == "Maria Lopez"      # el usuario no es una palabra del nombre


def test_username_is_not_truncated_at_a_hyphen():
    found = {e.value for e in EntityExtractor.extract("Empresa: @epicweb-dev | contacto @juanito y (@maria_99)", "t") if e.entity_type == "username"}
    assert found == {"@juanito", "@maria_99"}
