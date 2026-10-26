"""Señales graduadas de homónimo (A6): país vecino, ciudades, LinkedIn y extensión de otro país."""
import pytest

from osint_app.core.models import SearchResult
from osint_app.profiler_engine import ProfilerEngine, SeedData, ToolResult
from osint_app.utils import homonyms
from osint_app.utils.homonyms import homonym_signals, total_penalty, warning_text


def codes(text, country="Ecuador", url="", context=""):
    return [s.code for s in homonym_signals(text, url, country, context)]


# ── reconocer el país del objetivo ───────────────────────────────────────────

@pytest.mark.parametrize("country,code", [
    ("Ecuador", "ec"), ("ecuador", "ec"), ("Ecuador, Quito", "ec"), ("PERÚ", "pe"), ("México", "mx"),
    ("España", "es"), ("USA", "us"), ("Canadá", ""), ("", ""), ("Marte", ""),
])
def test_country_code(country, code):
    assert homonyms.country_code(country) == code


# ── señales ──────────────────────────────────────────────────────────────────

def test_strong_signal_is_unchanged():
    sig = homonym_signals("Juan Perez - Madrid, Spain", "", "Ecuador")
    assert sig[0].code == "country" and sig[0].penalty == homonyms.STRONG_PENALTY
    assert sig[0].message == homonyms.homonym_warning("Juan Perez - Madrid, Spain", "Ecuador")


@pytest.mark.parametrize("text,expected", [
    ("Juan Perez, Lima Peru", ["neighbor_country"]),                  # país vecino
    ("Perfil en Bogotá, Colombia", ["neighbor_country"]),             # el caso que el detector estricto no marca
    ("Ingeniero en Medellín", ["foreign_city"]),                      # solo la ciudad
    ("Trabaja en Miami", ["foreign_city"]),                           # ciudad de fuera de Latinoamérica
    ("Vive en Buenos Aires", ["foreign_city"]),
])
def test_neighbor_country_and_foreign_city(text, expected):
    assert codes(text) == expected


def test_foreign_city_penalties_differ_by_region():
    assert homonym_signals("Medellín", "", "Ecuador")[0].penalty == homonyms.CITY_LATAM_PENALTY
    assert homonym_signals("Miami", "", "Ecuador")[0].penalty == homonyms.CITY_OTHER_PENALTY


@pytest.mark.parametrize("text", [
    "Juan Perez - Quito, Ecuador", "Ingeniero en Guayaquil", "Perfil en Bogotá, Colombia y Quito, Ecuador",   # ligado al objetivo
    "Estudió en Quito y trabajó en Bogotá",                                                                    # ciudad propia
    "Juan Mendoza, ingeniero", "María Rosario Zamora Salinas", "Carlos Ibarra Quevedo", "Luis Pereira Trujillo",   # apellidos
    "la lima y la manta del cuarto", "el pasto está verde", "salta y salto",                                   # palabras comunes
    "Orlando Paris Roma", "Sevilla Granada",                                                                   # nombres propios
    "viaje a quito", "bogota bogota",                                                                          # sin mayúscula: no cuenta
    "Valencia, Córdoba, León, Mérida, Santiago, Cuenca",                                                       # ambiguas: excluidas
])
def test_no_signal_for_traps_and_own_country(text):
    assert codes(text) == []


def test_weak_signals_need_a_known_target_country():
    assert codes("Juan Perez en Bogotá", country="") == []
    assert codes("Juan Perez en Bogotá", country="Marte") == []
    assert codes("Perfil de Madrid, Spain", country="Marte") == ["country"]    # solo la señal fuerte: no hay ciudad que comparar


def test_other_city_of_same_country_is_a_weak_hint():
    sig = homonym_signals("Juan Perez en Guayaquil", "", "Ecuador", "Ingeniero de la UTPL en Loja")
    assert [s.code for s in sig] == ["other_city"] and sig[0].penalty == homonyms.OTHER_CITY_PENALTY
    assert "loja" in sig[0].message and "guayaquil" in sig[0].message
    assert codes("Juan Perez en Loja y Guayaquil", context="vive en Loja") == []     # menciona también la ciudad del contexto
    assert codes("Juan Perez en Guayaquil") == []                                    # sin contexto no hay con qué comparar


@pytest.mark.parametrize("url,expected", [
    ("https://co.linkedin.com/in/jperez", ["linkedin_country"]),
    ("https://pe.linkedin.com/in/jperez", ["linkedin_country"]),
    ("https://ec.linkedin.com/in/jperez", []),                         # el del objetivo
    ("https://www.linkedin.com/in/jperez", []),
    ("https://empresa.com.mx/equipo", ["tld"]), ("https://sitio.es/perfil", ["tld"]),
    ("https://empresa.com.ec/equipo", []), ("https://empresa.com/x", []), ("https://t.co/abc", []), ("https://youtu.be/x", []),
])
def test_url_signals(url, expected):
    assert codes("Juan Perez", url=url) == expected


def test_strong_country_and_its_city_are_not_counted_twice():
    sig = homonym_signals("Juan Perez - Madrid, Spain", "", "Ecuador")
    assert [s.code for s in sig] == ["country"] and total_penalty(sig) == homonyms.STRONG_PENALTY


def test_signals_add_up_and_penalty_is_capped():
    sig = homonym_signals("Juan Perez en Bogotá, Colombia", "https://co.linkedin.com/in/jp", "Ecuador")
    assert {s.code for s in sig} == {"neighbor_country", "linkedin_country"} and total_penalty(sig) == 35
    many = homonym_signals("Madrid, Spain", "https://pe.linkedin.com/in/jp", "Ecuador")      # país ajeno + LinkedIn de otro país
    assert total_penalty(many) == 50 - 10 and total_penalty(many) <= homonyms.MAX_PENALTY
    cap = homonyms.total_penalty([homonyms.Signal("a", "", 30.0), homonyms.Signal("b", "", 30.0)])
    assert cap == homonyms.MAX_PENALTY
    assert warning_text([]) == "" and total_penalty([]) == 0


# ── métrica etiquetada (regresión) ───────────────────────────────────────────

# (texto, url, país, contexto, debe_marcarse). Objetivo típico: persona de Ecuador.
LABELLED = [
    # homónimos con señal débil que el detector estricto NO marcaba
    ("Juan Perez - Bogotá, Colombia", "", "Ecuador", "", True),
    ("Ingeniero en Lima", "", "Ecuador", "", True),
    ("Gerente en Santiago de Chile", "", "Ecuador", "", True),
    ("Médico en Medellín", "", "Ecuador", "", True),
    ("Perfil profesional", "https://pe.linkedin.com/in/juan-perez-123", "Ecuador", "", True),
    ("Perfil profesional", "https://co.linkedin.com/in/juanperez", "Ecuador", "", True),
    ("Director en Monterrey", "", "Ecuador", "", True),
    ("Abogado", "https://estudio.com.ar/equipo/juan-perez", "Ecuador", "", True),
    ("Juan Perez en Guayaquil", "", "Ecuador", "Ingeniero en Loja", True),
    ("Lives in Miami", "", "Ecuador", "", True),
    # buenos candidatos: NO deben marcarse
    ("Juan Perez - Quito, Ecuador", "https://ec.linkedin.com/in/juan-perez", "Ecuador", "", False),
    ("Ingeniero de software", "https://www.linkedin.com/in/jperez", "Ecuador", "", False),
    ("Juan Mendoza, gerente", "", "Ecuador", "", False),
    ("Carlos Zamora Ibarra, contador", "", "Ecuador", "", False),
    ("María Rosario Pereira", "", "Ecuador", "", False),
    ("Profesor en la UDLA, Quito", "", "Ecuador", "", False),
    ("Trabajó en Quito y Bogotá", "", "Ecuador", "", False),
    ("Consultor", "https://empresa.com.ec/equipo", "Ecuador", "", False),
    ("Estudia en la ESPOL en Guayaquil", "", "Ecuador", "Estudiante en Guayaquil", False),
    ("Perfil de Juan en la Mendoza S.A.", "", "Ecuador", "", False),
]


def test_graded_signals_metrics(capsys):
    tp = fp = tn = fn = 0
    wrong = []
    for text, url, country, context, should in LABELLED:
        flagged = bool(homonym_signals(text, url, country, context))
        tp += should and flagged
        fn += should and not flagged
        fp += (not should) and flagged
        tn += (not should) and not flagged
        if flagged != should:
            wrong.append((text, url, should))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    with capsys.disabled():
        print("\n=== MÉTRICA HOMÓNIMOS (señales graduadas) ===")
        print(f"Casos: {len(LABELLED)} | TP={tp} FP={fp} TN={tn} FN={fn} | Precisión {precision:.0%} | Recall {recall:.0%}")
    assert not wrong, f"mal clasificados: {wrong}"


# ── integración con el perfilador ────────────────────────────────────────────

def _engine(results):
    eng = ProfilerEngine()
    eng.results = [ToolResult("T", "ok", results)]
    return eng


def _sr(title, url="", snippet=""):
    return SearchResult(title=title, url=url, snippet=snippet, source_tool="T", category="Web", relevance_score=80)


def test_profiler_penalizes_and_explains_weak_signals_without_dropping():
    seed = SeedData(name="Juan Perez", country="Ecuador")
    eng = _engine([_sr("Juan Perez - Ingeniero", "https://co.linkedin.com/in/jperez", "Juan Perez en Bogotá, Colombia"),
                   _sr("Juan Perez - Ingeniero", "https://ec.linkedin.com/in/jperez", "Juan Perez en Quito, Ecuador")])
    cands = {c.url: c for c in eng.extract_candidates(seed)}
    foreign, own = cands["https://co.linkedin.com/in/jperez"], cands["https://ec.linkedin.com/in/jperez"]
    assert own.warning == "" and "LinkedIn de colombia" in foreign.warning and "menciona colombia" in foreign.warning
    assert foreign.confidence == 40 - 35 and foreign.confidence > 0               # nombre 40 menos 35: baja, no se descarta
    assert own.confidence == 50


def test_strong_penalty_is_unchanged_in_profiler():
    seed = SeedData(name="Juan Perez", country="Ecuador")
    sig = _engine([_sr("Juan Perez - Madrid, Spain", "https://x.com/a")]).extract_candidates(seed)[0]
    base = _engine([_sr("Juan Perez - Quito", "https://x.com/b")]).extract_candidates(seed)[0]
    assert "spain" in sig.warning and sig.confidence == base.confidence - ProfilerEngine.HOMONYM_PENALTY


def test_company_corroborates_the_person():
    eng = ProfilerEngine()
    r = _sr("Juan Perez - Gerente en Banco Pichincha", "https://a.com")
    with_company = eng._calculate_confidence(r, SeedData(name="Juan Perez", company="Banco Pichincha"))
    without = eng._calculate_confidence(r, SeedData(name="Juan Perez"))
    assert with_company[0] == without[0] + 15 and "company" in with_company[1]
    other = eng._calculate_confidence(r, SeedData(name="Juan Perez", company="Produbanco"))
    assert "company" not in other[1]
    assert "company" not in eng._calculate_confidence(r, SeedData(name="Juan Perez", company="Ban"))[1]       # nombre demasiado corto


def test_distinctive_alias_ties_the_text_to_the_target():
    # Caso real #27: Forbes Colombia sobre Luisito Comunica iba a "otra persona" por "menciona Colombia"
    title = "Top Creators 2024 | 'Luisito Comunica' - Forbes Colombia"
    url = "https://forbes.co/2024/12/13/editors-picks/top-creators-2024-luisito-comunica/"
    assert homonym_signals(title, url, "México") != []                                   # sin alias: avisa
    assert homonym_signals(title, url, "México", aliases=["Luisito Comunica"],
                           name="Luis Arturo Villar Sudek") == []


def test_alias_must_be_distinctive_to_tie():
    text = "Luis Villar, abogado de Bogotá, Colombia"
    # un alias de una palabra o contenido en el nombre legal no liga: hay homónimos con ese nombre
    assert homonym_signals(text, "", "México", aliases=["Luis"], name="Luis Arturo Villar Sudek") != []
    assert homonym_signals(text, "", "México", aliases=["Luis Villar"], name="Luis Villar Sudek") != []
