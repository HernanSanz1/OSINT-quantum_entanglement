"""Papelera de homónimos (enfoque C, 04-11-2026): solo lo clarísimo sale de la tabla, con su motivo y recuperable."""
import pytest

from osint_app.utils.homonyms import Signal, trash_reason

COUNTRY = Signal("country", "posible homónimo: menciona «México» pero el objetivo es de Ecuador", 30)
JOB = Signal("other_job", "posible homónimo: su LinkedIn dice «Médico» y buscas a «futbolista»", 20)
PLACE = Signal("named_place", "parece un lugar con su nombre («Coliseo Jefferson Pérez»), no la persona", 25)
LINKEDIN = Signal("linkedin_country", "posible homónimo (señal débil): perfil de LinkedIn de España", 20)
NEIGHBOR = Signal("neighbor_country", "posible homónimo (señal débil): menciona Colombia; el objetivo es de Ecuador", 15)


@pytest.mark.parametrize("signal", [JOB, PLACE])
def test_strong_signal_without_ties_goes_to_the_trash(signal):
    reason = trash_reason([signal], ["name"])
    assert reason and reason.endswith("no coincide ningún otro dato del objetivo")
    assert not reason.startswith("posible homónimo")            # el motivo se lee sin la etiqueta técnica


@pytest.mark.parametrize("tie", ["email", "username", "username_chained", "mention", "phone", "domain", "company",
                                 "university", "context", "city"])
def test_any_tie_to_the_target_keeps_it_in_the_table(tie):
    assert trash_reason([COUNTRY, JOB], ["name", tie]) == ""


def test_weak_signals_only_mark():
    assert trash_reason([NEIGHBOR], ["name"]) == ""
    assert trash_reason([LINKEDIN], ["name"]) == ""                 # alguien puede vivir fuera
    # Otro país solo no basta (prueba real: Cannondale «menciona France», el Tour de France de Carapaz)
    assert trash_reason([COUNTRY], ["name"]) == ""
    assert trash_reason([COUNTRY, LINKEDIN], ["name"]).startswith("Menciona «México»")
    assert trash_reason([LINKEDIN, NEIGHBOR], ["name"]).startswith("Perfil de LinkedIn de España")
    assert trash_reason([], ["name"]) == ""


def test_official_or_own_site_never_goes_to_the_trash():
    assert trash_reason([COUNTRY], ["name"], official=True) == ""


def test_in_trash_respects_restored_and_confirmed():
    pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    from osint_app.gui.tab_profiling import in_trash
    homonym = {"url": "https://mx.linkedin.com/in/otro", "extra": {"papelera": "Menciona «México»…"}}
    assert in_trash(homonym, set(), set())
    assert not in_trash(homonym, {homonym["url"]}, set())           # devuelto a la tabla
    assert not in_trash(homonym, set(), {homonym["url"]})           # confirmado: es de la persona
    assert not in_trash({"url": "https://x", "extra": {}}, set(), set())
    assert not in_trash({"url": "https://x"}, set(), set())


def test_profiling_tab_hides_trash_and_restores(monkeypatch):
    from osint_app.tests.test_seed_rich import _real_tab
    tab = _real_tab()
    saved = []
    monkeypatch.setattr(tab, "_save_verdict", lambda url, verdict: saved.append((url, verdict)))
    person = {"source": "Wikidata", "url": "https://www.wikidata.org/wiki/Q1", "title": "Gonzalo Plata",
              "snippet": "", "confidence": 90, "category": "Persona", "matched": ["name"], "warning": "", "extra": {}}
    other = {"source": "WebSearch", "url": "https://es.linkedin.com/in/gonzalo-plata-x", "title": "Gonzalo Plata - Médico",
             "snippet": "", "confidence": 20, "category": "Web", "matched": ["name"], "warning": "otro país",
             "extra": {"papelera": "Su LinkedIn dice «Médico»; no coincide ningún otro dato del objetivo"}}
    tab._on_candidates_ready([person, other])
    assert tab.candidates_table.rowCount() == 1 and tab.table_candidates == [person]
    assert tab.btn_trash.text() == "🗑 Descartados (1)" and tab.btn_trash.isEnabled()
    assert "1 en «Descartados»" in tab.lbl_stats.text()
    assert tab._trashed() == [other]
    # «↩ Devolver a la tabla» (lo que hace la ventana al pulsarlo)
    tab.restored_urls.add(other["url"])
    tab._save_verdict(other["url"], "restaurado")
    tab._on_candidates_ready(tab.candidates_data)
    assert tab.candidates_table.rowCount() == 2 and not tab.btn_trash.isEnabled()
    assert saved == [(other["url"], "restaurado")]
    # La ficha sigue recibiendo todos los candidatos (los separa en «posibles homónimos»)
    assert tab.candidates_data == [person, other]
    tab.close()
