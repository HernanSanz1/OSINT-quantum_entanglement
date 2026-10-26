"""Ficha desde un caso guardado: semilla, resultados en bruto y decisiones del analista quedan en el caso."""
import json
import os
import sys

import pytest

from osint_app.case_manager import CaseManager
from osint_app.core.models import SearchResult, TargetData, ToolReport
from osint_app.reports.case_profile import person_report_from_case, profile_from_case
from osint_app.reports.person_report import render_person_html

SEED = {"name": "Luis Arturo Villar Sudek", "context": "youtuber viajes", "country": "México", "city": "",
        "aliases": ["Luisito Comunica"], "extra_usernames": [], "username": None}


def _results(*items):
    return json.dumps([SearchResult(**i).to_dict() for i in items], ensure_ascii=False)


WIKIDATA = _results(
    {"title": "Instagram oficial de Luisito Comunica: reypalomo_", "url": "https://www.instagram.com/reypalomo_",
     "snippet": "", "source_tool": "Wikidata", "category": "Social Media", "relevance_score": 90,
     "extra_data": {"platform": "Instagram", "name": "Luisito Comunica", "username": "reypalomo_"}},
    {"title": "YouTube oficial de Luisito Comunica: UCECJDeK0MNapZbpaOzxrUPA",
     "url": "https://www.youtube.com/channel/UCECJDeK0MNapZbpaOzxrUPA", "snippet": "", "source_tool": "Wikidata",
     "category": "Social Media", "relevance_score": 90, "extra_data": {"platform": "YouTube", "name": "Luisito Comunica"}},
)
MAIGRET = _results(
    {"title": "Maigret: perfil en TikTok", "url": "https://www.tiktok.com/@reypalomo_",
     "snippet": "@reypalomo_ encontrado en TikTok", "source_tool": "Maigret", "category": "Social Media",
     "relevance_score": 70, "extra_data": {"username": "reypalomo_", "platform": "TikTok", "tags": []}},
)


def _case_with_reports(temp_db):
    case = CaseManager().create("Perfil: Luis Arturo Villar Sudek", "")
    for tool, raw in (("Wikidata", WIKIDATA), ("Maigret:reypalomo_", MAIGRET), ("IP Reputation", "[]")):
        temp_db.save_report(ToolReport(case_id=case.id, tool_name=tool, raw_json=raw, status="ok"))
    return case.id


def test_profile_runs_and_verdicts_are_stored_and_removed_with_the_case(temp_db):
    case_id = _case_with_reports(temp_db)
    temp_db.save_profile_run(case_id, SEED, {"WebSearch": "búsqueda web INCOMPLETA"})
    temp_db.set_verdict(case_id, "https://a.com", "confirmado")
    temp_db.set_verdict(case_id, "https://a.com", "descartado")           # cambiar de opinión sustituye
    temp_db.set_verdict(case_id, "https://b.com", "confirmado")
    temp_db.set_verdict(case_id, "https://b.com", "")                     # y "" la borra
    assert temp_db.get_verdicts(case_id) == {"https://a.com": "descartado"}
    assert temp_db.get_profile_runs(case_id)[0]["seed"]["aliases"] == ["Luisito Comunica"]
    temp_db.delete_case(case_id)
    assert temp_db.get_verdicts(case_id) == {} and temp_db.get_profile_runs(case_id) == []


def test_ficha_is_rebuilt_from_the_case_with_current_scoring(temp_db):
    case_id = _case_with_reports(temp_db)
    temp_db.save_profile_run(case_id, SEED, {})
    report = person_report_from_case(case_id)
    accounts = {a["url"]: a for a in report["accounts"]}
    assert accounts["https://www.youtube.com/channel/UCECJDeK0MNapZbpaOzxrUPA"]["official"]
    assert "Mismo usuario" in accounts["https://www.tiktok.com/@reypalomo_"]["note"]     # el alias llega a la ficha
    assert report["case_id"] == case_id
    assert "Luisito Comunica" in render_person_html(report)                            # alias en "Datos de partida"


def test_rejected_candidates_stay_out_of_the_rebuilt_ficha(temp_db):
    case_id = _case_with_reports(temp_db)
    temp_db.save_profile_run(case_id, SEED, {"WebSearch": "búsqueda web INCOMPLETA"})
    temp_db.set_verdict(case_id, "https://www.tiktok.com/@reypalomo_", "descartado")
    report = person_report_from_case(case_id)
    assert "https://www.tiktok.com/@reypalomo_" not in {a["url"] for a in report["accounts"]}
    assert report["rejected_count"] == 1 and report["warnings"] == {"WebSearch": "búsqueda web INCOMPLETA"}


def test_old_cases_without_profile_runs_use_the_seed_saved_as_case_data(temp_db):
    case_id = _case_with_reports(temp_db)
    for field_type, value, conf, source in (("name", "Luis Arturo Villar Sudek", 100, "seed"),
                                            ("name", "Luisito Comunica", 95, "seed"),
                                            ("country", "México", 100, "seed"), ("location", "Puebla", 100, "seed"),
                                            ("profile", "https://www.instagram.com/reypalomo_", 90, "confirmado")):
        temp_db.add_target_data(TargetData(case_id=case_id, field_type=field_type, value=value, source=source,
                                           confidence=conf))
    profile = profile_from_case(case_id)
    assert profile["seed"]["name"] == "Luis Arturo Villar Sudek" and profile["seed"]["aliases"] == ["Luisito Comunica"]
    assert profile["seed"]["city"] == "Puebla"
    assert profile["confirmed"] == {"https://www.instagram.com/reypalomo_"}


def test_case_without_a_person_profile_gives_none(temp_db):
    case = CaseManager().create("Análisis de dominio", "")
    temp_db.save_report(ToolReport(case_id=case.id, tool_name="Domain WHOIS", raw_json="[]", status="ok"))
    assert person_report_from_case(case.id) is None


@pytest.mark.skipif(not (sys.platform == "win32" or os.environ.get("SENTINEL_GUI_TESTS") == "1"),
                    reason="el motor web de Qt solo se prueba en Windows o con SENTINEL_GUI_TESTS=1")
def test_real_pdf_is_created_with_qt_webengine(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QCoreApplication, Qt, QTimer
    from PySide6.QtWidgets import QApplication
    if QApplication.instance() is None:
        QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
    app = QApplication.instance() or QApplication([])
    from osint_app.gui.pdf_export import save_html_as_pdf
    from osint_app.reports.person_report import build_person_report
    target, result = tmp_path / "ficha.pdf", {}
    html = render_person_html(build_person_report(SEED, []))

    def done(ok, path):
        result.update(ok=ok, path=path)
        app.quit()
    page = save_html_as_pdf(html, str(target), done)
    QTimer.singleShot(60000, app.quit)
    app.exec()
    assert result.get("ok") and page is not None
    assert target.read_bytes().startswith(b"%PDF")
