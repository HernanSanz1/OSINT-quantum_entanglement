"""Arreglos de la evaluación 3 de usuario final (2026-10-28), con los datos reales que se vieron en ella."""
import json
from types import SimpleNamespace

from osint_app.cti_match import (CTI_REPORT_TOOL, correlate_targets_with_cti, cti_report_items, cti_rows,
                                 rows_from_report, target_identifiers)
from osint_app.profiler_engine import _wiki_key
from osint_app.reports.person_report import build_person_report
from osint_app.reports.readable import readable_results
from osint_app.utils.homonyms import homonym_signals
from osint_app.utils.search_engine import readable_attempts

# Víctima real de ransomware.live (caso #38 de la evaluación)
POLICIA = {"fuente_id": "ransomware_ec", "fuente": "Ransomware.live Ecuador", "fecha": "2026-10-16T10:00:00+00:00",
           "url": "https://api.ransomware.live/v2/countryvictims/EC", "victima_reservada": "Ecuadors National Police",
           "victima_web": "policia.gob.ec",
           "resumen": json.dumps({"group_name": "thegentlemen", "activity": "Government & Defense"})}


def td(kind, value, source="Manual"):
    return SimpleNamespace(field_type=kind, value=value, source=source)


def test_lo_que_anaden_las_herramientas_no_es_el_objetivo():
    # Caso #30: IP Reputation y WHOIS añadían dns.google o un servidor de Scania como "datos del objetivo"
    ids = target_identifiers([td("DOMAIN", "presidencia.gob.ec"), td("domain", "dns.google", "IP Reputation"),
                              td("domain", "pichincha.andinanet.net", "Domain WHOIS"), td("name", "Glenda", "seed")])
    assert ids["domains"] == ["presidencia.gob.ec"] and ids["names"] == ["Glenda"]


def test_la_alerta_de_ransomware_se_lee_entera_y_se_guarda():
    result = {"targets": correlate_targets_with_cti(target_identifiers([td("DOMAIN", "policia.gob.ec")]), [POLICIA]),
              "cve_matches": [], "tech_matches": []}
    rows = cti_rows(result)
    assert len(rows) == 1 and rows[0]["level"] == "Crítica"
    for text in ("thegentlemen", "Ecuadors National Police", "2026-10-16", "Qué hacer"):
        assert text in rows[0]["detail"]
    raw = json.dumps(cti_report_items(rows, {}))
    assert rows_from_report(raw) == rows                               # vuelve a la tabla tras "Analizar Caso"
    shown = readable_results(CTI_REPORT_TOOL, raw)                       # pestaña Reportes
    assert "VÍCTIMA DE RANSOMWARE" in shown and "Qué hacer" in shown


def test_cruce_sin_coincidencias_tambien_queda_documentado():
    items = cti_report_items([], {"domains": ["python.org"], "names": [], "ips": []})
    assert items[0]["category"] == "Sin resultado" and "python.org" in items[0]["snippet"]
    assert rows_from_report(json.dumps(items)) == []


def test_paises_de_sus_equipos_no_son_de_otra_persona():
    # Gonzalo Plata (Wikidata: Sporting CP, Valladolid, Al Sadd, Flamengo) y textos reales de la evaluación
    covid = ("¡Otro más! Gonzalo Plata dio positivo de COVID-19 Esta mañana, el diario … de Portugal informó que "
             "Gonzalo Plata fue diagnosticado con coronavirus.")
    url = "https://fanbolerosec.com/wp/otro-mas-gonzalo-plata-dio-positivo-de-covid-19/"
    assert homonym_signals(covid, url, "Ecuador", "futbolista")                       # sin la ficha: "menciona portugal"
    assert not homonym_signals(covid, url, "Ecuador", "futbolista", known_codes=["ec", "pt", "es", "qa", "br"])
    transfermarkt = "Gonzalo Plata - Perfil del jugador 2026 - Transfermarkt ¿Con cuál te quedas? Gonzalo Plata. CR Flamengo."
    assert not homonym_signals(transfermarkt, "https://www.transfermarkt.es/gonzalo-plata/profil/spieler/592735",
                               "Ecuador", "futbolista")


def test_linkedin_de_espana_sigue_siendo_otra_persona_aunque_jugara_alli():
    text = "Gonzalo Plata Jiménez - Ingeniero | LinkedIn"
    signals = homonym_signals(text, "https://es.linkedin.com/in/gonzalo-plata-jimenez-66471343", "Ecuador",
                              "futbolista", known_codes=["es"])
    assert [s.code for s in signals] == ["linkedin_country"]


def test_su_wikipedia_en_otro_idioma_es_suya():
    assert _wiki_key("https://pt.wikipedia.org/wiki/Gonzalo_Plata") == _wiki_key("https://pt.m.wikipedia.org/wiki/Gonzalo_Plata")
    assert _wiki_key("https://es.wikipedia.org/wiki/Jefferson_P%C3%A9rez") == "es.wikipedia.org/wiki/jefferson_pérez"
    assert _wiki_key("https://www.transfermarkt.es/x") == ""


def _cand(url, title, snippet="", conf=40.0, source="WebSearch"):
    return {"url": url, "title": title, "snippet": snippet, "confidence": conf, "source": source,
            "category": "LinkedIn", "extra": {}}


def test_linkedin_con_otra_profesion_no_entra_en_cuentas():
    seed = {"name": "Gonzalo Plata", "context": "futbolista", "country": "Ecuador"}
    report = build_person_report(seed, [
        _cand("https://www.linkedin.com/in/gonzalo-plata-221605266",
              "Gonzalo Plata - Cedar Fair Entertainment Company | LinkedIn", "Experience: Cedar Fair · Location: Charlotte"),
        _cand("https://www.linkedin.com/in/gonzalo-plata-futbol", "Gonzalo Plata - Futbolista en Flamengo | LinkedIn"),
    ])
    handles = [a["handle"] for a in report["accounts"]]
    assert "gonzalo-plata-futbol" in handles and "gonzalo-plata-221605266" not in handles
    assert any("Cedar Fair" in h["warning"] for h in report["homonyms"])


def test_linkedin_con_su_nombre_legal_completo_se_queda():
    seed = {"name": "Luis Arturo Villar Sudek", "context": "youtuber viajes", "country": "México"}
    report = build_person_report(seed, [_cand("https://mx.linkedin.com/in/luis-arturo-villar-sudek-576194224",
                                              "Luis Arturo Villar Sudek - Ciencias de la Comunicación en... | LinkedIn")])
    assert [a["handle"] for a in report["accounts"]] == ["luis-arturo-villar-sudek-576194224"]


def test_correo_pegado_a_la_palabra_anterior():
    seed = {"name": "Luis Arturo Villar Sudek", "context": "youtuber", "country": "México"}
    bio = "Luisito Comunica · bio: El canal más chido de YouTubeluisitocomunica@wearedw.com"
    report = build_person_report(seed, [_cand("https://www.youtube.com/@luisitocomunica", "Luisito Comunica", bio, 90)])
    assert [c["value"] for c in report["contacts"]] == ["luisitocomunica@wearedw.com"]


def test_bloqueos_de_buscadores_en_palabras():
    text = readable_attempts([("searxng", "en pausa"), ("ddgs-auto", "bloqueado: tiempo agotado"),
                              ("duckduckgo", "bloqueado: captcha anti-bots"), ("yahoo", "vacío")])
    assert "ddgs" not in text and "anti-bots" not in text and "Yahoo" not in text
    assert "SearXNG" in text and "no respondió a tiempo" in text and "captcha" in text
