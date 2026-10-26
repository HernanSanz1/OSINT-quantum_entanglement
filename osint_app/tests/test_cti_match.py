"""Cruce de los datos del objetivo con el CTI: víctimas de ransomware, menciones en noticias, IP en avisos, EPSS.

Las víctimas tienen la forma real de ransomware.live (resumen JSON que a veces llega cortado).
"""
import json
from types import SimpleNamespace

from osint_app.cti_link import CtiStore
from osint_app.cti_match import (
    correlate_targets_with_cti, host_of, ransomware_victims, same_site, target_identifiers,
)


def victim(name, website, group="qilin", cut=False):
    summary = json.dumps({"activity": "Transportation", "country": "EC", "group_name": group, "post_title": name,
                          "post_url": "http://x.onion/blog", "website": website}, ensure_ascii=False)
    return {"fuente_id": "ransomware_ec", "fuente": "Ransomware.live Ecuador", "fecha": "2026-10-12T14:50:15+00:00",
            "titulo": f"Registro OSINT de ransomware en Ecuador: sector Transportation, grupo {group}",
            "url": "https://api.ransomware.live/v2/countryvictims/EC", "ransomware": True,
            "victima_reservada": name, "resumen": summary[:60] if cut else summary}


NEWS = {"fuente_id": "ecucert", "fuente": "EcuCERT", "fecha": "2026-10-01", "url": "https://www.ecucert.gob.ec/x",
        "titulo": "Alerta: campaña de phishing suplanta a Conauto", "resumen": "Correos falsos desde conauto.com.ec"}
IOC = {"fuente_id": "cisa_advisories", "fuente": "CISA", "fecha": "2026-09-20", "url": "https://cisa.gov/a",
       "titulo": "Indicadores de la campaña", "resumen": "Infraestructura: 171.25.193.25, 198.51.100.4"}


def td(kind, value, source="Manual"):
    return SimpleNamespace(field_type=kind, value=value, source=source)


def test_domains_compare_without_www_and_with_subdomains():
    assert host_of("https://www.conauto.com.ec/inicio") == "conauto.com.ec"
    assert same_site("www.conauto.com.ec", "mail.conauto.com.ec") and not same_site("conauto.com.ec", "auto.com.ec")


def test_identifiers_come_from_the_target_data_in_any_case_and_skip_free_mail():
    ids = target_identifiers([td("DOMAIN", "www.Conauto.com.ec"), td("email", "ana@conauto.com.ec"),
                              td("email", "x@gmail.com"), td("COMPANY", "ConAuto S.A."), td("IP", "8.8.8.8"),
                              td("ip", "192.168.1.10"), td("found_domain", "wikipedia.org", "WebSearch")])
    assert ids == {"domains": ["conauto.com.ec"], "names": ["ConAuto S.A."], "ips": ["8.8.8.8"]}


def test_victim_found_by_website_or_by_name():
    items = [victim("ConAuto", "www.conauto.com.ec"), victim("McDonald's Ecuador", "mcdonalds.com.ec")]
    by_web = correlate_targets_with_cti({"domains": ["conauto.com.ec"], "names": [], "ips": []}, items)
    assert [v["name"] for v in by_web["ransomware"]] == ["ConAuto"]
    by_name = correlate_targets_with_cti({"domains": [], "names": ["ConAuto Cía. Ltda."], "ips": []}, items)
    assert [v["name"] for v in by_name["ransomware"]] == ["ConAuto"]


def test_cut_summary_still_gives_the_victim_name():
    # La recolección corta el resumen a 900 caracteres: la web puede perderse, el nombre viene aparte
    items = [victim("ConAuto", "www.conauto.com.ec", cut=True)]
    assert ransomware_victims(items)[0]["name"] == "ConAuto"
    assert correlate_targets_with_cti({"domains": [], "names": ["ConAuto"], "ips": []}, items)["ransomware"]


def test_similar_but_different_organizations_do_not_match():
    items = [victim("Grupo Pasquel", "grupopasquel.com")]
    ids = {"domains": ["pasquel.ec"], "names": ["Grupo", "Pasquel Seguros"], "ips": []}
    assert correlate_targets_with_cti(ids, items)["ransomware"] == []


def test_news_mentions_and_ip_indicators():
    ids = {"domains": ["conauto.com.ec"], "names": ["Conauto"], "ips": ["171.25.193.25", "203.0.113.7"]}
    result = correlate_targets_with_cti(ids, [NEWS, IOC])
    assert [m["source"] for m in result["mentions"]] == ["EcuCERT"]
    assert "su dominio conauto.com.ec" in result["mentions"][0]["matched"]
    assert [i["matched"] for i in result["iocs"]] == ["su IP 171.25.193.25"]          # 203.0.113.7 no es .77


def test_generic_single_words_are_not_mentions():
    news = {**NEWS, "titulo": "El banco central de Ecuador alerta de fraudes", "resumen": ""}
    ids = {"domains": [], "names": ["Banco", "Ecuador"], "ips": []}
    assert correlate_targets_with_cti(ids, [news])["mentions"] == []


def test_tech_hits_are_ranked_by_danger_with_epss_and_public_exploit():
    items = [{"vendor": "WordPress", "product": "Plugin A", "cves": ["CVE-2026-0001"], "fecha": "2026-01-01"},
             {"vendor": "WordPress", "product": "Plugin B", "cves": ["CVE-2020-11738"], "kev": True,
              "fecha": "2021-11-03"},
             {"vendor": "WordPress", "product": "Plugin C", "cves": ["CVE-2026-0002"], "fecha": "2026-02-01"}]
    store = CtiStore(items, {"epss": {"CVE-2020-11738": {"epss": 0.97822}, "CVE-2026-0002": {"epss": 0.5}},
                             "poc_github": ["CVE-2020-11738"]})
    hits = store.search_tech("wordpress")
    assert [h.cve for h in hits] == ["CVE-2020-11738", "CVE-2026-0002", "CVE-2026-0001"]
    assert hits[0].poc and hits[0].epss == 0.97822 and hits[2].epss is None


def test_real_store_loads_the_enrichment_next_to_the_items(tmp_path):
    (tmp_path / "items.jsonl").write_text(json.dumps({"cves": ["CVE-2026-0001"]}) + "\n", encoding="utf-8")
    (tmp_path / "enriquecimiento.json").write_text(
        json.dumps({"epss": {"CVE-2026-0001": {"epss": 0.25}}, "poc_github": ["CVE-2026-0001"]}), encoding="utf-8")
    hit = CtiStore.load(tmp_path / "items.jsonl").by_cve("CVE-2026-0001")[0]
    assert hit.epss == 0.25 and hit.poc


def test_engine_reads_types_saved_in_capitals_by_the_data_tab(temp_db):
    # Caso real #23: "DOMAIN" e "IP" de la pestaña Datos no se relacionaban con nada
    from osint_app.case_manager import CaseManager
    from osint_app.core.models import TargetData
    from osint_app.correlation_engine import CorrelationEngine
    case = CaseManager().create("Dominio", "")
    for kind, value in (("DOMAIN", "conauto.com.ec"), ("IP", "171.25.193.25")):
        temp_db.add_target_data(TargetData(case_id=case.id, field_type=kind, value=value, source="Manual"))
    engine = CorrelationEngine(case.id)
    assert {e.entity_type for e in engine.entities.values()} == {"domain", "ip"}
    result = engine.correlate_with_cti(store=CtiStore([victim("ConAuto", "www.conauto.com.ec"), IOC]))
    assert [v["name"] for v in result["targets"]["ransomware"]] == ["ConAuto"]
    assert [i["matched"] for i in result["targets"]["iocs"]] == ["su IP 171.25.193.25"]
