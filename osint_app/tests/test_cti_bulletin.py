"""Boletín CTI (evaluación 3, 2026-10-28): textos fieles a cada noticia, en español y sin frases cortadas.

Los módulos del boletín son scripts con imports planos (from clientes import …): se cargan con su carpeta en la ruta y
con el almacén apuntando a una carpeta temporal, para no leer ni escribir los datos del usuario.
"""
import importlib
import sys
from pathlib import Path

import pytest

CTI_DIR = Path(__file__).resolve().parents[2] / "sentinel_unified" / "modules" / "cti"


@pytest.fixture(scope="module")
def cti(tmp_path_factory):
    store = tmp_path_factory.mktemp("cti_store")
    mp = pytest.MonkeyPatch()
    mp.setenv("SENTINEL_CTI_STORE", str(store))
    mp.setenv("SENTINEL_CTI_REPORTS", str(store / "boletines"))
    mp.syspath_prepend(str(CTI_DIR))
    for name in ("render", "dossier"):
        sys.modules.pop(name, None)
    render, dossier = importlib.import_module("render"), importlib.import_module("dossier")
    yield render, dossier
    for name in ("render", "dossier", "clientes", "exposicion_cve", "seleccion_cliente", "fuentes", "productos",
                 "validar", "harvest"):
        sys.modules.pop(name, None)
    mp.undo()


def test_resumen_cortado_por_la_fuente(cti):
    render, _ = cti
    cut = ("Siemens confirmó la explotación activa de CVE-2026-110936. La falla permite cargar bibliotecas maliciosas "
           "desde una ruta de")
    assert render.sentence_limit(cut) == "Siemens confirmó la explotación activa de CVE-2026-110936."
    assert render.sentence_limit("Las fallas pueden permitir que una página web maliciosa").endswith("maliciosa…")


def test_texto_escrito_para_otra_noticia_no_se_usa(cti):
    render, _ = cti
    # Boletín real: el titular de KSMBD llevaba el texto de una vulnerabilidad antigua de net/sched
    ksmbd = {"fuente_id": "thehackernews", "fuente": "The Hacker News", "cves": [],
             "titulo": "Two CVSS 9.0 Linux KSMBD RCE Flaws Disclosed on Public Mailing Lists Before Kernel Fixes",
             "resumen": "Two critical flaws in the Linux kernel KSMBD server were disclosed before fixes shipped."}
    text = render.editorial_text(ksmbd)
    assert "net/sched" not in text and "KSMBD" in text
    net_sched = {**ksmbd, "titulo": "Linux kernel net/sched zero-day", "resumen": "A use-after-free in net/sched of Linux."}
    assert "net/sched" in render.editorial_text(net_sched)


def test_noticia_en_ingles_resumida_en_espanol(cti):
    render, _ = cti
    item = {"fuente": "The Hacker News", "cves": ["CVE-2026-111497"], "productos_cve": ["Google Brotli"],
            "etiquetas": ["PoC PUBLICO"],
            "titulo": "PHP Issues Second Windows Security Update in Five Days to Fix Brotli Code Execution Flaw",
            "resumen": "PHP has rebuilt its official Windows packages to fix CVE-2026-111497, a flaw in the Brotli library."}
    assert render.is_english(item["titulo"], short=True) and not render.is_english("GitLab corrige falla crítica", True)
    assert render.title_text(item).startswith("Ejecución remota de código en Google Brotli (CVE-2026-111497)")
    text = render.generic_editorial(item)
    assert "exploit público" in text and "Titular original" in text and "has rebuilt" not in text


def test_producto_del_catalogo_y_no_de_microsoft_para_otros(cti):
    _, dossier = cti
    items = [{"fuente_id": "microsoft_msrc", "cves": ["CVE-2026-111497"], "vendor": "Microsoft",
              "product": "Google: Buffer overflow vulnerability in the Brotli decoder"},
             {"fuente_id": "cisa_kev", "cves": ["CVE-2026-111497"], "vendor": "Google", "product": "Brotli"}]
    assert dossier.catalog_products(items) == {"CVE-2026-111497": "Google Brotli"}


def test_seccion_ecuador_dice_lo_que_trae(cti):
    render, _ = cti
    chrome = {"fuente_id": "csirt_telconet", "titulo": "Chrome 156 corrige 353 fallos", "resumen": "Google publicó…"}
    victim = {"fuente_id": "ransomware_ec", "titulo": "Registro OSINT de ransomware en Ecuador", "resumen": "{}"}
    assert render.ecuador_title([chrome]) == "Avisos difundidos en Ecuador (EcuCERT, CSIRT Telconet)"
    assert render.ecuador_title([chrome, victim]) == "Seguridad Ecuador"


def test_relevancia_para_el_cliente(cti):
    render, _ = cti
    item = {"cliente_matches": [{"nombre": "VMware vCenter", "confirmado": True}]}
    assert "Relevante para su entorno: VMware vCenter" in render.client_relevance_phrase(item)
    assert render.client_relevance_phrase({}) == ""


def test_resumen_del_dossier_sin_jerga():
    pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)     # Linux sin entorno gráfico (CI)
    from osint_app.gui.tab_cti import dossier_summary_lines
    lines = dossier_summary_lines({"semana": "2026-10-28", "totales": {"items_store": 7800, "items_ventana": 206,
                                                                       "explotados": 14},
                                   "secciones": {"amenaza_semana": 1, "principales_cves": 10},
                                   "brechas": ["Seguridad Ecuador: 1/3 candidatos."]})
    text = "\n".join(lines)
    assert "items store" not in text and "candidatos" not in text
    assert "7800 noticias" in text and "Seguridad Ecuador (1 de 3)" in text


# ── Clase del producto (evaluación 4) ────────────────────────────────────────

SIX_KEV = {"titulo": "CISA Adds Six Known Exploited Vulnerabilities to Catalog",
           "resumen": "CVE-2026-96656 Plex Media Server SSRF · CVE-2026-110936 Siemens Software Center …",
           "cves": ["CVE-2026-96652", "CVE-2026-96656", "CVE-2026-110936", "CVE-2026-106931"]}


@pytest.mark.parametrize("cve,product,expected", [
    # la noticia compartida nombra a Siemens: antes los cuatro salían "Tecnología OT / industrial"
    ("CVE-2026-96656", "Plex Media Server", "Software / componente empresarial"),
    ("CVE-2026-110936", "Siemens Software Center", "Software / componente empresarial"),
    ("CVE-2026-106931", "EG Secure Solutions SiteGuard Server Edition", "Software / componente empresarial"),
    # un PLC con Linux dentro sigue siendo OT (antes "Sistema operativo / servicio base")
    ("CVE-2026-64560", "Siemens SIMATIC S7-1500 TM MFP", "Tecnología OT / industrial"),
    ("CVE-2026-53362", "Linux Kernel", "Sistema operativo / servicio base"),
    ("CVE-2026-20000", "Google Chromium", "Navegador / cliente web"),
    ("CVE-2026-111497", "Google Brotli", "Librería / componente de software"),
    ("CVE-2026-20127", "Cisco Catalyst SD-WAN Controller and Manager", "Tecnología de frontera / acceso remoto"),
    ("CVE-2026-102764", "BeyondTrust Remote Support", "Tecnología de frontera / acceso remoto"),
])
def test_class_comes_from_this_cve_not_from_a_shared_news_item(cti, cve, product, expected):
    render, _ = cti
    item = {"cve": cve, "producto": product, "titulo": f"{cve} - {product}", "impacto": ""}
    assert render.cve_class_text(cve, product, SIX_KEV, item) == expected


def test_class_matches_whole_words_only(cti):
    render, _ = cti
    item = {"producto": "Acme Analytics Graphics Knowledge Base", "titulo": "", "impacto": ""}
    assert render.cve_class_text("CVE-2026-1", item["producto"], {}, item) == "Software / componente empresarial"


def test_single_cve_source_still_gives_the_class(cti):
    render, _ = cti
    first = {"titulo": "Hitachi Energy TRO600 series products", "resumen": "RTU used in substations",
             "cves": ["CVE-2026-10756"]}
    item = {"producto": "", "titulo": "", "impacto": ""}
    assert render.cve_class_text("CVE-2026-10756", "", first, item) == "Tecnología OT / industrial"


# ── Validar el boletín antes de enviarlo ─────────────────────────────────────

BULLETIN_EVAL4 = """<html><body>
<div class="news-item"><h2>&#9889; Amenaza de la Semana</h2>
<p><strong>Siemens confirma explotación activa:</strong> Siemens confirmó la explotación de CVE-2026-110936.
<a href="https://csirt.telconet.net/x" class="info-button">Leer M&aacute;s</a></p></div>
<div class="news-item"><h2>&#9888;&#65039; Principales CVEs</h2><ul>
<li><a href="https://csirt.telconet.net/gitlab">CVE-2026-110264 CVSS v3.1: 10.0 CRÍTICA</a>: Clase: Aplicación.
Afecta a Microsoft Integer Overflow or Wraparound in GitLab. La falla reside en el compilador Onigmo, incluido en
Leer más ... Fuente principal: CSIRT Telconet.</li>
<li><a href="https://cisa.gov/1">CVE-2026-96652 CVSS v3.1: 7.2 ALTA</a>: Afecta a Plex Media Server. Actualizar.</li>
<li><a href="https://cisa.gov/2">CVE-2026-96654 CVSS v3.1: 7.2 ALTA</a>: Afecta a Plex Media Server. Actualizar.</li>
<li><a href="https://cisa.gov/3">CVE-2026-96656 CVSS v3.1: 7.2 ALTA</a>: Afecta a Plex Media Server. Actualizar.</li>
<li>Researchers demonstrate the exploit on the latest build of the server with crafted data that is sent</li>
</ul></div>
<div class="news-item"><h2>Avisos difundidos en Ecuador</h2><ul></ul></div>
<h2>&#128269; Referencias</h2><ul><li><a href="https://cisa.gov">CISA</a></li></ul>
</body></html>"""


def test_validation_finds_what_the_evaluation_found_by_hand(cti):
    import importlib
    validar = importlib.import_module("validar")
    report = validar.validate(BULLETIN_EVAL4, client="XTRIM")
    kinds = [p["tipo"] for p in report["problemas"]]
    assert report["noticias"] == 6
    assert "frase cortada" in kinds and "producto dudoso" in kinds and "producto repetido" in kinds
    assert "en inglés" in kinds and "sin enlace" in kinds and "sección vacía" in kinds and "cliente" in kinds
    gitlab = [p for p in report["problemas"] if p["tipo"] == "producto dudoso"][0]
    assert gitlab["titulo"].startswith("CVE-2026-110264")


def test_validation_of_a_clean_bulletin(cti):
    import importlib
    validar = importlib.import_module("validar")
    page = ("<h2>Noticias Principales</h2><ul><li><strong>Fortinet corrige un fallo:</strong> Fortinet publicó "
            "parches para FortiOS. Afecta a Fortinet FortiOS. Deben aplicarse las correcciones."
            "<a href=\"https://fortiguard.com/x\" class=\"info-button\">Leer Más</a></li></ul>"
            "<p>Boletín preparado para XTRIM.</p>")
    assert validar.validate(page, client="XTRIM")["problemas"] == []


def test_rendering_the_same_week_again_keeps_the_previous_bulletin(cti, tmp_path, monkeypatch):
    render, _ = cti
    monkeypatch.setattr(render, "REPORTS", tmp_path / "boletines")
    monkeypatch.setattr(render, "render", lambda dossier: "<html>boletín</html>")
    dossier = tmp_path / "dossier-2026-W44-XTRIM.json"
    dossier.write_text('{"semana": "2026-W44", "cliente": {"nombre": "XTRIM"}}', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["render.py", str(dossier)])
    assert render.main() == 0 and render.main() == 0
    assert (tmp_path / "boletines" / "AltelThreatIntell_2026W44_XTRIM.html").exists()
    assert len(list((tmp_path / "boletines" / "anteriores").glob("AltelThreatIntell_2026W44_XTRIM_*.html"))) == 1


# ── Decisiones del 31-10-2026: últimos 7 días, sección del cliente, filtro estricto solo para CVE ────────────

def test_default_window_is_the_last_seven_days_including_today(cti):
    import datetime as dt
    _, dossier = cti
    period, start, end = dossier.week_window(None)
    today = dt.datetime.now(dossier.LOCAL_TZ).date()
    assert start.astimezone(dossier.LOCAL_TZ).date() == today - dt.timedelta(days=6)
    assert end.astimezone(dossier.LOCAL_TZ).date() == today + dt.timedelta(days=1)
    assert period == f"{today.isocalendar().year}-W{today.isocalendar().week:02d}"
    # Una semana pedida a mano sigue siendo de lunes a domingo
    _, start, end = dossier.week_window("2026-W44")
    assert start.astimezone(dossier.LOCAL_TZ).date() == dt.date(2026, 10, 26) and (end - start).days == 7


def test_period_label_shows_the_exact_days(cti):
    render, _ = cti
    window = {"inicio": "2026-10-25T05:00:00+00:00", "fin": "2026-11-01T05:00:00+00:00"}
    assert render.period_label({"semana": "2026-W44", "ventana": window}) == "Semana del 25 al 31 de Octubre, 2026"
    window = {"inicio": "2026-10-29T05:00:00+00:00", "fin": "2026-11-05T05:00:00+00:00"}
    assert render.range_label(window) == "29 de Octubre al 4 de Noviembre, 2026"
    window = {"inicio": "2026-12-29T05:00:00+00:00", "fin": "2027-01-05T05:00:00+00:00"}
    assert render.range_label(window) == "29 de Diciembre, 2026 al 4 de Enero, 2027"
    assert render.range_label({}) == ""


def test_threat_news_without_cve_go_to_news_sections_but_not_noise(cti):
    _, dossier = cti
    teams = {"fuente_id": "thehackernews", "titulo": "Attackers Use Microsoft Teams IT Support Scams to Deploy Malware",
             "etiquetas": ["FRAUDE / PHISHING", "MALWARE"], "cves": []}
    assert dossier.news_without_cve(teams)
    assert not dossier.news_without_cve({**teams, "titulo": "Webinar: How to Build AI Threat Readiness"})
    assert not dossier.news_without_cve({**teams, "titulo": "⚡ Weekly Recap: This2Shell, That2Shell"})
    assert not dossier.news_without_cve({**teams, "cves": ["CVE-2026-1"]})          # las CVE: filtro estricto
    assert not dossier.news_without_cve({**teams, "fuente_id": "cisa_kev"})
    assert not dossier.news_without_cve({**teams, "etiquetas": ["CORROBORACION CRUZADA"]})
    # Los avisos de EcuCERT y CSIRT Telconet sin número de CVE (Firefox, HPE, nginx) también
    nginx = {"fuente_id": "csirt_telconet", "region": "ec", "titulo": "Ubuntu publica parches para nginx",
             "etiquetas": [], "cves": []}
    assert dossier.news_without_cve(nginx)


@pytest.mark.parametrize("a,b,same", [
    ("Hackers exploit Cisco SD-WAN flaw to deploy custom KeyDrift malware",
     "Hackers Exploited Cisco SD-WAN Flaw to Plant Malware Built to Steal Encryption Keys", True),
    ("Volt Typhoon Used Covert Silent Train Network in Four Zero-Day Exploitation Campaigns",
     "Volt Typhoon hides zero-day attacks using 'Silent Train' framework", True),
    ("Attackers Exploit PHP2Shell Flaws in Internet-Exposed Palo Alto Networks Management Interfaces",
     "PHP2Shell Attack Roots 25 Servers, Breaches U.S. Government-Affiliated Network", True),
    ("Cisco Patches Actively Exploited ASA and FTD VPN Flaw", "Hackers exploit Cisco SD-WAN flaw", False),
    ("Hackers exploit Fortinet flaw", "Hackers exploit Ivanti flaw", False),
])
def test_same_story_from_different_sources(cti, a, b, same):
    _, dossier = cti
    assert dossier.same_story({"titulo": a}, {"titulo": b}) is same


def test_client_section_takes_exact_products_only(cti):
    _, dossier = cti

    titles = {1: "VMware vCenter patch", 2: "Microsoft 365 token theft", 3: "Linux kernel TCP bug"}

    def item(n, level, cves=()):
        return {"id": f"i{n}", "titulo": titles[n], "score": 10 - n, "cves": list(cves),
                "fecha": "2026-10-28", "cliente_matches": [{"nombre": "X", "nivel_coincidencia": level}]}
    vcenter, m365 = item(1, "producto_exacto", ["CVE-2026-1"]), item(2, "servicio_exacto")
    linux = item(3, "sistema_operativo")
    used = set()
    chosen = dossier.client_environment_items([linux, m365, vcenter], used, [])
    assert [c["id"] for c in chosen] == ["i1", "i2"]          # «cualquier noticia de Linux» no basta
    assert used == {"i1", "i2"}                                # y no se repiten en las demás secciones


def test_canned_text_needs_the_news_to_back_its_claims(cti):
    render, _ = cti
    passkeys = {"fuente_id": "bleepingcomputer", "fuente": "BleepingComputer", "cves": [], "etiquetas": [],
                "titulo": "Microsoft urges Entra ID admins to migrate users to passkeys",
                "resumen": "Microsoft again asked Entra ID administrators to migrate users to phishing-resistant "
                           "methods before it retires SMS and voice authentication."}
    text, title = render.editorial_text(passkeys), render.title_text(passkeys)
    assert "vulnerabilidad" not in text and "corrección del fabricante" not in text
    assert "corrige falla" not in title and title.startswith("Cambio en los métodos de acceso")
    assert "corrige falla" not in render.reference_title({**passkeys, "resumen": ""})
    esx = {"fuente_id": "cisa_kev", "fuente": "CISA KEV", "cves": ["CVE-2026-41709"], "etiquetas": [],
           "titulo": "CVE-2026-41709 Broadcom VMware ESX",
           "resumen": "Broadcom VMWare ESX contains an insufficient logging vulnerability."}
    assert "omisión de autenticación" not in render.editorial_text(esx)
    # Un texto escrito a mano que sí corresponde se sigue usando
    vmsa = {**esx, "titulo": "Broadcom VMware VMSA advisory", "resumen": "Broadcom VMware authentication bypass and "
            "remote code execution vulnerabilities in vCenter and ESXi."}
    assert "omisión de autenticación" in render.editorial_text(vmsa)


def test_client_section_in_the_bulletin(cti):
    render, _ = cti
    item = {"fuente_id": "csirt_telconet", "fuente": "CSIRT Telconet", "titulo": "VMware corrige falla en vCenter",
            "resumen": "Broadcom publicó parches para vCenter.", "cves": ["CVE-2026-1"], "url": "https://x.ec/a",
            "cliente_matches": [{"nombre": "VMware vCenter", "nivel_coincidencia": "producto_exacto"}]}
    dossier = {"cliente": {"nombre": "XTRIM"}, "secciones": {"entorno_cliente": [item]}}
    html_text = render.client_section(dossier)
    assert "Lo que afecta a la infraestructura de XTRIM" in html_text
    assert "Qué revisar: confirme si su VMware vCenter usa una versión afectada" in html_text
    empty = render.client_section({"cliente": {"nombre": "XTRIM"}, "secciones": {"entorno_cliente": []}})
    assert "no hubo noticias que nombren las tecnologías" in empty
    assert render.client_section({"secciones": {}}) == ""                       # el GLOBAL no la tiene
    validar = importlib.import_module("validar")
    page = ('<html><body><h2>Amenaza</h2><p><strong>Algo:</strong> Texto. <a class="info-button" href="https://x">Leer</a></p>'
            f"{empty}</body></html>")
    assert validar.validate(page)["problemas"] == []                           # no es «sección vacía»


def test_empty_news_section_explains_itself(cti):
    render, _ = cti
    assert render.list_section("Noticias", []) == ""
    assert "Esta semana no hubo" in render.list_section("Noticias", [], "", "Esta semana no hubo otras noticias.")


def test_english_text_without_cve_does_not_ask_for_a_patch(cti):
    render, _ = cti
    item = {"fuente": "The Hacker News", "cves": [], "etiquetas": [],
            "titulo": "Microsoft 365 Token-Replay Attacks Compromise 97 Accounts",
            "resumen": "A campaign leveraging an adversary-in-the-middle relay to capture sign-in sessions."}
    text = render.english_item_text(item)
    assert "corrección del fabricante" not in text and "robo de sesiones" in text


# ── 04-11-2026: titulares de noticias en inglés, resúmenes semanales, Microsoft a principios de mes ──────────────

@pytest.mark.parametrize("title,expected", [
    ("China-Aligned Hackers Hijack Sogou Input Method DNS Requests to Deploy DarkVigil Backdoor",
     ["China", "Sogou", "DarkVigil"]),
    ("Fake ChatGPT and Claude Apps Abuse Signed Executables to Deploy Crypto Miners", ["ChatGPT", "Claude"]),
    ("Attackers Exploit Critical Siemens IoT2050 Flaw to Plant Remote Command Backdoors", ["Siemens", "IoT2050"]),
    ("APT29-Linked Hackers Hijack Web Analytics Script to Deliver iOS and Android Exploits", ["APT29", "iOS", "Android"]),
    ("Japan's GMO urges customers to shut down PCs amid ransomware threat", ["Japón", "GMO"]),
    ("Attackers Exploit PHP2Shell Flaws in Internet-Exposed Palo Alto Networks Management Interfaces",
     ["PHP2Shell", "Palo Alto Networks"]),
    # Siglas técnicas y palabras corrientes no cuentan; «exchange» de criptomonedas no es Microsoft Exchange
    ("Linux Kernel TCP Flaw With 9.8 CVSS Score Affects RCE", ["Linux"]),
    ("Crypto exchange hacked", []),
])
def test_title_subjects(cti, title, expected):
    render, _ = cti
    assert render.title_subjects(title) == expected


def test_english_heading_names_the_story(cti):
    render, _ = cti
    sogou = {"fuente": "The Hacker News", "cves": [], "titulo": "China-Aligned Hackers Hijack Sogou Input Method DNS "
             "Requests to Deploy DarkVigil Backdoor", "resumen": "A backdoor called DarkVigil."}
    gpt = {**sogou, "titulo": "Fake ChatGPT and Claude Apps Abuse Signed Executables to Deploy Crypto Miners",
           "resumen": "Malware distributed through fake apps."}
    assert render.spanish_heading(sogou) == "Campaña de malware: China, Sogou, DarkVigil, según The Hacker News"
    assert render.spanish_heading(sogou) != render.spanish_heading(gpt)      # antes, dos titulares iguales
    siemens = {**sogou, "cves": ["CVE-2026-58115"], "titulo": "Attackers Exploit Critical Siemens IoT2050 Flaw to Plant "
               "Remote Command Backdoors", "resumen": ""}
    assert render.spanish_heading(siemens) == ("Explotación activa: Siemens, IoT2050 (CVE-2026-58115), según "
                                               "The Hacker News")
    recap = {**sogou, "titulo": "⚡ Weekly Recap: Critical CVEs, Linux DDoS Botnet, Device-Code Phishing"}
    assert render.spanish_heading(recap).startswith("Resumen de varias amenazas de la semana")


def test_weekly_recaps_are_not_news(cti):
    _, dossier = cti
    assert dossier.not_news({"titulo": "⚡ Weekly Recap: Critical CVEs, Linux DDoS Botnet"})
    assert not dossier.not_news({"titulo": "Attackers Exploit Critical Siemens IoT2050 Flaw"})


def test_msrc_release_ids_do_not_depend_on_the_system_language(cti):
    import datetime as dt
    harvest = importlib.import_module("harvest")
    nov = dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc)
    assert harvest.current_msrc_release_id(nov) == "2026-Nov"
    assert harvest.previous_msrc_release_id(nov) == "2026-Oct"
    assert harvest.previous_msrc_release_id(dt.datetime(2027, 1, 5, tzinfo=dt.timezone.utc)) == "2026-Dec"


def test_msrc_uses_last_month_before_patch_tuesday(cti, monkeypatch):
    import urllib.error
    harvest = importlib.import_module("harvest")
    asked = []

    def fetch(url, timeout=35):
        asked.append(url.rsplit("/", 1)[-1])
        if url.endswith(harvest.current_msrc_release_id()):
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return b'<cvrfdoc xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.1"></cvrfdoc>'
    monkeypatch.setattr(harvest, "fetch", fetch)
    assert harvest.harvest_msrc_cvrf_actual({"id": "microsoft_msrc", "url": "https://x/cvrf"}) == []
    assert asked == [harvest.current_msrc_release_id(), harvest.previous_msrc_release_id()]


def test_rss_source_down_is_an_error_not_zero_news(cti, monkeypatch):
    harvest = importlib.import_module("harvest")
    calls = []

    def fetch(url, timeout=35):
        calls.append(url)
        raise ConnectionResetError("el servidor cortó la conexión")
    monkeypatch.setattr(harvest, "fetch", fetch)
    with pytest.raises(ConnectionResetError):
        harvest.harvest_rss({"id": "csirt_telconet", "url": "https://x/feed/", "paginas": 5})
    assert len(calls) == 1                     # antes, 5 páginas y ~100 s para acabar en «OK, 0 noticias»
