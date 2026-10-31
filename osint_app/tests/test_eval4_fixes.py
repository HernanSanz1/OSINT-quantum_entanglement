"""Arreglos de la evaluación 4 de Cowork (29-10-2026), con los datos reales que la provocaron."""
import json

import pytest

from osint_app.cti_link import tech_scan_note
from osint_app.core.models import QueryParameters, ToolReport
from osint_app.reports.person_report import build_person_report, render_person_html
from osint_app.reports.readable import readable_results
from osint_app.tools import ip_reputation
from osint_app.tools.tech_detect import fetch_candidates
from osint_app.utils.contact_privacy import mask_contacts, mask_email, mask_phone
from osint_app.utils.directories import is_directory_result


# ── F4-1 Tech Detect: también con «www.» ─────────────────────────────────────

def test_tech_detect_tries_www_before_plain_http():
    # presidencia.gob.ec sin www: certificado de otro nombre y http sin respuesta; www sí responde
    assert fetch_candidates("presidencia.gob.ec") == [
        "https://presidencia.gob.ec", "https://www.presidencia.gob.ec",
        "http://presidencia.gob.ec", "http://www.presidencia.gob.ec"]


def test_tech_detect_keeps_the_path_and_does_not_double_www():
    assert fetch_candidates("www.python.org/about") == ["https://www.python.org/about", "http://www.python.org/about"]


def test_tech_detect_falls_back_to_www(monkeypatch):
    import requests
    from osint_app.tools import tech_detect

    tried = []

    class Resp:
        headers = {"Server": "nginx"}
        text = '<meta name="generator" content="WordPress 7.0.4">'

    def fake_get(url, **kw):
        tried.append(url)
        if "www." not in url:
            raise requests.exceptions.SSLError("certificado de otro nombre")
        return Resp()

    monkeypatch.setattr(tech_detect.requests, "get", fake_get)
    results = tech_detect.TechDetectTool().execute(QueryParameters(domain="presidencia.gob.ec"))
    assert tried == ["https://presidencia.gob.ec", "https://www.presidencia.gob.ec"]
    assert {r.raw_data["technology"] for r in results} >= {"nginx", "WordPress"}


def _report(tool):
    return ToolReport(case_id=1, tool_name=tool, raw_json="[]")


def test_cti_cross_says_tech_could_not_be_analysed_instead_of_zero():
    note = tech_scan_note([_report("Tech Detect"), _report("Domain WHOIS")], [])
    assert "no se pudo analizar" in note and "no significa que no haya riesgo" in note
    assert "no se analizó" in tech_scan_note([_report("Domain WHOIS")], [])
    assert tech_scan_note([_report("Tech Detect")], ["nginx"]) == ""


# ── F4-2 / N-3 directorios oficiales y datos de contacto ─────────────────────

def test_official_notary_directory_is_not_a_candidate():
    # PDF real que salía al 60 % en el perfil de Jefferson Pérez Quezada (otro Jefferson Pérez, notario en Cuenca)
    title = "PROVINCIA CANTÓN NOTARÍA NOTARIO (A) DIRECCIÓN TELÉFONO E-MAIL AZUAY CUENCA"
    url = "https://www.funcionjudicial.gob.ec/images/directorio-notarial/notarias+AZUAY2018.pdf"
    assert is_directory_result(title, url) == "directorio oficial de funcionarios"
    assert is_directory_result("Notarías", "https://sitio.gob.ec/doc.pdf",
                               "Notarías del cantón Cuenca · Notario: Juan Pérez") == "directorio oficial de funcionarios"
    assert is_directory_result("Nómina de servidores públicos 2024", "https://x.gob.ec/a") != ""
    assert is_directory_result("Directorio de funcionarios", "https://x.gob.ec/a") != ""


@pytest.mark.parametrize("title,url,snippet", [
    # "Directorio" también es la junta directiva de una federación: puede citar a la persona
    ("Nuevo directorio de la Federación Ecuatoriana de Atletismo", "https://fea.org.ec/noticia",
     "Jefferson Pérez integra el directorio"),
    ("Jefferson Pérez - Wikipedia", "https://es.wikipedia.org/wiki/Jefferson_P%C3%A9rez", "Marchista ecuatoriano"),
    ("Contacto", "https://jeffersonperez.com/contacto", "Escríbenos: teléfono y correo de la fundación"),
])
def test_real_pages_are_not_official_directories(title, url, snippet):
    assert is_directory_result(title, url, snippet) == ""


def test_profiler_skips_the_notary_directory():
    from osint_app.core.models import SearchResult
    from osint_app.profiler_engine import ProfilerEngine, SeedData, ToolResult

    eng = ProfilerEngine()
    eng.results = [ToolResult("Google Dorks", "ok", [SearchResult(
        title="PROVINCIA CANTÓN NOTARÍA NOTARIO (A) DIRECCIÓN TELÉFONO E-MAIL AZUAY CUENCA",
        url="https://www.funcionjudicial.gob.ec/images/directorio-notarial/notarias+AZUAY2018.pdf",
        snippet="JEFFERSON PÉREZ QUEZADA (07)2840123 notaria@ejemplo.ec", source_tool="Google Dorks",
        category="Registros EC", relevance_score=70)])]
    assert eng.extract_candidates(SeedData(name="Jefferson Pérez Quezada", country="Ecuador")) == []
    assert eng.skipped_listings == {"directorio oficial de funcionarios": 1}


@pytest.mark.parametrize("text,expected", [
    ("Escríbeme a juan.perez@gmail.com", "Escríbeme a j•••@gmail.com"),
    ("Cel 0991234567.", "Cel ••••••••67."),
    ("(07)2840123", "(••)•••••23"),
    ("+593 99 123 4567", "+••• •• ••• ••67"),
    ("Tel. 07-284-0123", "Tel. ••-•••-••23"),
])
def test_emails_and_phones_are_masked(text, expected):
    assert mask_contacts(text) == expected


@pytest.mark.parametrize("text", [
    "Medallas en 1996 2000 2004 2008", "CVE-2026-111497", "fecha 2026-10-29", "29/10/2026",
    "1.234.567 suscriptores", "https://x.com/a/status/1234567890123", "Marca 1:20:49 en 20 km", "", None,
])
def test_numbers_that_are_not_phones_stay(text):
    assert mask_contacts(text) == (text or "")


def test_mask_helpers_keep_a_hint_of_the_value():
    assert mask_email("midu@gmail.com") == "m•••@gmail.com"
    assert mask_phone("+56 9 1234 5688") == "+•• • •••• ••88"


def _midudev_report():
    candidates = [{"source": "WebSearch", "url": "https://midu.dev/contacto", "title": "Contacto midudev",
                   "snippet": "Escríbeme a midudev.ejemplo@gmail.com o al +56 9 1234 5688", "confidence": 70,
                   "category": "Web"}]
    return build_person_report({"name": "Miguel Ángel Durán", "username": "midudev"}, candidates)


def test_ficha_hides_contacts_by_default_and_shows_them_on_request():
    report = _midudev_report()
    assert len(report["contacts"]) == 2                   # el dato no se pierde: sigue en la ficha
    hidden = render_person_html(report)
    assert "midudev.ejemplo@gmail.com" not in hidden and "1234 5688" not in hidden
    assert "m•••@gmail.com" in hidden and "Ver con datos de contacto" in hidden
    shown = render_person_html(report, show_contacts=True)
    assert "midudev.ejemplo@gmail.com" in shown and "+56 9 1234 5688" in shown
    assert "Ocultos por protección de datos" not in shown


def test_links_are_not_broken_by_the_masking():
    candidates = [{"source": "WebSearch", "url": "https://x.com/midudev/status/1234567890123",
                   "title": "midudev en X", "snippet": "tel 0991234567", "confidence": 70, "category": "Web"}]
    page = render_person_html(build_person_report({"name": "Miguel Ángel Durán"}, candidates))
    assert 'href="https://x.com/midudev/status/1234567890123"' in page


def test_reports_view_masks_snippets_and_says_so():
    raw = json.dumps([{"title": "Jefferson Pérez | Facebook", "url": "https://facebook.com/jp",
                       "snippet": "Contacto: 0991234567", "relevance_score": 70, "category": "Web"}])
    text = readable_results("WebSearch", raw)
    assert "0991234567" not in text and "••••••••67" in text and "ocultos" in text
    assert "ocultos" not in readable_results("WebSearch", json.dumps([{"title": "t", "snippet": "sin datos"}]))


# ── F4-3 IP Reputation: salida de Tor = riesgo alto ──────────────────────────

def test_tor_exit_alone_is_high_risk(monkeypatch):
    # 171.25.193.25 sigue en la lista oficial, pero GreyNoise dejó de verla escaneando: bajaba de 65 a 25
    lists = {"tor": {"171.25.193.25"}, "drop": [], "firehol": [], "urlhaus": {}}
    monkeypatch.setattr(ip_reputation, "_download_list", lambda name: lists.get(name))
    tool = ip_reputation.IpReputationTool()
    monkeypatch.setattr(tool, "_internetdb", lambda ip: ({"ports": [443], "tags": ["tor"]}, ""))
    monkeypatch.setattr(tool, "_greynoise", lambda ip: ({"noise": False, "riot": False}, ""))
    result = tool.execute(QueryParameters(ip="171.25.193.25"))[0]
    assert result.raw_data["risk"] == "alto" and result.raw_data["score"] >= 50
    clean = tool.execute(QueryParameters(ip="8.8.8.8"))[0]
    assert clean.raw_data["risk"] == "bajo"


# ── F4-4 escala fija de la ventana ───────────────────────────────────────────

def test_gui_uses_system_dpi_awareness_on_windows():
    from pathlib import Path
    source = (Path(__file__).parents[1] / "main.py").read_text(encoding="utf-8")
    start = source.index('os.environ.setdefault("QT_QPA_PLATFORM", "windows:dpiawareness=1")')
    assert start < source.index("app = QApplication(sys.argv)")      # antes de crear la aplicación


# ── Colores de las tablas y columna Producto ─────────────────────────────────

def test_stylesheet_does_not_override_cell_colours():
    # "color" en QTableWidget::item tapaba setForeground: ni el rojo de lo explotado en CTI ni la confianza se veían
    import re
    from pathlib import Path
    qss = (Path(__file__).parents[1] / "gui" / "style.qss").read_text(encoding="utf-8")
    for rule in re.findall(r"QTableWidget::item, QTreeWidget::item \{([^}]*)\}", qss):
        assert not re.search(r"(?<![-\w])color\s*:", rule)


@pytest.fixture(scope="module")
def productos():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / "sentinel_unified" / "modules" / "cti" / "productos.py"
    spec = importlib.util.spec_from_file_location("productos_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("title,product", [
    # títulos reales de avisos de Microsoft (MSRC)
    ("ipv4: free inet_opt and ireq_opt after an RCU grace period", "Linux kernel"),
    ("net/sched: act_ct: don't WARN on benign flow_offload_alloc() failure", "Linux kernel"),
    ("SUNRPC: Reject short RFC 4121 MIC tokens in gss_krb5_verify_mic_v2", "Linux kernel"),
    ("Chromium CVE-2026-113005: Memory corruption", "Google Chromium"),
    ("Apache HTTP Server: mod_dav_fs namespace overflow", "Apache HTTP Server"),
    ("Integer Overflow or Wraparound in GitLab", ""),
    ("Authorization: Negotiate sent to foreign origin", ""),
    ("Windows Resilient File System (ReFS) Elevation of Privilege", "Microsoft Windows Resilient File System (ReFS)"),
    ("Microsoft Office Outlook Remote Code Execution Vulnerability", "Microsoft Office Outlook"),
    ("Remote Desktop Client Remote Code Execution", "Microsoft Remote Desktop Client"),
    ("Role: Windows Fax Service Elevation of Privilege", "Microsoft Windows Fax Service"),
    ("Desktop Window Manager Elevation of Privilege", "Microsoft Desktop Window Manager"),
    ("Linux Kernel Elevation of Privilege", "Linux kernel"),
    ("SQLite Elevation of Privilege", "SQLite"),
    ("BlueZ A2DP Stack-based Buffer Overflow Remote Code Execution", ""),
    ("Uncontrolled Resource Consumption in Elasticsearch Leading to Denial of Service", ""),
])
def test_msrc_product_is_not_always_microsoft(productos, title, product):
    assert productos.msrc_product(title) == product


def test_catalog_prefers_kev_and_ignores_unclear_msrc(productos):
    items = [
        {"fuente_id": "microsoft_msrc", "vendor": "Microsoft", "product": "ipv4: free inet_opt and ireq_opt",
         "cves": ["CVE-2026-98432"]},
        {"fuente_id": "microsoft_msrc", "vendor": "Microsoft", "product": "Integer Overflow or Wraparound in GitLab",
         "cves": ["CVE-2026-110264"]},
        {"fuente_id": "microsoft_msrc", "vendor": "Microsoft", "product": "Google:  Buffer overflow in the Brotli decoder",
         "cves": ["CVE-2026-111497"]},
        {"fuente_id": "cisa_kev", "vendor": "Google", "product": "Brotli", "cves": ["CVE-2026-111497"]},
    ]
    assert productos.catalog_products(items) == {"CVE-2026-98432": "Linux kernel", "CVE-2026-111497": "Google Brotli"}
    assert productos.item_product({"fuente_id": "cisa_kev", "vendor": "Broadcom", "product": "VMware ESX"}) == \
        "Broadcom VMware ESX"


# ── Homónimos sueltos de la evaluación 4 ─────────────────────────────────────

def _li(title, url, snippet=""):
    from osint_app.core.models import SearchResult
    return SearchResult(title=title, url=url, snippet=snippet, source_tool="WebSearch", category="Web",
                        relevance_score=70)


def _candidates(seed, results):
    from osint_app.profiler_engine import ProfilerEngine, ToolResult
    eng = ProfilerEngine()
    eng.results = [ToolResult("WebSearch", "ok", results)]
    return {c.url: c for c in eng.extract_candidates(seed, min_confidence=0)}


def test_linkedin_of_another_profession_is_flagged_in_the_table():
    from osint_app.profiler_engine import SeedData
    doctor = "https://ec.linkedin.com/in/moises-caicedo-bautin-591642161"
    cedar = "https://www.linkedin.com/in/gonzalo-plata-221605266"
    cands = _candidates(SeedData(name="Moisés Caicedo", context="futbolista Chelsea", country="Ecuador"), [
        _li("Moises Caicedo Bautin - Médico en Ministerio de Salud - Ecuador", doctor)])
    assert "Médico en Ministerio de Salud" in cands[doctor].warning
    cands = _candidates(SeedData(name="Gonzalo Plata", context="futbolista", country="Ecuador"), [
        _li("Gonzalo Plata - Cedar Fair Entertainment Company | LinkedIn", cedar,
            "Experience: Cedar Fair Entertainment Company · Location: Charlotte")])
    assert "Cedar Fair" in cands[cedar].warning


def test_own_linkedin_is_not_flagged_for_its_headline():
    from osint_app.profiler_engine import SeedData
    url = "https://es.linkedin.com/in/midudev"
    cands = _candidates(SeedData(name="Miguel Ángel Durán", context="programador divulgador", username="midudev"), [
        _li("Miguel Ángel Durán García - Inteligencia Artificial ... | LinkedIn", url, "Experiencia: midudev")])
    assert "LinkedIn dice" not in cands[url].warning


def test_sports_job_matches_an_athlete_and_empty_headline_uses_experience():
    from osint_app.utils.homonyms import other_job, readable_linkedin_title
    title, snippet = "Glenda Morejón - -- | LinkedIn", "-- · Experiencia: Ministerio de deporte Ecuador · Ubicación: Cuenca"
    assert other_job(title, snippet, "marchista atleta") == ""
    assert readable_linkedin_title(title, snippet) == "Glenda Morejón - Ministerio de deporte Ecuador"
    assert readable_linkedin_title("Juan - Abogado | LinkedIn", "") == "Juan - Abogado | LinkedIn"


def test_olympic_venue_with_year_is_not_where_the_person_lives():
    from osint_app.utils.homonyms import homonym_signals
    text = "la medallista olímpica inicia su ciclo hacia Los Ángeles 2028"
    assert homonym_signals(text, "https://x.com/Primicias/status/1", "Ecuador", "marchista atleta") == []
    assert homonym_signals("Glenda Morejón vive en Los Ángeles", "https://x.com/a", "Ecuador", "marchista")


def test_second_channel_that_links_to_the_known_account_is_not_another_person():
    seed = {"name": "Miguel Ángel Durán", "context": "programador divulgador", "username": "midudev"}
    cands = [
        {"source": "GitHubOSINT", "url": "https://youtube.com/@midudev", "title": "Youtube de midudev",
         "snippet": "", "confidence": 70, "category": "Web"},
        {"source": "Google Dorks", "url": "https://www.youtube.com/@midulive", "title": "midulive - YouTube",
         "snippet": "Repositorio de código: https://github.com/midudev/aprendiendo", "confidence": 50,
         "category": "Web"},
    ]
    report = build_person_report(seed, cands)
    assert not any("midulive" in h["url"] for h in report["homonyms"])
    live = [a for a in report["accounts"] if "midulive" in a["url"]][0]
    assert "enlaza a @midudev" in live["note"]


def test_a_rejected_account_stays_out_under_any_of_its_addresses():
    seed = {"name": "Glenda Morejón", "context": "marchista atleta", "country": "Ecuador"}
    cands = [{"source": s, "url": u, "title": "Glenda Morejon - OMEGA Boutique | LinkedIn", "snippet": "",
              "confidence": 30, "category": "Web", "warning": "posible homónimo"}
             for s, u in (("WebSearch", "https://ec.linkedin.com/in/glenda-x"),
                          ("Google Dorks", "https://www.linkedin.com/in/glenda-x"))]
    report = build_person_report(seed, cands, rejected_urls=["https://ec.linkedin.com/in/glenda-x"])
    assert report["homonyms"] == [] and report["accounts"] == []


# ── Interfaz y textos menores ────────────────────────────────────────────────

def test_retry_bar_explains_why_and_when():
    pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    from osint_app.gui.tab_profiling import retry_bar_text
    now = retry_bar_text(3, 0)
    assert "3 consulta(s)" in now and "bloquearon" in now and "se conservan" in now
    assert "en 2 min" in retry_bar_text(3, 90)


def test_suggested_tools_need_their_key():
    pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    from types import SimpleNamespace
    from osint_app.gui.tab_correlation import ENTITY_LABELS, available_tools
    tools = {"Hunter.io": SimpleNamespace(is_available=True, requires_api_key=True, api_key=""),
             "crt.sh": SimpleNamespace(is_available=True, requires_api_key=False, api_key=""),
             "CENSYS": SimpleNamespace(is_available=True, requires_api_key=True, api_key="guardada"),
             "Subfinder": SimpleNamespace(is_available=False)}
    assert available_tools(SimpleNamespace(tools=tools)) == {"crt.sh", "CENSYS"}
    assert ENTITY_LABELS["name"] == "Nombres" and ENTITY_LABELS["context"] == "Contexto"


def test_urlhaus_is_not_requested_and_the_report_says_why(monkeypatch):
    calls = []
    monkeypatch.setattr(ip_reputation.requests, "get", lambda url, **kw: calls.append(url))
    assert ip_reputation._download_list("urlhaus") is None and calls == []
    lists = {"tor": set(), "drop": [], "firehol": []}
    monkeypatch.setattr(ip_reputation, "_download_list", lambda name: lists.get(name))
    tool = ip_reputation.IpReputationTool()
    monkeypatch.setattr(tool, "_internetdb", lambda ip: ({}, ""))
    monkeypatch.setattr(tool, "_greynoise", lambda ip: ({"noise": False}, ""))
    snippet = tool.execute(QueryParameters(ip="8.8.8.8"))[0].snippet
    assert "Sin consultar: URLhaus (abuse.ch exige ahora una clave gratuita)" in snippet
    assert "No respondieron" not in snippet


def test_summary_sentence_reads_well():
    report = build_person_report({"name": "Jefferson Pérez"}, [
        {"source": "Wikidata", "url": "https://www.wikidata.org/wiki/Q1", "title": "Jefferson Pérez",
         "snippet": "Marchista", "confidence": 90, "category": "Persona pública"}])
    assert "Sobre esta persona: tiene una <b>ficha pública</b>" in render_person_html(report)
