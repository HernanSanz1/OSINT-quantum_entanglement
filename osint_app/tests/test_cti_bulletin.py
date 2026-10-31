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
                 "validar"):
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
