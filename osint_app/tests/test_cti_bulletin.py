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
    for name in ("render", "dossier", "clientes", "exposicion_cve", "seleccion_cliente", "fuentes"):
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
