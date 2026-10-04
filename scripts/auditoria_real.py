#!/usr/bin/env python3
"""Pruebas REALES de las herramientas contra objetivos públicos (no simulaciones).

Uso:
    python scripts/auditoria_real.py            # todas
    python scripts/auditoria_real.py wikidata   # solo las que contengan esa palabra

Cada prueba ejecuta la herramienta de verdad y comprueba un HECHO público verificable (p. ej. que la cuenta X
oficial de Daniel Noboa sea "DanielNoboaOk" o que una IP de salida de Tor se detecte como Tor). Sirve para
detectar cuándo una fuente cambia su formato, bloquea o deja de responder, cosa que las pruebas simuladas no ven.

Necesita Internet. Los datos se guardan en una carpeta temporal (no toca los casos del usuario). Algunas fuentes
limitan la cuota (GitHub sin token: 60 consultas/hora; HackerTarget: 50/día): no lo ejecutes en bucle.
Objetivos: solo personas públicas, organizaciones e infraestructura pública.
"""
import os
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SENTINEL_DATA_DIR", tempfile.mkdtemp(prefix="sentinel_auditoria_"))

from osint_app.core.models import QueryParameters  # noqa: E402
from osint_app.tools import build_tool_registry  # noqa: E402

TOOLS = build_tool_registry()


def run(tool, **params):
    t = TOOLS[tool]
    msgs = []
    t._progress_cb = msgs.append
    return t.execute(QueryParameters(**params)), msgs


def text(results):
    return " ".join(f"{r.title} {r.snippet} {r.url}" for r in results).lower()


# (nombre, función que devuelve (ok, detalle))
def wikidata_noboa():
    r, _ = run("Wikidata", target_name="Daniel Noboa Azín", context="presidente Ecuador")
    return "x.com/danielnoboaok" in text(r), f"{len(r)} resultados"


def wikidata_homonimo():
    r, m = run("Wikidata", target_name="Luisa González")
    return any("homónimo" in x.lower() or "personas con ese nombre" in x for x in m + [y.snippet for y in r]), m[-1][:90] if m else ""


def wikidata_nombre_completo():
    r, _ = run("Wikidata", target_name="Jefferson Pérez Quezada", context="atleta Ecuador")
    return "jeffersonperezq" in text(r), f"{len(r)} resultados"


def github_correos_commits():
    r, _ = run("GitHubOSINT", username="torvalds")
    t = text(r)
    if "limitó las consultas" in t:
        return None, "GitHub sin cuota (añade un token con --set-key GitHub)"
    return "torvalds@linux-foundation.org" in t, f"{len(r)} resultados"


def websearch_persona():
    r, m = run("WebSearch", target_name="Rafael Correa", context="expresidente Ecuador")
    hits = sum(1 for x in r if "correa" in (x.title + x.snippet).lower())
    if not r and any("bloquearon" in x for x in m):
        return None, "todos los buscadores bloquearon (configura BraveSearch)"
    return hits >= 5, f"{len(r)} resultados, {hits} mencionan a la persona"


def subdominios_respaldo():
    r, m = run("crt.sh", domain="python.org")
    return len(r) >= 10, (m[-1][:110] if m else "")


def mail_health_redirect():
    r, _ = run("Mail Health", domain="gmail.com")
    return "vía redirect" in text(r), r[0].snippet[:90] if r else ""


def tech_detect_wordpress():
    r, m = run("Tech Detect", domain="wordpress.org")
    return "wordpress" in text(r), (m[-1][:90] if m else "")


def ip_reputation_tor():
    r, _ = run("IP Reputation", ip="185.220.101.1")
    return "tor" in text(r), r[0].title if r else ""


def ip_reputation_google():
    r, _ = run("IP Reputation", ip="8.8.8.8")
    return bool(r) and "riesgo bajo" in r[0].title, r[0].title if r else ""


def link_shield_legitimo():
    r, _ = run("Link Shield", url="https://www.python.org/")
    return bool(r) and r[0].raw_data.get("level") == "bajo", str(r[0].raw_data.get("score")) if r else ""


def link_shield_phishing_activo():
    import requests
    feed = [u for u in requests.get("https://openphish.com/feed.txt", timeout=20).text.split() if u.startswith("http")]
    if not feed:
        return None, "OpenPhish sin datos"
    r, _ = run("Link Shield", url=feed[0])
    return bool(r) and r[0].raw_data.get("level") == "alto", feed[0].replace("http", "hxxp", 1)[:60]


def wayback_dominio():
    r, m = run("Wayback Machine", domain="sri.gob.ec")
    return len(r) >= 50, (m[-1][:80] if m else "")


def whois_cctld():
    r, _ = run("Domain WHOIS", domain="presidencia.gob.ec")
    return "ecuadordomain" in text(r), r[0].snippet[:80] if r else ""


def telefono_ecuador():
    r, _ = run("phonenumbers", phone="0991234567")
    return "ecuador" in text(r), r[0].snippet if r else ""


def file_metadata_exif():
    r, m = run("File Metadata", url="https://upload.wikimedia.org/wikipedia/commons/3/3f/Fronalpstock_big.jpg")
    return "nikon" in text(r), (m[-1][:80] if m else "")


def sherlock_usuario():
    if not TOOLS["Sherlock"].is_available:
        return None, "Sherlock no instalado (pip install sherlock-project)"
    r, _ = run("Sherlock", username="torvalds", extra_args="--site GitHub --timeout 10")
    return "github.com/torvalds" in text(r), f"{len(r)} perfiles"


def maigret_usuario():
    if not TOOLS["Maigret"].is_available:
        return None, "Maigret no instalado (pip install maigret)"
    r, m = run("Maigret", username="kentcdodds")
    return len(r) >= 10 and "kent c. dodds" in text(r), (m[-1][:80] if m else "")


TESTS = [wikidata_noboa, wikidata_homonimo, wikidata_nombre_completo, github_correos_commits, websearch_persona,
         subdominios_respaldo, mail_health_redirect, tech_detect_wordpress, ip_reputation_tor, ip_reputation_google,
         link_shield_legitimo, link_shield_phishing_activo, wayback_dominio, whois_cctld, telefono_ecuador,
         file_metadata_exif, sherlock_usuario, maigret_usuario]


def main():
    wanted = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    counts = {"OK": 0, "FALLO": 0, "OMITIDA": 0}
    for test in TESTS:
        if wanted and wanted not in test.__name__:
            continue
        start = time.time()
        try:
            ok, detail = test()
        except Exception as e:
            ok, detail = False, f"excepción {type(e).__name__}: {e}"[:150]
            traceback.print_exc(limit=1)
        label = "OMITIDA" if ok is None else "OK" if ok else "FALLO"
        counts[label] += 1
        print(f"[{label:7}] {test.__name__:28} {time.time() - start:5.1f}s  {detail}")
        sys.stdout.flush()
    print(f"\nResumen: {counts['OK']} OK · {counts['FALLO']} fallos · {counts['OMITIDA']} omitidas")
    return 1 if counts["FALLO"] else 0


if __name__ == "__main__":
    sys.exit(main())
