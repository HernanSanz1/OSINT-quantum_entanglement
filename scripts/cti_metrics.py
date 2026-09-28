#!/usr/bin/env python3
"""Métricas reales del CTI y de su cruce con las tecnologías de los clientes.

Uso:
    python scripts/cti_metrics.py

Lee el almacén CTI real (sentinel_unified/modules/cti/store/items.jsonl) y el
inventario de tecnologías por cliente, y mide cuántas de las tecnologías que usa
cada cliente tienen CVEs activos en la inteligencia de amenazas.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sentinel_unified" / "modules" / "cti"))

from osint_app.cti_link import CtiStore  # noqa: E402


def _tech_hits(store, terms):
    """Todas las coincidencias CTI para una tecnología (cualquiera de sus términos)."""
    hits = []
    for term in terms:
        hits += store.search_tech(term, limit=500)
    return hits


def main() -> int:
    store = CtiStore.load()
    s = store.summary()

    print("=" * 64)
    print(" MÉTRICAS CTI — datos reales del almacén")
    print("=" * 64)
    print(f"  Ítems totales ............ {s['items']}")
    print(f"  CVEs únicos indexados .... {s['cves']}")
    print(f"  KEV (explotación activa) . {s['kev']}")
    print(f"  Con exploit (MSRC) ....... {s['exploited']}")
    print(f"  Ligados a ransomware ..... {s['ransomware']}")
    print(f"  Vendors distintos ........ {s['vendors']}")

    try:
        from clientes import CLIENTES
    except ImportError:
        print("\n(No se pudo cargar el inventario de clientes.)")
        return 0

    print()
    print("=" * 64)
    print(" COBERTURA POR CLIENTE — tecnologías con CVEs activos")
    print("=" * 64)

    tot_tech = tot_cve = tot_active = 0
    for name, client in CLIENTES.items():
        techs = client.get("tecnologias", [])
        with_cve = with_active = 0
        active_names = []
        for tech in techs:
            hits = _tech_hits(store, tech.get("terms", ()))
            if hits:
                with_cve += 1
            if any(h.actively_exploited for h in hits):
                with_active += 1
                active_names.append(tech.get("nombre", "?"))
        tot_tech += len(techs)
        tot_cve += with_cve
        tot_active += with_active
        print(f"\n  {name}: {len(techs)} tecnologías | con CVEs: {with_cve} "
              f"| con CVE EXPLOTADO: {with_active}")
        for nm in active_names[:8]:
            print(f"      ⚠️  {nm}")

    print()
    print("-" * 64)
    print(f"  TOTAL: {tot_tech} tecnologías | {tot_cve} con CVEs "
          f"| {tot_active} con CVE explotado activamente")
    print("-" * 64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
