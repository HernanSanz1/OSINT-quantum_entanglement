"""
Puente CTI ↔ casos.

Lee el almacén del módulo CTI (sentinel_unified/modules/cti/store/items.jsonl)
y lo indexa para poder cruzar las entidades de un caso de investigación con la
inteligencia de amenazas: ¿un CVE del caso está siendo explotado? ¿el objetivo
usa una tecnología con vulnerabilidades activas?

Este módulo es la BASE (lectura + índice). La correlación en sí vive en
correlate_case_with_cti().
"""
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# Ruta por defecto del almacén CTI, relativa a la raíz del repo.
DEFAULT_STORE = (
    Path(__file__).resolve().parent.parent
    / "sentinel_unified" / "modules" / "cti" / "store" / "items.jsonl"
)


def _truthy(value) -> bool:
    """Acepta booleanos reales o texto ('True'/'true'/'1')."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "si", "sí")


def normalize_cves(value) -> List[str]:
    """Devuelve la lista de CVEs (en mayúsculas) de un campo que puede venir
    como lista, como texto con la lista, o vacío."""
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        text = " ".join(str(v) for v in value)
    else:
        text = str(value)
    seen, out = set(), []
    for m in CVE_RE.findall(text):
        cve = m.upper()
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


@dataclass
class CtiHit:
    """Un ítem CTI relevante para una entidad del caso."""
    cve: str
    title: str = ""
    vendor: str = ""
    product: str = ""
    source: str = ""
    url: str = ""
    severity: str = ""
    kev: bool = False           # Known Exploited Vulnerability (CISA)
    exploited: bool = False
    ransomware: bool = False

    @property
    def actively_exploited(self) -> bool:
        return self.kev or self.exploited

    def to_dict(self) -> Dict:
        return {
            "cve": self.cve, "title": self.title, "vendor": self.vendor,
            "product": self.product, "source": self.source, "url": self.url,
            "severity": self.severity, "kev": self.kev,
            "exploited": self.exploited, "ransomware": self.ransomware,
            "actively_exploited": self.actively_exploited,
        }


def _to_hit(item: Dict, cve: str) -> CtiHit:
    return CtiHit(
        cve=cve,
        title=str(item.get("titulo", "") or ""),
        vendor=str(item.get("vendor", "") or ""),
        product=str(item.get("product", "") or ""),
        source=str(item.get("fuente", "") or ""),
        url=str(item.get("url", "") or ""),
        severity=str(item.get("severity", "") or ""),
        kev=_truthy(item.get("kev")),
        exploited=_truthy(item.get("exploited")),
        ransomware=_truthy(item.get("ransomware")),
    )


class CtiStore:
    """Índice en memoria del almacén CTI para consultas rápidas."""

    def __init__(self, items: List[Dict]):
        self._items = items
        self._by_cve: Dict[str, List[Dict]] = {}
        for item in items:
            for cve in normalize_cves(item.get("cves")):
                self._by_cve.setdefault(cve, []).append(item)

    @classmethod
    def load(cls, path: Path = None) -> "CtiStore":
        """Carga items.jsonl. Si no existe o falla, devuelve un almacén vacío."""
        path = Path(path) if path else DEFAULT_STORE
        items: List[Dict] = []
        if not path.exists():
            logger.warning(f"CTI store no encontrado en {path}")
            return cls(items)
        try:
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError as e:
            logger.error(f"No se pudo leer el CTI store: {type(e).__name__}")
        return cls(items)

    def __len__(self) -> int:
        return len(self._items)

    @property
    def cve_count(self) -> int:
        return len(self._by_cve)

    def by_cve(self, cve: str) -> List[CtiHit]:
        """Ítems CTI que mencionan ese CVE exacto."""
        cve = (cve or "").strip().upper()
        return [_to_hit(item, cve) for item in self._by_cve.get(cve, [])]

    def search_tech(self, term: str, limit: int = 25) -> List[CtiHit]:
        """Ítems cuyo vendor o product contienen `term` (coincidencia laxa).

        Sirve para: 'el objetivo usa <tecnología>' → CVEs activos de esa tech.
        """
        term = (term or "").strip().lower()
        if len(term) < 3:
            return []
        hits: List[CtiHit] = []
        for item in self._items:
            haystack = f"{item.get('vendor', '')} {item.get('product', '')}".lower()
            if term in haystack:
                cves = normalize_cves(item.get("cves"))
                hits.append(_to_hit(item, cves[0] if cves else ""))
                if len(hits) >= limit:
                    break
        return hits


def collect_tech_terms_from_reports(reports) -> List[str]:
    """Extrae las tecnologías detectadas (por Tech Detect) de los reportes de un
    caso, para cruzarlas con el CTI. Lee los resultados de categoría 'Technology'.
    """
    terms: List[str] = []
    seen = set()
    for report in reports or []:
        raw = getattr(report, "raw_json", None) or (report.get("raw_json") if isinstance(report, dict) else None)
        if not raw:
            continue
        try:
            items = json.loads(raw)
        except (ValueError, TypeError):
            continue
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            tech = None
            if item.get("category") == "Technology":
                tech = (item.get("raw_data") or {}).get("technology") or item.get("title")
            if tech and tech.lower() not in seen:
                seen.add(tech.lower())
                terms.append(tech)
    return terms


def _entity_field(entity, name: str):
    """Lee un campo de una entidad, sea objeto (.attr) o dict."""
    if isinstance(entity, dict):
        return entity.get(name)
    return getattr(entity, name, None)


def correlate_entities_with_cti(entities, store: "CtiStore",
                                tech_terms: Optional[List[str]] = None) -> Dict:
    """Cruza las entidades de un caso con la inteligencia de amenazas (CTI).

    - Entidades de tipo 'cve' → coincidencia exacta con el CTI (fuerte).
    - tech_terms (tecnologías del objetivo) → CVEs de ese vendor/product.

    Devuelve un dict serializable con las coincidencias y un resumen.
    """
    cve_matches: List[Dict] = []
    seen_cve = set()
    for entity in entities or []:
        if _entity_field(entity, "entity_type") != "cve":
            continue
        value = _entity_field(entity, "value")
        for cve in normalize_cves(value):
            if cve in seen_cve:
                continue
            seen_cve.add(cve)
            hits = store.by_cve(cve)
            if hits:
                cve_matches.append({
                    "cve": cve,
                    "actively_exploited": any(h.actively_exploited for h in hits),
                    "ransomware": any(h.ransomware for h in hits),
                    "hits": [h.to_dict() for h in hits],
                })

    tech_matches: List[Dict] = []
    for term in dict.fromkeys((t or "").strip().lower() for t in (tech_terms or []) if t):
        hits = store.search_tech(term)
        if hits:
            tech_matches.append({
                "term": term,
                "count": len(hits),
                "actively_exploited": sum(1 for h in hits if h.actively_exploited),
                "hits": [h.to_dict() for h in hits],
            })

    return {
        "cve_matches": cve_matches,
        "tech_matches": tech_matches,
        "total_cve_matches": len(cve_matches),
        "total_tech_matches": len(tech_matches),
        "actively_exploited": sum(1 for m in cve_matches if m["actively_exploited"]),
    }
