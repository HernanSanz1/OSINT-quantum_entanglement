"""
Wikidata — ficha estructurada de personas públicas (sin clave, sin raspado).

Por qué: los buscadores bloquean el raspado (captcha) y devuelven texto suelto. Wikidata es una base abierta
(CC0) mantenida por la comunidad con datos ESTRUCTURADOS y referenciados de personas públicas: fecha y lugar
de nacimiento, nacionalidad, cargos, estudios, empleadores, partido, familiares y —lo más útil para OSINT— sus
cuentas oficiales (X/Twitter, Instagram, Facebook, LinkedIn, GitHub, YouTube, TikTok) y web oficial.

Probado en real (2026-10-04): Daniel Noboa (X, Instagram, Facebook), Rafael Correa (cuentas y nombre completo
"Rafael Vicente Correa Delgado"), Linus Torvalds (GitHub "torvalds", LinkedIn), Jefferson Pérez.
Homónimos: "Luisa González" devuelve 5 personas y la política ecuatoriana sale 3.ª → se elige por contexto
y, si no hay forma de distinguir, se avisa en vez de adivinar.

Solo sirve para personas con ficha en Wikidata (figuras públicas); para el resto devuelve 0 sin error.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple

import requests

from ..core.base_tool import OSINTTool
from ..core.models import QueryParameters, SearchResult, ToolRequirements
from ..utils.person_match import name_match, normalize_text

logger = logging.getLogger(__name__)

API = "https://www.wikidata.org/w/api.php"
# Política de Wikimedia: User-Agent con forma de contacto; los genéricos reciben HTTP 429/403
USER_AGENT = "SENTINEL-OSINT/2.0 (https://github.com/HernanSanz1/OSINT-quantum_entanglement; investigacion OSINT)"
TIMEOUT = 15
HUMAN = "Q5"

# Propiedad → (etiqueta, plantilla de URL del perfil)
SOCIAL = {
    "P2002": ("X/Twitter", "https://x.com/{}"),
    "P2003": ("Instagram", "https://www.instagram.com/{}"),
    "P2013": ("Facebook", "https://www.facebook.com/{}"),
    "P6634": ("LinkedIn", "https://www.linkedin.com/in/{}"),
    "P2037": ("GitHub", "https://github.com/{}"),
    "P2397": ("YouTube", "https://www.youtube.com/channel/{}"),
    "P7085": ("TikTok", "https://www.tiktok.com/@{}"),
    "P4033": ("Mastodon", ""),
    "P12361": ("Bluesky", "https://bsky.app/profile/{}"),
}
# Propiedad → etiqueta de datos personales (los valores son entidades: se resuelven a texto)
ENTITY_FIELDS = {
    "P27": "Nacionalidad", "P19": "Lugar de nacimiento", "P39": "Cargos", "P106": "Ocupación",
    "P69": "Estudios", "P108": "Empleadores", "P102": "Partido", "P26": "Cónyuge", "P22": "Padre",
    "P25": "Madre", "P40": "Hijos", "P3373": "Hermanos",
}
TEXT_FIELDS = {"P1559": "Nombre nativo", "P1477": "Nombre de nacimiento"}
MAX_CANDIDATES = 8
TYPO_RATIO = 0.85          # "Sommerferld" (errata real en Wikidata) ≈ "Sommerfeld"


def fuzzy_name_points(name: str, text: str) -> float:
    """40 si TODAS las palabras del nombre están en el texto, admitiendo erratas leves en palabras de 5+ letras."""
    from difflib import SequenceMatcher
    from ..utils.person_match import name_tokens
    tokens, words = name_tokens(name), normalize_text(text).split()
    if len(tokens) < 2:
        return 0.0

    def close(t: str) -> bool:
        return t in words or (len(t) >= 5 and any(len(w) >= 5 and SequenceMatcher(None, t, w).ratio() >= TYPO_RATIO for w in words))
    return 40.0 if all(close(t) for t in tokens) else 0.0


class WikidataTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Wikidata",
            "Ficha estructurada de personas públicas: datos, cargos y cuentas oficiales verificadas",
            ToolRequirements(
                mandatory=["target_name"],
                optional=["observable", "location", "company"],
                produces=["name", "url", "username", "location", "company", "note"],
                hint="Nombre de una persona pública. El contexto (país, cargo, ciudad) ayuda a separar homónimos.",
            ),
        )
        self._python_pkgs = ["requests"]
        self._install_cmd = "pip install requests"

    # ── consultas ────────────────────────────────────────────────────────────
    def _api(self, **params) -> dict:
        params.setdefault("format", "json")
        resp = requests.get(API, params=params, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _short_forms(name: str) -> List[str]:
        """Formas cortas con las que suele estar registrada una persona hispana en Wikidata.

        "Jefferson Pérez Quezada" está como "Jefferson Pérez" (prueba real: con el nombre completo daba 0).
        3 palabras: N A1 · 4: N1 A1 y N1 N2 A1.
        """
        parts = name.split()
        if len(parts) == 3:
            return [f"{parts[0]} {parts[1]}"]
        if len(parts) >= 4:
            return [f"{parts[0]} {parts[-2]}", f"{parts[0]} {parts[1]} {parts[-2]}"]
        return []

    def _search_ids(self, name: str) -> List[str]:
        ids: List[str] = []
        for query in [name, *self._short_forms(name)]:
            for lang in ("es", "en"):
                data = self._api(action="wbsearchentities", search=query, language=lang, uselang=lang,
                                 type="item", limit=MAX_CANDIDATES)
                for item in data.get("search", []):
                    if item["id"] not in ids:
                        ids.append(item["id"])
                if len(ids) >= MAX_CANDIDATES:
                    break
            if ids:
                break                                   # la forma completa (o la primera corta) ya encontró fichas
        return ids[:MAX_CANDIDATES]

    def _entities(self, ids: List[str], props: str) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        for i in range(0, len(ids), 50):
            data = self._api(action="wbgetentities", ids="|".join(ids[i:i + 50]), props=props, languages="es|en")
            out.update(data.get("entities", {}))
        return out

    # ── utilidades ───────────────────────────────────────────────────────────
    @staticmethod
    def _label(entity: dict) -> str:
        labels = entity.get("labels", {})
        return (labels.get("es") or labels.get("en") or {}).get("value", "")

    @staticmethod
    def _description(entity: dict) -> str:
        desc = entity.get("descriptions", {})
        return (desc.get("es") or desc.get("en") or {}).get("value", "")

    @staticmethod
    def _values(entity: dict, prop: str) -> List:
        """Valores de una propiedad, sin los marcados como obsoletos (rango 'deprecated')."""
        values = []
        for claim in entity.get("claims", {}).get(prop, []):
            if claim.get("rank") == "deprecated":
                continue
            value = claim.get("mainsnak", {}).get("datavalue", {}).get("value")
            if value is not None:
                values.append(value)
        return values

    @staticmethod
    def _is_human(entity: dict) -> bool:
        return any(isinstance(v, dict) and v.get("id") == HUMAN for v in WikidataTool._values(entity, "P31"))

    @staticmethod
    def _date(value) -> str:
        if isinstance(value, dict) and value.get("time"):
            match = re.match(r"[+-]?(\d{4})-(\d{2})-(\d{2})", value["time"])
            if match:
                y, m, d = match.groups()
                return y if (m, d) == ("00", "00") or value.get("precision", 11) <= 9 else f"{y}-{m}-{d}"
        return ""

    def _context_score(self, entity: dict, labels: Dict[str, str], context: str) -> Tuple[int, List[str]]:
        """Cuántas palabras del contexto del caso aparecen en la descripción, nacionalidad, cargos u ocupación."""
        words = {w for w in normalize_text(context).split() if len(w) > 3}
        if not words:
            return 0, []
        related = [labels.get(v["id"], "") for p in ("P27", "P39", "P106", "P69", "P108", "P19", "P102")
                   for v in self._values(entity, p) if isinstance(v, dict) and "id" in v]
        haystack = set(normalize_text(" ".join([self._description(entity), *related])).split())
        # "ecuador" también casa con "ecuatoriano/a" en las descripciones ("atleta ecuatoriano")
        hits = [w for w in words if w in haystack or any(h.startswith(w[:6]) for h in haystack if len(w) >= 6)]
        return len(hits), hits

    # ── ejecución ────────────────────────────────────────────────────────────
    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        name = (query_params.target_name or "").strip()
        if len(name) < 3:
            return []
        context = " ".join(x for x in (query_params.context, query_params.location, query_params.company) if x)
        self._report_progress(f"🔍 Wikidata: buscando a {name}…")
        try:
            ids = self._search_ids(name)
            if not ids:
                self._report_progress("✅ Wikidata: no tiene ficha (normal si no es una persona pública).")
                return []
            entities = self._entities(ids, "labels|descriptions|claims|sitelinks|aliases")
            humans = [e for e in (entities.get(i) for i in ids) if e and self._is_human(e)]
            if not humans:
                self._report_progress("✅ Wikidata: hay fichas con ese nombre pero ninguna es una persona.")
                return []
            ref_ids = sorted({v["id"] for e in humans for p in ENTITY_FIELDS
                              for v in self._values(e, p) if isinstance(v, dict) and "id" in v})[:200]
            labels = {qid: self._label(e) for qid, e in self._entities(ref_ids, "labels").items()} if ref_ids else {}
        except requests.RequestException as e:
            self._report_progress(f"❌ Wikidata: no se pudo consultar ({type(e).__name__}).")
            return []
        except ValueError:
            self._report_progress("❌ Wikidata: respuesta no válida.")
            return []

        scored = []
        for e in humans:
            names = " ".join([self._label(e)] + [a["value"] for lang in ("es", "en") for a in e.get("aliases", {}).get(lang, [])]
                             + [str(v.get("text", "")) for p in TEXT_FIELDS for v in self._values(e, p) if isinstance(v, dict)])
            points, _ = name_match(name, names)
            typo = False
            if points < 25 and fuzzy_name_points(name, names) >= 40:
                points, typo = 39.0, True                       # casi completo: vale, pero se avisa de la variación
            ctx_hits, ctx_words = self._context_score(e, labels, context)
            scored.append((points, ctx_hits, e, ctx_words + (["(nombre escrito con una variación)"] if typo else [])))
        scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
        scored = [t for t in scored if t[0] >= 25]            # al menos nombre de pila + apellido
        if not scored:
            self._report_progress("✅ Wikidata: ninguna persona con ese nombre.")
            return []

        best_points, best_ctx, best, best_words = scored[0]
        rivals = [t for t in scored[1:] if t[0] >= best_points]
        ambiguous = bool(rivals) and not (best_ctx > max(t[1] for t in rivals))
        results = []
        for points, _, e, ctx_words in scored[:4]:
            if ambiguous or e is best:
                results.append(self._person_result(e, labels, points, ctx_words, ambiguous, len(scored)))
            else:
                # Otra persona con el mismo nombre que el contexto descarta: se muestra, pero no como la buscada
                results.append(self._person_result(e, labels, points, ctx_words, True, len(scored), discarded=True))
        if not ambiguous:
            results += self._social_results(best, name, results[0].raw_data)
            self._report_progress(f"✅ Wikidata: {self._label(best)} — {self._description(best)} "
                                  f"({len(results) - 1} cuentas/datos vinculados)")
        else:
            self._report_progress(f"⚠️ Wikidata: {len(scored)} personas con ese nombre y el contexto no basta para "
                                  f"elegir; se listan todas sin dar ninguna por buena. Añade país, cargo o ciudad.")
        return results

    def _person_result(self, e: dict, labels: Dict[str, str], points: float, ctx_words: List[str],
                       ambiguous: bool, total: int, discarded: bool = False) -> SearchResult:
        qid = e.get("id", "")
        fields: Dict[str, object] = {"wikidata_id": qid, "name": self._label(e), "description": self._description(e)}
        birth = self._date((self._values(e, "P569") or [None])[0])
        death = self._date((self._values(e, "P570") or [None])[0])
        if birth:
            fields["birth_date"] = birth
        if death:
            fields["death_date"] = death
        for prop, label in ENTITY_FIELDS.items():
            vals = [labels.get(v["id"], v["id"]) for v in self._values(e, prop) if isinstance(v, dict) and "id" in v]
            if vals:
                fields[label] = vals[:6]
        for prop, label in TEXT_FIELDS.items():
            vals = [v.get("text") for v in self._values(e, prop) if isinstance(v, dict) and v.get("text")]
            if vals:
                fields[label] = vals[0]
        websites = [v for v in self._values(e, "P856") if isinstance(v, str)]
        if websites:
            fields["website"] = websites[0]
        socials = self._socials(e)
        if socials:
            fields["accounts"] = {k: v[0] for k, v in socials.items()}
        sitelinks = e.get("sitelinks", {})
        for wiki, lang in (("eswiki", "es"), ("enwiki", "en")):
            if wiki in sitelinks:
                fields[f"wikipedia_{lang}"] = f"https://{lang}.wikipedia.org/wiki/{sitelinks[wiki]['title'].replace(' ', '_')}"

        aliases = [a["value"] for lang in ("es", "en") for a in e.get("aliases", {}).get(lang, [])]
        if aliases:
            fields["aliases"] = list(dict.fromkeys(aliases))[:5]
        parts = [fields["description"]]
        if fields.get("aliases"):
            parts.append("También conocido como: " + ", ".join(fields["aliases"]))
        if birth:
            parts.append(f"Nacimiento: {birth}" + (f" en {fields['Lugar de nacimiento'][0]}" if fields.get("Lugar de nacimiento") else ""))
        for label in ("Nacionalidad", "Cargos", "Ocupación", "Estudios", "Empleadores", "Partido"):
            if fields.get(label):
                parts.append(f"{label}: {', '.join(fields[label][:3])}")
        if socials:
            parts.append("Cuentas: " + ", ".join(f"{k} {v[0]}" for k, v in socials.items()))
        warning = f"⚠️ HOMÓNIMO POSIBLE ({total} personas con ese nombre en Wikidata). " if ambiguous else ""
        if discarded:
            warning = "OTRA PERSONA con el mismo nombre (el contexto del caso no coincide). "
        if ctx_words:
            parts.append("Coincide con el contexto: " + ", ".join(ctx_words))
        location = (fields.get("Lugar de nacimiento") or [""])[0]
        employers = fields.get("Empleadores") or []
        return SearchResult(
            title=f"Wikidata: {fields['name']} — {fields['description'][:80]}",
            url=f"https://www.wikidata.org/wiki/{qid}",
            snippet=warning + " · ".join(p for p in parts if p),
            source_tool=self.name,
            category="Persona pública (Wikidata)",
            relevance_score=20 if discarded else 50 if ambiguous else (95 if points >= 39 else 80),
            raw_data=fields,
            extra_data={"name": fields["name"], "location": location, "company": employers[0] if employers else "",
                        "wikidata_id": qid, "ambiguous": ambiguous, "discarded": discarded},
        )

    def _socials(self, e: dict) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for prop, (label, _) in SOCIAL.items():
            vals = [v for v in self._values(e, prop) if isinstance(v, str) and v.strip()]
            if vals:
                out[label] = list(dict.fromkeys(vals))
        return out

    def _social_results(self, e: dict, name: str, card: Optional[dict] = None) -> List[SearchResult]:
        """Una entrada por cuenta oficial: así el perfilador las trata como candidatos y extrae el usuario.

        El texto incluye la identidad de la ficha (nombre completo, descripción, nacionalidad, lugar de
        nacimiento): antes solo decía "X de Jefferson Pérez", puntuaba 25 frente a "Jefferson Pérez Quezada" y
        las cuentas oficiales verificadas se descartaban (prueba real).
        """
        results = []
        person = self._label(e)
        card = card or {}
        identity = " · ".join(str(x) for x in (
            card.get("Nombre de nacimiento") or card.get("Nombre nativo") or "", card.get("description", ""),
            ", ".join(card.get("Nacionalidad") or []), ", ".join(card.get("Lugar de nacimiento") or [])) if x)
        for prop, (label, template) in SOCIAL.items():
            for handle in list(dict.fromkeys(v for v in self._values(e, prop) if isinstance(v, str) and v.strip()))[:3]:
                url = template.format(handle) if template else ""
                results.append(SearchResult(
                    title=f"{label} oficial de {person}: {handle}",
                    url=url,
                    snippet=f"Cuenta {label} '{handle}' de {person} ({identity}) registrada en Wikidata ({e.get('id')}). "
                            f"Dato comunitario con referencias: confírmalo abriendo el perfil.",
                    source_tool=self.name,
                    category="Social Media",
                    relevance_score=90,
                    raw_data={"platform": label, "handle": handle, "wikidata_id": e.get("id")},
                    extra_data={"name": person, "username": handle, "platform": label},
                ))
        for site in [v for v in self._values(e, "P856") if isinstance(v, str)][:2]:
            results.append(SearchResult(
                title=f"Web oficial de {person}", url=site,
                snippet=f"Sitio web oficial de {person} según Wikidata ({e.get('id')}).",
                source_tool=self.name, category="Web", relevance_score=85,
                extra_data={"name": person},
            ))
        return results
