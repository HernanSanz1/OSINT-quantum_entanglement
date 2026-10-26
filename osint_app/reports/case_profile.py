"""Ficha de persona a partir de un caso guardado, no solo del perfilamiento que está en pantalla.

El caso guarda la semilla, los resultados en bruto de cada herramienta y las decisiones del analista. Con eso se
vuelven a extraer y puntuar los candidatos con la lógica ACTUAL (un caso antiguo aprovecha las mejoras) y se arma
la misma ficha que al terminar el perfilamiento. Antes, al cerrar la ventana o cambiar de caso ya no se podía.
"""
import json
import logging
from dataclasses import fields
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_SEED_FIELDS = ("name", "context", "country", "city", "university", "email", "username", "phone", "domain", "company")


def _seed_from_target_data(case_id: int, db) -> Dict:
    """Casos guardados antes de existir profile_runs: la semilla está en los datos del caso con origen "seed"
    (el principal con confianza 100; alias y usuarios, correos y teléfonos extra con 95)."""
    data = [d for d in db.get_target_data(case_id) if d.source == "seed"]
    main: Dict[str, str] = {}
    extra: Dict[str, List[str]] = {}
    for d in data:                                   # ya vienen ordenados por confianza, de mayor a menor
        key = "city" if d.field_type == "location" else d.field_type
        if d.confidence >= 100 and key not in main:
            main[key] = d.value
        else:
            extra.setdefault(key, []).append(d.value)
    if not main.get("name"):
        return {}
    seed = {k: main.get(k, "") for k in _SEED_FIELDS}
    seed.update(aliases=extra.get("name", []), extra_usernames=extra.get("username", []),
                extra_emails=extra.get("email", []), extra_phones=extra.get("phone", []))
    return seed


def _search_results(raw_json: str) -> list:
    from ..core.models import SearchResult
    known = {f.name for f in fields(SearchResult)}
    out = []
    try:
        items = json.loads(raw_json or "[]")
    except ValueError:
        return out
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("url") is not None:
            out.append(SearchResult(**{k: v for k, v in item.items() if k in known}))
    return out


def profile_from_case(case_id: int, db=None) -> Optional[Dict]:
    """{"seed", "candidates", "confirmed", "rejected", "warnings", "run_at"} del caso, o None si no tiene un perfil."""
    from ..profiler_engine import ProfilerEngine, SeedData, ToolResult
    if db is None:
        from ..db.feedback_db import db
    runs = db.get_profile_runs(case_id)
    seed = runs[0]["seed"] if runs else _seed_from_target_data(case_id, db)
    if not seed or not seed.get("name"):
        return None
    profile_tools = set(ProfilerEngine.TOOL_PRIORITY)
    results = []
    for report in db.get_reports(case_id):
        # "Sherlock:jperez" es la segunda ronda de Sherlock; los análisis sueltos de otras pestañas no cuentan
        if report.tool_name.split(":")[0] in profile_tools and report.status == "ok":
            results.append(ToolResult(tool_name=report.tool_name, status="ok", results=_search_results(report.raw_json)))
    if not any(r.results for r in results):
        return None

    seed_obj = SeedData(**{f.name: seed[f.name] for f in fields(SeedData) if f.name in seed and seed[f.name] is not None})
    engine = ProfilerEngine()
    engine.results = results
    # Usuarios de la segunda ronda ("Maigret:reypalomo_"): en vivo el perfilador los recuerda para puntuar sus
    # perfiles; sin esto, al rehacer la ficha desde el caso esas cuentas bajaban de 30 a 0 y desaparecían.
    # Solo de las herramientas de la segunda ronda y con forma de usuario: "WebSearch:Luisito Comunica" es la
    # búsqueda del alias, no un usuario (tomarlo por uno subía a "Alta" a los imitadores; caso real #27)
    own = {u.lower() for u in seed_obj.all_usernames()}
    engine.chained_usernames = list(dict.fromkeys(
        name for tool, _, name in (r.tool_name.partition(":") for r in results)
        if name and tool in ProfilerEngine.CHAINED_USERNAME_TOOLS and not any(ch.isspace() for ch in name)
        and name.lower() not in own))
    candidates = [{"source": c.source_tool, "url": c.url, "title": c.title, "snippet": c.snippet,
                   "confidence": c.confidence, "category": c.category, "matched": c.matched_fields,
                   "warning": c.warning, "extra": c.extra_data}
                  for c in engine.extract_candidates(seed_obj, min_confidence=20.0)]
    confirmed, rejected = _verdicts(case_id, db)
    return {"seed": seed, "candidates": candidates, "confirmed": confirmed, "rejected": rejected,
            "warnings": runs[0]["warnings"] if runs else {}, "run_at": runs[0]["run_at"] if runs else ""}


def _verdicts(case_id: int, db) -> Tuple[set, set]:
    verdicts = db.get_verdicts(case_id)
    confirmed = {u for u, v in verdicts.items() if v == "confirmado"}
    rejected = {u for u, v in verdicts.items() if v == "descartado"}
    # Casos antiguos: los perfiles confirmados se guardaban como datos del caso con origen "confirmado"
    confirmed |= {d.value for d in db.get_target_data(case_id)
                  if d.source == "confirmado" and d.field_type == "profile" and d.value not in rejected}
    return confirmed, rejected


def person_report_from_case(case_id: int, db=None) -> Optional[Dict]:
    """La ficha (lo que devuelve build_person_report) del perfil guardado en el caso, o None si no hay perfil."""
    from .person_report import build_person_report
    profile = profile_from_case(case_id, db)
    if profile is None:
        return None
    return build_person_report(profile["seed"], profile["candidates"], profile["confirmed"], profile["rejected"],
                               case_id=case_id, warnings=profile["warnings"])
