"""Vista legible de un reporte de herramienta (texto plano), para la pestaña Reportes.

Antes la pestaña mostraba el JSON crudo de cada herramienta: ilegible para una persona no técnica.
"""
import json
from urllib.parse import unquote

from .person_report import confidence_word

_NOTICE_CATEGORIES = {"Aviso", "Error", "Config Error", "Sin resultado", "Error / Deprecado"}
MAX_SNIPPET = 300


def readable_results(tool_name: str, raw_json: str) -> str:
    """Texto legible de los resultados guardados de una herramienta. Si no son una lista de resultados, JSON ordenado."""
    try:
        data = json.loads(raw_json or "[]")
    except (TypeError, ValueError):
        return str(raw_json or "")
    if not isinstance(data, list):
        return json.dumps(data, indent=2, ensure_ascii=False)
    items = [d for d in data if isinstance(d, dict)]
    if not items:
        return f"{tool_name}: sin resultados.\n\n(Que una herramienta no encuentre nada no siempre significa que no exista información.)"

    if any(isinstance(d.get("extra"), dict) and "cti_row" in d["extra"] for d in items):
        return _readable_cti(tool_name, items)

    notices = [d for d in items if str(d.get("category", "")) in _NOTICE_CATEGORIES]
    results = [d for d in items if d not in notices]
    lines = [f"{tool_name} — {len(results)} resultado(s)", "=" * 60,
             "Relevancia: la que da la propia herramienta. En Perfilamiento la confianza se recalcula con todos los "
             "datos del objetivo (nombre, país, contexto, homónimos), por eso puede ser distinta.", ""]
    for d in notices:
        lines += [f"⚠️ {d.get('title', '')}", f"   {d.get('snippet', '')}", ""]
    for n, d in enumerate(sorted(results, key=lambda x: -float(x.get("relevance_score") or 0)), 1):
        score = float(d.get("relevance_score") or 0)
        snippet = " ".join(str(d.get("snippet") or "").split())
        if len(snippet) > MAX_SNIPPET:
            snippet = snippet[:MAX_SNIPPET] + "…"
        lines.append(f"{n}. {d.get('title') or 'Sin título'}")
        lines.append(f"   Tipo: {d.get('category') or '—'} · Relevancia: {confidence_word(score)} ({score:.0f})")
        if d.get("url"):
            lines.append(f"   Enlace: {_readable_url(d['url'])}")
        if snippet:
            lines.append(f"   {snippet}")
        lines.append("")
    return "\n".join(lines)


def _readable_url(url: str) -> str:
    """La URL con sus tildes ("Jos%C3%A9" → "José"), como la escribiría una persona."""
    try:
        return unquote(str(url))
    except (TypeError, ValueError):
        return str(url)


def _readable_cti(tool_name: str, items: list) -> str:
    """El cruce con el CTI: cada coincidencia con su explicación completa (lo más grave primero)."""
    lines = [f"{tool_name} — {len(items)} coincidencia(s) con la inteligencia de amenazas", "=" * 60, ""]
    for n, d in enumerate(items, 1):
        row = d["extra"]["cti_row"]
        lines += [f"{n}. [{row.get('level', '')}] {row.get('a', '')} — {row.get('relation', '')}",
                  *(f"   {line}" if line else "" for line in str(row.get("detail", "")).splitlines()), ""]
    return "\n".join(lines)
