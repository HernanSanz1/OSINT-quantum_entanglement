"""
HTML report generator v2 — works with ToolReport objects OR raw SearchResult lists.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import List, Union


CATEGORY_COLORS = {
    "Social Media":   "#89b4fa",
    "Document":       "#a6e3a1",
    "Email":          "#f38ba8",
    "Email Social":   "#f38ba8",
    "Email Verification": "#f38ba8",
    "Professional":   "#cba6f7",
    "Code":           "#fab387",
    "Credentials":    "#eba0ac",
    "Financial":      "#f9e2af",
    "Legal":          "#eba0ac",
    "DNS":            "#94e2d5",
    "Network":        "#94e2d5",
    "Subdomain":      "#89dceb",
    "Certificate":    "#89dceb",
    "Wayback":        "#a6adc8",
    "Phone":          "#cba6f7",
    "SpiderFoot":     "#cba6f7",
    "Google Account": "#fab387",
    "General":        "#6c7086",
    "Config Error":   "#585b70",
}


def generate_html(source) -> str:
    """
    Generate an HTML report string.
    source can be:
      - a ToolReport object (v2)
      - a list of SearchResult-like objects (v1 compat)
    Returns the HTML string (does NOT write to file).
    """
    # ─── Normalise input ──────────────────────────────────────────────────────
    if hasattr(source, "raw_json"):
        # v2 ToolReport
        tool_name = source.tool_name
        run_at    = source.run_at[:16]
        summary   = source.summary
        try:
            results = json.loads(source.raw_json)
        except Exception:
            results = []
    else:
        # list of SearchResult objects
        tool_name = "OSINT"
        run_at    = datetime.now().strftime("%Y-%m-%d %H:%M")
        summary   = f"{len(source)} resultados"
        results   = [r.to_dict() if hasattr(r, "to_dict") else r for r in source]

    # ─── Aggregate stats ──────────────────────────────────────────────────────
    tools_count: dict = {}
    cats_count:  dict = {}
    for r in results:
        t = r.get("source_tool", tool_name)
        c = r.get("category", "General")
        tools_count[t] = tools_count.get(t, 0) + 1
        cats_count[c]  = cats_count.get(c, 0) + 1

    tool_rows = "".join(
        f"<tr><td>{t}</td><td>{c}</td></tr>" for t, c in tools_count.items()
    )
    cat_rows = "".join(
        f"<tr><td>{c}</td><td>{n}</td></tr>" for c, n in cats_count.items()
    )

    # ─── Result cards ─────────────────────────────────────────────────────────
    cards = ""
    for r in results:
        color   = CATEGORY_COLORS.get(r.get("category", "General"), "#6c7086")
        title   = r.get("title", "Sin título")
        url     = r.get("url", "")
        snippet = r.get("snippet", "")
        cat     = r.get("category", "General")
        stool   = r.get("source_tool", tool_name)
        score   = r.get("relevance_score", 0)
        href    = f'<a href="{url}" target="_blank">{title}</a>' if url else title
        cards += f"""
        <div class="card" style="border-left:4px solid {color}">
          <h3>{href}</h3>
          <div class="meta">
            <span class="badge" style="background:{color}20;color:{color}">{cat}</span>
            <span class="badge">🔧 {stool}</span>
            <span class="badge">⭐ {score}</span>
          </div>
          <p>{snippet}</p>
          {"<code>" + url + "</code>" if url else ""}
        </div>"""

    # ─── Full HTML ────────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Reporte OSINT — {tool_name} — {run_at}</title>
  <style>
    :root {{--bg:#1e1e2e;--surface:#313244;--text:#cdd6f4;--accent:#89b4fa}}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--text);padding:30px}}
    h1{{color:var(--accent);margin-bottom:4px}}
    .subtitle{{color:#a6adc8;font-size:13px;margin-bottom:20px}}
    h2{{color:var(--accent);margin:24px 0 10px;font-size:15px;text-transform:uppercase;letter-spacing:.5px}}
    .summary-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}}
    table{{width:100%;border-collapse:collapse;background:var(--surface);border-radius:8px;overflow:hidden}}
    th,td{{padding:10px 14px;text-align:left;border-bottom:1px solid #45475a}}
    th{{background:#45475a;color:var(--accent)}}
    .card{{background:var(--surface);border-radius:8px;padding:16px;margin-bottom:14px}}
    .card h3{{margin-bottom:8px;font-size:15px}}
    .card h3 a{{color:var(--accent);text-decoration:none}}
    .card h3 a:hover{{text-decoration:underline}}
    .meta{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}}
    .badge{{background:#45475a;padding:3px 10px;border-radius:20px;font-size:12px}}
    .card p{{font-size:13px;color:#a6adc8;margin-bottom:8px}}
    code{{font-size:11px;color:#a6e3a1;word-break:break-all}}
  </style>
</head>
<body>
  <h1>🔍 Reporte OSINT — {tool_name}</h1>
  <p class="subtitle">Generado: {datetime.now():%Y-%m-%d %H:%M:%S} &nbsp;|&nbsp; Ejecución: {run_at} &nbsp;|&nbsp; Total: <strong>{len(results)}</strong> resultados</p>
  <p class="subtitle">{summary}</p>

  <h2>Resumen</h2>
  <div class="summary-grid">
    <table>
      <thead><tr><th>Herramienta</th><th>Resultados</th></tr></thead>
      <tbody>{tool_rows}</tbody>
    </table>
    <table>
      <thead><tr><th>Categoría</th><th>Resultados</th></tr></thead>
      <tbody>{cat_rows}</tbody>
    </table>
  </div>

  <h2>Resultados Detallados</h2>
  {cards}
</body>
</html>"""


def save_html(source, output_path: str) -> None:
    """Write HTML report to disk."""
    Path(output_path).write_text(generate_html(source), encoding="utf-8")
