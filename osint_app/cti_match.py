"""Cruce de los datos del objetivo de un caso con las noticias y amenazas guardadas por el módulo CTI.

Antes el cruce solo comparaba CVE y nombres de tecnología. Aquí se usan los datos que el analista dio del objetivo
(dominio, empresa, nombre, IP, correo corporativo) para responder lo que importa en un SOC:

- ¿Aparece como víctima de ransomware? (ransomware.live, víctimas en Ecuador): por su web o por su nombre.
- ¿Lo citan noticias o boletines de seguridad (EcuCERT, CSIRT Telconet, CISA…)?
- ¿Alguna de sus IP aparece como indicador en un aviso?

Solo los datos del objetivo, no los miles de dominios que salen en los resultados de las herramientas (wikipedia.org
en una noticia no dice nada del caso).
"""
import ipaddress
import json
import re
import unicodedata
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import urlsplit

# Correo de un proveedor público: su dominio no es el de la organización
FREE_MAIL = {"gmail.com", "hotmail.com", "outlook.com", "live.com", "msn.com", "yahoo.com", "yahoo.es", "hotmail.es",
             "icloud.com", "me.com", "protonmail.com", "proton.me", "aol.com", "gmx.com", "yandex.com"}
# Una sola palabra así no identifica a nadie en una noticia
GENERIC_WORDS = {"banco", "grupo", "ecuador", "ministerio", "gobierno", "policia", "empresa", "universidad", "hospital",
                 "municipio", "seguros", "corporacion", "comercial", "servicios", "nacional", "internacional",
                 "consultora", "soluciones", "tecnologia", "sistemas", "agencia", "instituto", "fundacion"}
_LEGAL = re.compile(r"\b(s\.?\s?a\.?\s?s?\.?|c\.?\s?a\.?|cia\.?|ltda\.?|inc\.?|corp\.?|llc|sociedad anonima|compania)(?=\s|$)")
MAX_MENTIONS = 20
# Quién metió el dato en el caso: el analista (Datos, Perfilamiento, lo confirmado) o una versión antigua sin fuente.
# Lo que añaden las herramientas (los nombres de servidor de una IP, los DNS de un WHOIS…) no es el objetivo:
# en un caso real salían dns.google o un servidor de Scania como "datos del objetivo cruzados".
ANALYST_SOURCES = {"", "manual", "seed", "confirmado"}
# Nombre del reporte que guarda cada cruce en el caso (pestaña Reportes y exportación)
CTI_REPORT_TOOL = "Cruce CTI"


def fold(text: str) -> str:
    """Minúsculas y sin tildes."""
    return unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode("ascii").lower()


def _org_key(name: str) -> str:
    """Nombre comparable de una organización: sin tildes, sin forma jurídica (S.A., Cía. Ltda.…), solo letras."""
    return re.sub(r"[^a-z0-9]", "", _LEGAL.sub(" ", fold(name)))


def host_of(value: str) -> str:
    """Dominio sin "www." de una web, URL o dominio suelto ("https://www.conauto.com.ec/x" → "conauto.com.ec")."""
    value = (value or "").strip().lower()
    if not value:
        return ""
    try:
        host = urlsplit(value if "://" in value else "https://" + value).hostname or ""
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def same_site(a: str, b: str) -> bool:
    """El mismo sitio o uno es subdominio del otro (mail.conauto.com.ec ↔ conauto.com.ec)."""
    a, b = host_of(a), host_of(b)
    return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def target_identifiers(target_data: Iterable) -> Dict[str, List[str]]:
    """Datos del objetivo útiles para el cruce, sacados de los datos del caso (lo descubierto "found_" no cuenta)."""
    out: Dict[str, Set[str]] = {"domains": set(), "names": set(), "ips": set()}
    for td in target_data:
        kind = (getattr(td, "field_type", "") or "").lower()   # la pestaña Datos guarda "DOMAIN", el perfilador "domain"
        value = (getattr(td, "value", "") or "").strip()
        source = (getattr(td, "source", "") or "").strip().lower()
        if not value or kind.startswith("found_") or source not in ANALYST_SOURCES:
            continue
        if kind in ("domain", "url", "website"):
            host = host_of(value)
            if "." in host:
                out["domains"].add(host)
        elif kind == "email" and "@" in value:
            domain = value.rsplit("@", 1)[1].lower()
            if domain not in FREE_MAIL:
                out["domains"].add(domain)
        elif kind in ("company", "organization", "name"):
            out["names"].add(value.lstrip("@"))
        elif kind == "ip":
            try:
                if ipaddress.ip_address(value).is_global:
                    out["ips"].add(value)
            except ValueError:
                pass
    return {k: sorted(v) for k, v in out.items()}


def _distinctive(name: str) -> bool:
    words = fold(name).split()
    return len(words) >= 2 or (len(words) == 1 and len(words[0]) >= 7 and words[0] not in GENERIC_WORDS)


def _phrase(text: str, phrase: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", text) is not None


def _field(text: str, key: str) -> str:
    """Un campo del resumen de ransomware.live (a veces viene cortado y no se puede leer como JSON)."""
    match = re.search(rf'"{key}":\s*"([^"]*)"', text or "")
    return match.group(1) if match else ""


def ransomware_victims(items: Iterable[Dict]) -> List[Dict]:
    """Víctimas de ransomware del almacén CTI: nombre, web, grupo, sector y fecha."""
    victims = []
    for item in items:
        if item.get("fuente_id") != "ransomware_ec":
            continue
        summary = str(item.get("resumen") or "")
        try:
            data = json.loads(summary)
        except ValueError:
            data = {}
        victims.append({
            "name": str(item.get("victima_reservada") or data.get("post_title") or _field(summary, "post_title")),
            "website": str(item.get("victima_web") or data.get("website") or _field(summary, "website")),
            "group": str(data.get("group_name") or _field(summary, "group_name")),
            "sector": str(data.get("activity") or _field(summary, "activity")),
            "date": str(item.get("fecha") or "")[:10],
            "source": str(item.get("fuente") or ""), "url": str(item.get("url") or ""),
        })
    return victims


def _victim_matches(victim: Dict, ids: Dict[str, List[str]]) -> Optional[str]:
    for domain in ids["domains"]:
        if same_site(victim["website"], domain) or same_site(victim["name"], domain):
            return f"su web {domain}"
    victim_key = _org_key(victim["name"])
    for name in ids["names"]:
        key = _org_key(name)
        if len(key) >= 5 and key == victim_key:
            return f"su nombre «{name}»"
        short, long_ = sorted((fold(name), fold(victim["name"])), key=len)
        if len(_org_key(short)) >= 8 and _distinctive(short) and _phrase(long_, short):
            return f"su nombre «{name}»"
    return None


def correlate_targets_with_cti(ids: Dict[str, List[str]], items: Iterable[Dict]) -> Dict:
    """Víctimas de ransomware, menciones en noticias e indicadores (IP) que coinciden con el objetivo."""
    items = list(items)
    ransomware = []
    for victim in ransomware_victims(items):
        why = _victim_matches(victim, ids)
        if why:
            ransomware.append({**victim, "matched": why})

    names = [n for n in ids["names"] if _distinctive(n)]
    mentions, iocs = [], []
    for item in items:
        if item.get("fuente_id") == "ransomware_ec":
            continue
        text = fold(f"{item.get('titulo', '')} {item.get('resumen', '')}")
        found = [f"su dominio {d}" for d in ids["domains"] if _phrase(text, d)]
        found += [f"su nombre «{n}»" for n in names if _phrase(text, fold(n))]
        ip_hits = [ip for ip in ids["ips"] if re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", text)]
        entry = {"title": str(item.get("titulo") or ""), "source": str(item.get("fuente") or ""),
                 "url": str(item.get("url") or ""), "date": str(item.get("fecha") or "")[:10]}
        if ip_hits:
            iocs.append({**entry, "matched": ", ".join(f"su IP {ip}" for ip in ip_hits)})
        elif found:
            mentions.append({**entry, "matched": ", ".join(found)})
    mentions.sort(key=lambda m: m["date"], reverse=True)
    return {"ransomware": ransomware, "mentions": mentions[:MAX_MENTIONS], "mentions_total": len(mentions),
            "iocs": iocs, "identifiers": ids}


# ── Filas del cruce: lo que se ve en Correlación, se guarda en Reportes y se exporta ────────────────────────────
# Antes las filas solo vivían en la tabla: la alerta de ransomware se cortaba ("VÍCTIMA DE …"), no se exportaba
# y "Analizar Caso" la borraba (evaluación 3, policia.gob.ec).

RED, ORANGE, SOFT_RED = "#ff3333", "#ffaa00", "#ff6b6b"


def _epss(value) -> str:
    return f"EPSS {value * 100:.0f} %" if isinstance(value, (int, float)) else "—"


def _row(a, relation, b, level, evidence, color, url, detail, score) -> Dict:
    return {"a": str(a), "relation": relation, "b": str(b), "level": level, "evidence": evidence, "color": color,
            "url": url or "", "detail": detail, "score": score}


def cti_rows(result: Dict) -> List[Dict]:
    """Una fila por coincidencia con el CTI, lo más grave primero, cada una con su explicación completa."""
    rows = []
    targets = result.get("targets") or {}
    for v in targets.get("ransomware", []):
        group = v.get("group") or "grupo sin identificar"
        site = v.get("website") or v.get("name")
        detail = "\n".join([
            f"🚨 {site} aparece como VÍCTIMA DE RANSOMWARE.",
            f"Grupo: {group}",
            f"Nombre publicado por el grupo: {v.get('name') or '—'}",
            f"Sector: {v.get('sector') or '—'}",
            f"Fecha de publicación: {v.get('date') or '—'}",
            f"Coincide por: {v.get('matched')}",
            f"Fuente: {v.get('source') or '—'} ({v.get('url') or 'sin enlace'})",
            "",
            "Qué significa: el grupo dice haber robado o cifrado datos de esta organización y lo publica para "
            "presionar. No siempre es cierto ni completo: confírmalo con la organización o su CSIRT.",
            "Qué hacer: avisar al responsable de seguridad, buscar datos y credenciales filtrados, revisar accesos "
            "remotos (VPN, RDP) y guardar esta evidencia en el caso.",
        ])
        rows.append(_row(site, f"🚨 VÍCTIMA DE RANSOMWARE ({group})", f"{v.get('name')} · coincide {v.get('matched')}",
                         "Crítica", f"{v.get('date')} · {v.get('source')}", RED, v.get("url"), detail, 100))
    for i in targets.get("iocs", []):
        detail = (f"🚨 {i['matched']} aparece como indicador en un aviso de seguridad.\nAviso: {i['title']}\n"
                  f"Fecha: {i['date']} · Fuente: {i['source']}\nEnlace: {i['url']}\n\nQué hacer: revisa en el aviso "
                  "por qué se cita la IP (atacante, servidor comprometido…) y busca conexiones con ella en tus registros.")
        rows.append(_row(i["matched"], "🚨 IP en un aviso de seguridad", i["title"], "Crítica",
                         f"{i['date']} · {i['source']}", RED, i["url"], detail, 95))
    for m in targets.get("mentions", []):
        detail = (f"📰 Una noticia de seguridad cita {m['matched']}.\nNoticia: {m['title']}\n"
                  f"Fecha: {m['date']} · Fuente: {m['source']}\nEnlace: {m['url']}\n\n"
                  "Que te citen no significa que te hayan atacado: lee la noticia para saber el contexto.")
        rows.append(_row(m["matched"], "📰 citado en una noticia de seguridad", m["title"], "Revisar",
                         f"{m['date']} · {m['source']}", ORANGE, m["url"], detail, 60))

    for m in result.get("cve_matches", []):
        h = m["hits"][0]
        exploited = m.get("actively_exploited")
        rel = "⚠️ en CTI · EXPLOTADO" if exploited else "en CTI"
        if m.get("ransomware"):
            rel += " · ransomware"
        tech = f"{h.get('vendor', '')} {h.get('product', '')}".strip() or "—"
        poc = any(x.get("poc") for x in m["hits"])
        detail = "\n".join([
            f"{m['cve']} (está en los datos del caso) aparece en la inteligencia de amenazas.",
            f"Producto: {tech}",
            f"Explotada activamente (lista KEV de CISA): {'SÍ' if exploited else 'no consta'}",
            f"Usada por ransomware: {'sí' if m.get('ransomware') else 'no consta'}",
            f"Exploit público: {'sí' if poc else 'no consta'}",
            f"{_epss(h.get('epss'))} (probabilidad de que se explote en los próximos 30 días)",
            f"Fuente: {h.get('source') or '—'} · {h.get('url') or ''}",
        ])
        rows.append(_row(m["cve"], rel, tech, _epss(h.get("epss")), (h.get("source") or "") + (" · exploit público" if poc else ""),
                         RED if exploited else ORANGE, h.get("url", ""), detail, 90 if exploited else 70))

    for t in result.get("tech_matches", []):
        h = t["hits"][0]
        poc = " · exploit público" if h.get("poc") else ""
        detail = "\n".join([
            f"La tecnología «{t['term']}» del objetivo tiene {t['count']} aviso(s) en el CTI, "
            f"{t['actively_exploited']} de ellos explotado(s).",
            f"El más peligroso: {h.get('cve') or '—'} {h.get('vendor', '')} {h.get('product', '')}".rstrip(),
            f"{_epss(h.get('epss'))} (probabilidad de que se explote en los próximos 30 días)",
            f"Fecha: {h.get('date') or '—'} · Fuente: {h.get('source') or '—'}{poc}",
            f"Enlace: {h.get('url') or '—'}",
            "",
            "Ojo: que una tecnología tenga vulnerabilidades no significa que este sitio las tenga; depende de su "
            "versión y sus plugins. Compruébalo antes de dar la alerta.",
        ])
        rows.append(_row(t["term"], f"tecnología · {t['count']} aviso(s), {t['actively_exploited']} explotado(s)",
                         f"{h.get('cve') or '—'} {h.get('vendor', '')} {h.get('product', '')}".strip(),
                         _epss(h.get("epss")), f"{h.get('date')} · {h.get('source')}{poc} · comprueba versión y plugins",
                         SOFT_RED if t["actively_exploited"] else ORANGE, h.get("url", ""), detail,
                         55 if t["actively_exploited"] else 40))
    return rows


def cti_report_items(rows: List[Dict], identifiers: Dict[str, List[str]]) -> List[Dict]:
    """El cruce como reporte del caso (lista de resultados, como las herramientas): legible en Reportes."""
    if not rows:
        used = ", ".join(sum((identifiers or {}).values(), [])) or "ningún dato del objetivo"
        return [{"title": "Sin coincidencias con el CTI", "category": "Sin resultado", "url": "",
                 "snippet": f"Se buscó {used} en la inteligencia de amenazas guardada y no apareció."}]
    return [{"title": f"{r['a']} — {r['relation']}", "category": r["level"], "url": r["url"],
             "snippet": r["detail"], "relevance_score": r["score"], "source": CTI_REPORT_TOOL, "extra": {"cti_row": r}}
            for r in rows]


def rows_from_report(raw_json: str) -> List[Dict]:
    """Las filas guardadas en un reporte del cruce (vacía si el reporte no tiene coincidencias)."""
    try:
        items = json.loads(raw_json or "[]")
    except (TypeError, ValueError):
        return []
    return [i["extra"]["cti_row"] for i in items if isinstance(i, dict) and isinstance(i.get("extra"), dict)
            and isinstance(i["extra"].get("cti_row"), dict)]
