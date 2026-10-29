"""
Ficha de persona legible para usuarios no técnicos (HTML autocontenido, imprimible a PDF desde el navegador).

Sustituye a la "ficha de inteligencia" anterior, que (verificado 2026-10-12):
- dejaba SIEMPRE vacías las secciones de usuarios, correos, ubicaciones y empresas (leía un campo `raw_data` que
  los candidatos no tienen; los datos están en `extra`);
- cargaba imágenes de internet al abrirse (Gravatar o la foto del objetivo), avisando a terceros de que alguien
  abría el informe;
- era una tabla de URLs con porcentajes, difícil de entender sin conocimientos técnicos.

Aquí nada se carga de internet, todo el texto de terceros se escapa y solo se enlazan direcciones http(s).

Uso:
    report = build_person_report(seed, candidates, confirmed_urls, rejected_urls)
    html = render_person_html(report)
"""
import html
import re
from collections import OrderedDict
from datetime import datetime
from typing import Dict, Iterable, List, Optional
import unicodedata
from urllib.parse import unquote, urlsplit

from ..utils.homonyms import context_matches
from ..utils.identity import is_content_url, parse_profile_url

PLATFORM_NAMES = {
    "x": "X (Twitter)", "instagram": "Instagram", "facebook": "Facebook", "linkedin": "LinkedIn", "tiktok": "TikTok",
    "youtube": "YouTube", "github": "GitHub", "telegram": "Telegram", "reddit": "Reddit", "medium": "Medium",
}
# Categorías que no son datos de la persona
_SKIP_CATEGORIES = {"Aviso", "Error", "Config Error", "Alerta", "Sin resultado", "Username Generation"}
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+\d[\d\s().-]{7,}\d")
# Una biografía sin saltos de línea pega la palabra anterior al correo: "El canal más chido de YouTube" + salto +
# "luisito…@" llegaba como "YouTubeluisitocomunica@wearedw.com" (evaluación 2026-10-28)
_GLUED_PREFIX = re.compile(r"^(?:YouTube|Instagram|Facebook|TikTok|Twitter|Twitch|LinkedIn|GitHub|Email|E-mail|Mail|"
                           r"Correo|Contacto|Contact|Web)(?=[a-z0-9])")
MAX_MENTIONS = 15
# Sitios que no se listan en la ficha aunque exista el mismo usuario: una coincidencia de nombre de usuario en un sitio
# para adultos, de citas o de pagos no prueba nada y atribuirla a alguien puede dañarle (visto en real 2026-10-13:
# "chaturbate.com" en la ficha de un creador de contenido solo porque coincidía el usuario).
_SENSITIVE_TAGS = {"porn", "dating", "gambling", "finance", "fintech", "crypto", "trading", "medicine"}
_SENSITIVE_HOSTS = ("chaturbate", "onlyfans", "pornhub", "xvideos", "xhamster", "fansly", "stripchat", "cam4",
                    "bongacams", "myfreecams", "livejasmin", "manyvids", "fetlife", "adultfriendfinder", "tinder",
                    "badoo", "okcupid", "plentyoffish", "paypal", "venmo", "cash.app", "binance", "coinbase")


def is_sensitive_site(url: str, extra: Optional[Dict] = None) -> bool:
    tags = {str(t).lower() for t in ((extra or {}).get("tags") or [])}
    return bool(tags & _SENSITIVE_TAGS) or any(h in _host(url) for h in _SENSITIVE_HOSTS)


def confidence_word(score: float) -> str:
    return "Alta" if score >= 70 else "Media" if score >= 40 else "Baja"


def _host(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _fold(text: str) -> str:
    """Minúsculas, sin tildes y solo letras y números: "Agustín-Domínguez" → "agustindominguez"."""
    plain = unicodedata.normalize("NFKD", unquote(text or "")).encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]", "", plain)


def _identity_keys(seed: Dict):
    """(palabras del nombre y alias de 4+ letras, usuarios conocidos) del objetivo, sin tildes."""
    names = [seed.get("name") or ""] + list(seed.get("aliases") or [])
    words = {_fold(w) for n in names for w in re.split(r"[\s.\-_]+", n or "") if len(_fold(w)) >= 4}
    users = {_fold(u) for u in [seed.get("username")] + list(seed.get("extra_usernames") or []) if u}
    return words, users - {""}


def _handle_key(handle: str) -> str:
    """Usuario comparable entre plataformas; un canal de YouTube "c/Nombre" o "user/Nombre" es el usuario "Nombre"."""
    if handle.lower().startswith(("c/", "user/")):
        handle = handle.split("/", 1)[1]
    return _fold(handle)


def _clean_email(email: str) -> str:
    return _GLUED_PREFIX.sub("", email)


def _status(url: str, confirmed: set, rejected: set) -> str:
    return "confirmada" if url in confirmed else "descartada" if url in rejected else "por revisar"


def build_person_report(seed: Dict, candidates: Iterable[Dict], confirmed_urls: Iterable[str] = (),
                        rejected_urls: Iterable[str] = (), case_id: Optional[int] = None,
                        warnings: Optional[Dict[str, str]] = None) -> Dict:
    """Organiza los candidatos del perfilamiento en secciones con sentido para una persona no técnica.

    `seed`: nombre, contexto, país… · `candidates`: como los emite el perfilador (source, url, title, snippet,
    confidence, category, matched, warning, extra) · `warnings`: avisos de las herramientas (búsqueda bloqueada…),
    que la ficha muestra arriba para que un "no se encontró" no se tome por definitivo.
    """
    confirmed, rejected = set(confirmed_urls), set(rejected_urls)
    accounts: "OrderedDict[str, Dict]" = OrderedDict()   # clave plataforma:usuario
    other_profiles: List[Dict] = []
    mentions: List[Dict] = []
    homonyms: List[Dict] = []
    contacts: "OrderedDict[str, Dict]" = OrderedDict()
    public_card: Optional[Dict] = None
    sources = set()
    hidden_sensitive = 0
    seen_other_hosts = set()

    for c in sorted(candidates, key=lambda x: -float(x.get("confidence") or 0)):
        url = c.get("url") or ""
        category = str(c.get("category") or "")
        if category.split(" /")[0] in _SKIP_CATEGORIES or url in rejected:
            continue
        sources.add(str(c.get("source") or "").split(":")[0])
        score = float(c.get("confidence") or 0)
        extra = c.get("extra") if isinstance(c.get("extra"), dict) else {}
        item = {"url": url, "title": c.get("title") or url, "snippet": c.get("snippet") or "", "score": score,
                "level": confidence_word(score), "status": _status(url, confirmed, rejected),
                "source": str(c.get("source") or "").split(":")[0], "warning": c.get("warning") or ""}

        text = f"{item['title']} {item['snippet']}"
        for email in map(_clean_email, _EMAIL_RE.findall(text)):
            contacts.setdefault(email.lower(), {"kind": "Correo", "value": email, "source": item["source"], "url": url})
        for phone in _PHONE_RE.findall(text):
            contacts.setdefault(re.sub(r"\D", "", phone), {"kind": "Teléfono", "value": phone.strip(), "source": item["source"], "url": url})
        if extra.get("email"):
            contacts.setdefault(str(extra["email"]).lower(), {"kind": "Correo", "value": extra["email"], "source": item["source"], "url": url})

        if category.startswith("Persona pública"):
            if not extra.get("discarded") and not extra.get("ambiguous") and public_card is None:
                public_card = {**item, "facts": item["snippet"]}
            elif extra.get("discarded") or extra.get("ambiguous"):
                homonyms.append(item)
            continue
        if item["warning"]:
            homonyms.append(item)
            continue

        parsed = parse_profile_url(url) if url else None
        if parsed and not is_content_url(url):
            platform, handle, canonical = parsed
            hkey = _handle_key(handle) if not handle.lower().startswith("channel/") else _fold(handle)
            key = f"{platform}:{hkey}"
            # Enlace con la URL ORIGINAL: el analizador pasa el usuario a minúsculas y los canales de YouTube
            # (UCECJDeK0…) distinguen mayúsculas: con la canónica el enlace quedaba roto (visto en real).
            # El nombre del canal sale de la ruta, no del final de la URL ("channels?app=desktop…", visto en real)
            segs = [x for x in (urlsplit(url).path or "").split("/") if x]
            label = handle if "/" not in handle else "canal " + (segs[1] if len(segs) > 1 else handle.split("/", 1)[1])
            acc = accounts.setdefault(key, {"platform": PLATFORM_NAMES.get(platform, platform.capitalize()),
                                            "handle": label, "url": url, "score": score, "posts": [],
                                            "status": item["status"], "sources": set(), "name": extra.get("name") or "",
                                            "official": False, "hkey": hkey, "item": item, "note": ""})
            acc["score"] = max(acc["score"], score)
            acc["sources"].add(item["source"])
            acc["official"] = acc["official"] or bool(extra.get("official"))
            if item["status"] == "confirmada":
                acc["status"] = "confirmada"
            continue
        if parsed and is_content_url(url):
            key = f"{parsed[0]}:{parsed[1]}"
            if key in accounts:                          # publicación de una cuenta ya listada: se agrupa debajo
                accounts[key]["posts"].append(item)
                continue
        if c.get("source", "").split(":")[0] in ("Sherlock", "Maigret") and url:
            if item["status"] != "confirmada" and is_sensitive_site(url, extra):
                hidden_sensitive += 1
                continue
            host = _host(url)
            if host in seen_other_hosts:                 # op.gg ×6 (una por región): basta una
                continue
            seen_other_hosts.add(host)
            other_profiles.append({**item, "platform": host,
                                   "has_profile_data": any(k.startswith("profile_") for k in extra)})
            continue
        if url:
            mentions.append(item)

    # Publicaciones que llegaron antes que su cuenta: se recolocan
    for m in list(mentions):
        parsed = parse_profile_url(m["url"])
        if parsed and is_content_url(m["url"]) and f"{parsed[0]}:{parsed[1]}" in accounts:
            accounts[f"{parsed[0]}:{parsed[1]}"]["posts"].append(m)
            mentions.remove(m)

    account_list = sorted(accounts.values(), key=lambda a: (a["status"] != "confirmada", not a["official"], -a["score"]))
    _sort_accounts(account_list, seed or {}, homonyms, mentions)
    mentions.sort(key=lambda m: -float(m.get("score") or 0))   # los perfiles ajenos movidos aquí, en su sitio
    for acc in account_list:
        acc["level"] = confidence_word(acc["score"])
        acc["sources"] = sorted(s for s in acc["sources"] if s)
    likely = [a for a in account_list if a["score"] >= 70 or a["status"] == "confirmada"]
    possible = [a for a in account_list if a not in likely and a["score"] >= 40]
    return {
        "seed": seed, "case_id": case_id, "generated": datetime.now().astimezone(),
        "public_card": public_card, "accounts": account_list, "likely_accounts": likely, "possible_accounts": possible,
        "other_profiles": other_profiles, "contacts": list(contacts.values()),
        "mentions": mentions[:MAX_MENTIONS], "mentions_total": len(mentions), "homonyms": homonyms,
        "sources": sorted(s for s in sources if s), "confirmed_count": len(confirmed), "rejected_count": len(rejected),
        "hidden_sensitive": hidden_sensitive, "warnings": dict(warnings or {}),
    }


# Titular de un perfil de LinkedIn: "Gonzalo Plata - Cedar Fair Entertainment Company | LinkedIn"
_LINKEDIN_HEADLINE = re.compile(r"^[^|]*?\s[-–]\s(.+?)\s*\|\s*LinkedIn", re.I)


def _other_job(acc: Dict, context: str, name: str = "") -> str:
    """Lo que dice hacer un perfil de LinkedIn si no tiene nada que ver con el contexto del objetivo; si no, vacío.

    No se aplica si el usuario lleva el nombre completo (3+ palabras): "luis-arturo-villar-sudek" con "Ciencias de la
    Comunicación" es muy probablemente Luisito Comunica aunque el contexto diga "youtuber".
    """
    if acc["platform"] != "LinkedIn" or not context.strip():
        return ""
    words = [_fold(w) for w in (name or "").split() if _fold(w)]
    if len(words) >= 3 and all(w in acc["hkey"] for w in words):
        return ""
    match = _LINKEDIN_HEADLINE.match(acc["item"]["title"])
    if not match:
        return ""
    text = f"{acc['item']['title']} {acc['item']['snippet']}"
    return "" if context_matches(text, context) else match.group(1).strip()


def _sort_accounts(account_list: List[Dict], seed: Dict, homonyms: List[Dict], mentions: List[Dict]) -> None:
    """Decide qué cuentas son de la persona, cuáles de otra y cuáles solo hablan de ella (enfoque A: se marcan y se
    separan con su motivo, nunca se borran). Reglas medidas con perfiles reales (Jefferson Pérez, Andersson Boscán y
    Luisito Comunica, 2026-10-21):

    1. Suya: oficial (Wikidata), confirmada por el analista o con confianza ≥ 70.
    2. Mismo usuario que una cuenta suya (reypalomo_, alias oficial de Luisito): se queda, con una nota.
    3. En una plataforma con una cuenta claramente suya, las demás de confianza < 70 son otra persona (midudev:
       cuatro "Miguel Ángel Durán" ajenos en LinkedIn).
    4. Un perfil cuyo usuario no tiene nada del nombre ni del alias (LinkedIn "net-worth-fever", "agustín-domínguez-
       prieto") es de otra persona que HABLA de ella: pasa a menciones.
    5. Con confianza < 40 y solo coincidencias de nombre (GitHub "jefferson-quezada" de un desarrollador): otra persona.
    6. Un LinkedIn cuyo titular habla de otra profesión que el contexto ("Cedar Fair Entertainment", "técnico en obra
       seca" para el futbolista Gonzalo Plata, evaluación 2026-10-28): otra persona.
    """
    words, users = _identity_keys(seed)

    def trusted(acc):
        return acc["official"] or acc["status"] == "confirmada" or acc["score"] >= 70

    sure = [a for a in account_list if trusted(a)]
    sure_handles = {a["hkey"] for a in sure} | users
    best_by_platform: Dict[str, Dict] = {}
    for acc in sure:
        best_by_platform.setdefault(acc["platform"], acc)

    for acc in list(account_list):
        if trusted(acc):
            continue
        if acc["hkey"] in sure_handles:                                                         # regla 2
            acc["note"] = "Mismo usuario que una de sus cuentas verificadas: probablemente suya, sin confirmar."
            continue
        best = best_by_platform.get(acc["platform"])
        reason = ""
        if best is not None:                                                                    # regla 3
            reason = (f"Probablemente otra persona: la cuenta de {acc['platform']} más probable es "
                      f"{best['handle'] if best['handle'].startswith('canal ') else '@' + best['handle']}.")
        elif words and not any(w in acc["hkey"] for w in words) and not acc["hkey"].startswith("channel"):  # regla 4
            account_list.remove(acc)
            mentions.append({**acc["item"], "warning": ""})
            mentions.extend(acc["posts"])
            continue
        elif _other_job(acc, seed.get("context") or "", seed.get("name") or ""):                # regla 6
            job = _other_job(acc, seed.get("context") or "", seed.get("name") or "")
            reason = f"Posiblemente otra persona: su LinkedIn dice «{job}» y buscas a «{seed.get('context')}»."
        elif acc["score"] < 40:                                                                 # regla 5
            reason = ("Posiblemente otra persona: solo coincide el nombre y nada más la liga a esta persona "
                      "(ni su usuario ni sus cuentas verificadas). Ábrela antes de atribuírsela.")
        if reason:
            account_list.remove(acc)
            homonyms.append({"url": acc["url"], "title": f"{acc['platform']} {acc['handle']}", "snippet": "",
                             "score": acc["score"], "warning": reason})


# ── HTML ─────────────────────────────────────────────────────────────────────

def _e(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _link(url: str, text: str) -> str:
    url = str(url or "")
    if url.lower().startswith(("http://", "https://")):
        return f'<a href="{_e(url)}" target="_blank" rel="noopener noreferrer">{_e(text)}</a>'
    return _e(text)


def _badge(level: str) -> str:
    return f'<span class="badge {level.lower()}">{_e(level)}</span>'


def _summary_sentence(r: Dict) -> str:
    likely = r["likely_accounts"]
    platforms = sorted({a["platform"] for a in likely})
    parts = []
    if r["public_card"]:
        parts.append("tiene una <b>ficha pública</b> en Wikidata")
    if likely:
        parts.append(f"se encontraron <b>{len(likely)} cuenta(s) probablemente suyas</b> en "
                     f"{len(platforms)} plataforma(s) ({_e(', '.join(platforms))})")
    if r.get("possible_accounts"):
        parts.append(f"{len(r['possible_accounts'])} cuenta(s) más que <b>podrían</b> ser suyas y conviene revisar "
                     f"(pueden ser de fans u homónimos)")
    if r["contacts"]:
        parts.append(f"<b>{len(r['contacts'])} dato(s) de contacto</b> públicos")
    if r["mentions_total"]:
        parts.append(f"<b>{r['mentions_total']} mención(es)</b> en webs y medios")
    if r["homonyms"]:
        parts.append(f"<b>{len(r['homonyms'])} resultado(s) que podrían ser otra persona</b> (separados al final)")
    incomplete = " <b>Atención: la búsqueda quedó incompleta</b> (ver el aviso de arriba)." if r.get("warnings") else ""
    if not parts:
        return "No se encontró información pública suficiente sobre esta persona con los datos dados." + incomplete
    return "Sobre esta persona " + "; ".join(parts) + "." + incomplete


def render_person_html(r: Dict) -> str:
    seed = r["seed"]
    name = seed.get("name") or "Sin nombre"
    when = r["generated"].strftime("%Y-%m-%d %H:%M (UTC%z)")
    seed_rows = "".join(f"<tr><th>{_e(label)}</th><td>{_e(seed.get(key))}</td></tr>"
                        for key, label in (("name", "Nombre"), ("context", "Contexto"), ("country", "País"),
                                           ("city", "Ciudad"), ("username", "Usuario"), ("email", "Correo"),
                                           ("phone", "Teléfono"), ("domain", "Dominio")) if seed.get(key))
    # Alias y usuarios extra también son datos de partida: son los que ligan cuentas como reypalomo_
    for key, label in (("aliases", "Alias"), ("extra_usernames", "Otros usuarios")):
        values = [str(v) for v in (seed.get(key) or []) if v]
        if values:
            seed_rows += f"<tr><th>{_e(label)}</th><td>{_e(', '.join(values))}</td></tr>"

    card = ""
    if r["public_card"]:
        pc = r["public_card"]
        facts = "".join(f"<li>{_e(f.strip())}</li>" for f in pc["facts"].split(" · ") if f.strip())
        card = (f'<section><h2>Ficha pública</h2><p class="hint">Datos estructurados de Wikidata, base abierta '
                f'mantenida por la comunidad. {_link(pc["url"], "Ver la ficha original")}</p><ul>{facts}</ul></section>')

    acc_rows = ""
    for a in r["accounts"]:
        posts = ""
        if a["posts"]:
            posts = "<details><summary>{} publicación(es) de esta cuenta</summary><ul>{}</ul></details>".format(
                len(a["posts"]), "".join(f"<li>{_link(p['url'], p['title'][:110])}</li>" for p in a["posts"][:10]))
        status = ("✔ Confirmada por el analista" if a["status"] == "confirmada"
                  else "✔ Oficial (Wikidata)" if a.get("official") else "Por revisar")
        if a.get("note"):
            posts = f"<br><small>{_e(a['note'])}</small>" + posts
        acc_rows += (f"<tr><td>{_e(a['platform'])}</td><td>{_link(a['url'], a['handle'] if a['handle'].startswith('canal ') else '@' + a['handle'])}"
                     f"{('<br><small>' + _e(a['name']) + '</small>') if a['name'] else ''}{posts}</td>"
                     f"<td>{_badge(a['level'])}</td><td>{_e(status)}</td><td>{_e(', '.join(a['sources']))}</td></tr>")
    accounts = (f'<section><h2>Cuentas en redes sociales</h2><p class="hint">Confianza <b>Alta</b>: varias pistas '
                f'coinciden (nombre, usuario, país…). <b>Media</b>: algunas. <b>Baja</b>: solo una; revísala antes '
                f'de darla por buena.</p><table><tr><th>Plataforma</th><th>Cuenta</th><th>Confianza</th>'
                f'<th>Estado</th><th>Encontrada por</th></tr>{acc_rows}</table></section>') if acc_rows else ""

    others = ""
    if r["other_profiles"] or r.get("hidden_sensitive"):
        items = "".join(f"<li>{_link(p['url'], p['platform'])}"
                        f"{' <small>(con datos del perfil)</small>' if p.get('has_profile_data') else ''}</li>"
                        for p in r["other_profiles"][:40])
        hidden = (f"<p class='hint'>No se listan {r['hidden_sensitive']} sitio(s) sensibles (adultos, citas, pagos o "
                  f"similares): una coincidencia de nombre de usuario ahí no prueba nada. Si los necesitas, están en "
                  f"SENTINEL.</p>") if r.get("hidden_sensitive") else ""
        others = (f'<section><h2>Mismo nombre de usuario en otros sitios (SIN VERIFICAR)</h2><p class="hint">Sitios '
                  f'donde existe una cuenta con el mismo nombre de usuario. <b>No significa que sea esta persona</b>: '
                  f'cualquiera puede elegir ese nombre. Ábrelo y compruébalo antes de usarlo.</p>'
                  f'<ul class="cols">{items}</ul>{hidden}</section>')

    contacts = ""
    if r["contacts"]:
        rows = "".join(f"<tr><td>{_e(c['kind'])}</td><td>{_e(c['value'])}</td><td>{_link(c['url'], c['source'])}</td></tr>"
                       for c in r["contacts"])
        contacts = (f'<section><h2>Datos de contacto públicos</h2><p class="hint">Aparecen publicados en la fuente '
                    f'indicada. Úsalos solo con una finalidad legítima.</p><table><tr><th>Tipo</th><th>Dato</th>'
                    f'<th>Dónde aparece</th></tr>{rows}</table></section>')

    mentions = ""
    if r["mentions"]:
        items = "".join(f"<li>{_link(m['url'], m['title'][:120])} {_badge(m['level'])}<br><small>{_e(m['snippet'][:220])}"
                        f"</small></li>" for m in r["mentions"])
        more = f"<p class='hint'>Se muestran {len(r['mentions'])} de {r['mentions_total']}.</p>" if r["mentions_total"] > len(r["mentions"]) else ""
        mentions = f"<section><h2>Menciones en webs y medios</h2><ul>{items}</ul>{more}</section>"

    homonyms = ""
    if r["homonyms"]:
        items = "".join(f"<li>{_link(h['url'], h['title'][:110])}<br><small>{_e(h['warning'] or h['snippet'][:160])}</small></li>"
                        for h in r["homonyms"][:20])
        homonyms = (f'<section class="muted"><h2>Posiblemente otra persona</h2><p class="hint">Resultados con el '
                    f'mismo nombre pero con señales de ser otra persona (otro país, otra profesión…). No se usan en '
                    f'el resumen.</p><ul>{items}</ul></section>')

    incomplete = ""
    if r.get("warnings"):
        items = "".join(f"<li><b>{_e(tool)}</b>: {_e(msg)}</li>" for tool, msg in r["warnings"].items())
        incomplete = (f'<div class="warn"><b>⚠ Búsqueda incompleta.</b> Algunas herramientas no pudieron consultar '
                      f'todas sus fuentes, así que pueden faltar resultados (sobre todo menciones en medios). Repite '
                      f'el perfilamiento más tarde antes de concluir que no hay información.<ul>{items}</ul></div>')

    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ficha de {_e(name)}</title>
<style>
  body {{ font-family: "Segoe UI", Arial, sans-serif; color: #1f2933; background: #f5f7fa; margin: 0; padding: 24px; line-height: 1.45; }}
  main {{ max-width: 980px; margin: 0 auto; background: #fff; padding: 28px 34px; border-radius: 8px; box-shadow: 0 1px 4px #0002; }}
  h1 {{ margin: 0 0 4px; font-size: 26px; }} h2 {{ font-size: 18px; margin: 28px 0 8px; border-bottom: 2px solid #e4e7eb; padding-bottom: 4px; }}
  .meta {{ color: #616e7c; font-size: 13px; }} .hint {{ color: #616e7c; font-size: 13px; margin: 4px 0 10px; }}
  .notice {{ background: #fff8e1; border-left: 4px solid #f0b429; padding: 10px 14px; font-size: 13px; margin: 14px 0; }}
  .warn {{ background: #ffe3e3; border-left: 4px solid #d64545; padding: 10px 14px; font-size: 13px; margin: 14px 0; }}
  .summary {{ background: #e3f8ff; border-left: 4px solid #2186eb; padding: 12px 16px; font-size: 15px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 14px; }} th, td {{ text-align: left; padding: 7px 8px; border-bottom: 1px solid #e4e7eb; vertical-align: top; }}
  th {{ background: #f5f7fa; }} a {{ color: #0b69a3; }} small {{ color: #616e7c; }}
  .badge {{ display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }}
  .alta {{ background: #e3f9e5; color: #207227; }} .media {{ background: #fff3c4; color: #8d6a00; }} .baja {{ background: #ffe3e3; color: #a61b1b; }}
  ul.cols {{ columns: 2; }} .muted {{ opacity: .85; }} details {{ margin-top: 4px; font-size: 13px; }}
  @media print {{ body {{ background: #fff; padding: 0; }} main {{ box-shadow: none; }} details {{ display: block; }} }}
</style></head>
<body><main>
<h1>Ficha de {_e(name)}</h1>
<div class="meta">Generada el {_e(when)}{(' · Caso #' + _e(r['case_id'])) if r.get('case_id') else ''} · SENTINEL</div>
<div class="notice"><b>Documento confidencial.</b> Contiene datos personales recogidos de fuentes públicas. Trátalo
según la Ley Orgánica de Protección de Datos Personales (LOPDP) y solo con una finalidad legítima. La información
pública puede estar desactualizada o ser de otra persona con el mismo nombre: verifícala antes de actuar.</div>
{incomplete}<section><h2>Resumen</h2><p class="summary">{_summary_sentence(r)}</p></section>
<section><h2>Datos de partida</h2><table>{seed_rows}</table></section>
{card}{accounts}{contacts}{mentions}{others}{homonyms}
<section><h2>Cómo se obtuvo</h2><p class="hint">Búsqueda automática en fuentes públicas con: {_e(', '.join(r['sources']) or '—')}.
Candidatos confirmados por el analista: {r['confirmed_count']} · descartados: {r['rejected_count']}. Este informe no
carga nada de internet al abrirse.</p></section>
</main></body></html>"""
