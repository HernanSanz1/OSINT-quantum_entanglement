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
        if not value or kind.startswith("found_"):
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
