#!/usr/bin/env python3
"""Collect public CTI sources for the Altel bulletin."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import html
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

from fuentes import ENRIQUECIMIENTO, FUENTES

BASE_DIR = Path(__file__).resolve().parent
STORE = BASE_DIR / "store"
ITEMS = STORE / "items.jsonl"
ENRICH = STORE / "enriquecimiento.json"
STATE = STORE / "state.json"
LOG = STORE / "harvest.log"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    STORE.mkdir(parents=True, exist_ok=True)
    line = f"{utcnow()} {msg}"
    print(line)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def canonical(url: str) -> str:
    if not url:
        return ""
    parsed = urllib.parse.urlsplit(url.strip())
    parsed = parsed._replace(fragment="")
    return urllib.parse.urlunsplit(parsed)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def parse_date(value: str | None) -> str:
    if not value:
        return utcnow()
    value = html.unescape(value.strip())
    fmts = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
    ]
    for fmt in fmts:
        try:
            parsed = dt.datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            continue
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        pass
    return utcnow()


def ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def fetch(url: str, timeout: int = 35) -> bytes:
    headers = {
        "User-Agent": "Altel-CTI/1.0 (+https://altel.com.ec)",
        "Accept": "application/rss+xml, application/xml, application/json, text/html, */*",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            return exc.read() or b'{"message":"rate limited"}'
        if exc.code not in (403, 406):
            raise
        cmd = ["curl", "-fsSL", "--max-time", str(timeout), "-A", headers["User-Agent"], url]
        return subprocess.check_output(cmd)


def clean_text(value: str | None) -> str:
    if not value:
        return ""
    value = re.sub(r"<[^>]+>", " ", value)
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def cves_from(*parts: str) -> list[str]:
    seen = set()
    out = []
    for part in parts:
        for cve in CVE_RE.findall(part or ""):
            cve = cve.upper()
            if cve not in seen:
                seen.add(cve)
                out.append(cve)
    return out


def normalizar(fuente: dict, titulo: str, url: str, fecha: str | None, resumen: str = "", **extra) -> dict:
    url = canonical(url)
    clave_base = extra.pop("clave_id", None) or url or f"{fuente['id']}:{titulo}:{fecha}"
    item = {
        "id": sha256_text(clave_base),
        "fuente_id": fuente["id"],
        "fuente": fuente["nombre"],
        "region": fuente.get("region", "global"),
        "peso_fuente": fuente.get("peso", 1.0),
        "idioma": fuente.get("idioma", "en"),
        "titulo": clean_text(titulo)[:500],
        "url": url,
        "fecha": parse_date(fecha),
        "resumen": clean_text(resumen)[:1200],
        "cves": cves_from(titulo, resumen, url),
        "cosechado": utcnow(),
    }
    item.update(extra)
    return item


def parse_rss(raw: bytes, fuente: dict) -> list[dict]:
    root = ET.fromstring(raw)
    items = []
    for node in root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry"):
        def first(names):
            for name in names:
                found = node.find(name)
                if found is not None and found.text:
                    return found.text
            return ""

        title = first(["title", "{http://www.w3.org/2005/Atom}title"])
        link = first(["link"])
        atom_link = node.find("{http://www.w3.org/2005/Atom}link")
        if not link and atom_link is not None:
            link = atom_link.attrib.get("href", "")
        date = first(["pubDate", "published", "updated", "{http://www.w3.org/2005/Atom}published", "{http://www.w3.org/2005/Atom}updated"])
        desc = first(["description", "summary", "{http://www.w3.org/2005/Atom}summary"])
        if title:
            items.append(normalizar(fuente, title, link, date, desc))
    return items


def harvest_rss(fuente: dict) -> list[dict]:
    pages = int(fuente.get("paginas", 1))
    all_items = []
    for page in range(1, pages + 1):
        url = fuente["url"]
        if page > 1:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}paged={page}"
        try:
            all_items.extend(parse_rss(fetch(url), fuente))
        except Exception as exc:
            log(f"WARN fuente={fuente['id']} pagina={page} error={exc}")
    return all_items


def harvest_kev(fuente: dict) -> list[dict]:
    data = json.loads(fetch(fuente["url"]).decode("utf-8"))
    vulns = data.get("vulnerabilities", [])
    items = []
    for vuln in vulns:
        cve = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        title = f"{cve} {vendor} {product}".strip()
        summary = vuln.get("shortDescription", "")
        item = normalizar(
            fuente,
            title,
            fuente["url"] + "#" + cve,
            vuln.get("dateAdded"),
            summary,
            clave_id=f"kev:{cve}",
            cves=[cve] if cve else [],
            kev=True,
            kev_date_added=vuln.get("dateAdded"),
            kev_due_date=vuln.get("dueDate"),
            ransomware=bool(vuln.get("knownRansomwareCampaignUse") == "Known"),
            vendor=vendor,
            product=product,
        )
        items.append(item)
    return items


class EcuCertParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_a = False
        self.href = ""
        self.current = []
        self.last_span = ""
        self.in_span = False
        self.alerts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "span":
            self.in_span = True
            self.current = []
        if tag == "a":
            self.in_a = True
            self.href = attrs.get("href", "")
            self.current = []

    def handle_endtag(self, tag):
        if tag == "span" and self.in_span:
            self.last_span = clean_text("".join(self.current))
            self.in_span = False
        if tag == "a" and self.in_a:
            text = clean_text("".join(self.current))
            if self.href and ".pdf" in self.href.lower():
                self.alerts.append((self.last_span, text, self.href))
            self.in_a = False

    def handle_data(self, data):
        if self.in_a or self.in_span:
            self.current.append(data)


def parse_ecucert_date(value: str) -> str:
    months = {
        "ene": 1, "jan": 1, "feb": 2, "mar": 3, "abr": 4, "apr": 4, "may": 5, "jun": 6,
        "jul": 7, "ago": 8, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dic": 12, "dec": 12,
    }
    match = re.search(r"(\d{1,2})([A-Za-z]{3})(\d{2})", value or "")
    if not match:
        return utcnow()
    day, mon, year = match.groups()
    parsed = dt.datetime(2000 + int(year), months.get(mon.lower(), 1), int(day), tzinfo=dt.timezone.utc)
    return parsed.isoformat(timespec="seconds")


def harvest_ecucert(fuente: dict) -> list[dict]:
    parser = EcuCertParser()
    parser.feed(fetch(fuente["url"]).decode("utf-8", "replace"))
    out = []
    for stamp, title, href in parser.alerts:
        url = urllib.parse.urljoin(fuente["url"], href)
        out.append(normalizar(fuente, title, url, parse_ecucert_date(stamp), title))
    return out


def harvest_ransomware_ec(fuente: dict) -> list[dict]:
    raw = fetch(fuente["url"]).decode("utf-8", "replace")
    data = json.loads(raw)
    if isinstance(data, dict) and data.get("message"):
        log(f"WARN fuente={fuente['id']} respuesta={data.get('message')}")
        return []
    rows = data if isinstance(data, list) else data.get("victims", [])
    out = []
    for row in rows[:80]:
        victim = row.get("victim") or row.get("post_title") or "victima no verificada"
        group = row.get("group") or row.get("group_name") or "grupo no identificado"
        group_label = str(group).strip()
        group_label = group_label[:1].upper() + group_label[1:] if group_label else "grupo no identificado"
        date = row.get("discovered") or row.get("published") or row.get("date")
        sector = row.get("activity") or row.get("sector") or "organizacion"
        title = f"Registro OSINT de ransomware en Ecuador: sector {sector}, grupo {group_label}"
        claimed_url = row.get("post_url") or row.get("url") or ""
        public_url = fuente["url"]
        if claimed_url.startswith(("http://", "https://")) and ".onion" not in claimed_url.lower():
            public_url = claimed_url
        out.append(normalizar(
            fuente, title, public_url, date, json.dumps(row, ensure_ascii=False)[:900],
            clave_id=f"ransomware_ec:{group}:{victim}:{date}",
            ransomware=True,
            reclamo_ransomware=True,
            fuente_referencia=fuente["url"],
            url_reclamo_reservada=claimed_url if ".onion" in claimed_url.lower() else "",
            victima_reservada=victim,
            verificacion="fuente_publica_osint",
        ))
    return out


def harvest_sitemap(fuente: dict) -> list[dict]:
    root = ET.fromstring(fetch(fuente["url"]))
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    out = []
    for node in root.findall(".//sm:url", ns)[:120]:
        loc = node.findtext("sm:loc", default="", namespaces=ns)
        lastmod = node.findtext("sm:lastmod", default="", namespaces=ns)
        if not loc or "/blog/" not in loc:
            continue
        title = urllib.parse.unquote(loc.rstrip("/").split("/")[-1]).replace("-", " ").title()
        out.append(normalizar(fuente, title, loc, lastmod, "Entrada detectada por sitemap."))
    return out


def current_msrc_release_id() -> str:
    now = dt.datetime.now(dt.timezone.utc)
    return f"{now.year}-{now.strftime('%b')}"


def unique_values(values: list[str]) -> list[str]:
    out = []
    seen = set()
    for value in values:
        value = clean_text(value)
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def harvest_msrc_cvrf_actual(fuente: dict) -> list[dict]:
    release_id = current_msrc_release_id()
    url = f"{fuente['url'].rstrip('/')}/{release_id}"
    raw = fetch(url, timeout=60)
    root = ET.fromstring(raw)
    ns = {
        "cvrf": "http://www.icasi.org/CVRF/schema/cvrf/1.1",
        "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1",
    }
    release_date = root.findtext(".//cvrf:InitialReleaseDate", default=utcnow(), namespaces=ns)
    document_title = root.findtext(".//cvrf:DocumentTitle", default=f"{release_id} Security Updates", namespaces=ns)
    out = []
    seen = set()
    for vuln in root.findall(".//vuln:Vulnerability", ns):
        cve = vuln.findtext("vuln:CVE", default="", namespaces=ns).upper()
        if not cve or cve in seen:
            continue
        seen.add(cve)
        title = vuln.findtext("vuln:Title", default=cve, namespaces=ns)
        threats_by_type: dict[str, list[str]] = {}
        for threat in vuln.findall("vuln:Threats/vuln:Threat", ns):
            threat_type = threat.attrib.get("Type", "")
            desc = threat.findtext("vuln:Description", default="", namespaces=ns)
            threats_by_type.setdefault(threat_type, []).append(desc)
        impacts = unique_values(threats_by_type.get("Impact", []))
        severities = unique_values(threats_by_type.get("Severity", []))
        exploit_status = "; ".join(unique_values(threats_by_type.get("Exploit Status", [])))
        remediations = []
        for rem in vuln.findall(".//vuln:Remediation", ns):
            rem_url = rem.findtext("vuln:URL", default="", namespaces=ns)
            rem_desc = rem.findtext("vuln:Description", default="", namespaces=ns)
            if rem_url:
                remediations.append({"descripcion": clean_text(rem_desc), "url": canonical(rem_url)})
        public_url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
        summary_parts = [
            f"{document_title}.",
            f"Impacto reportado: {', '.join(impacts) if impacts else 'no especificado en CVRF'}.",
            f"Severidad Microsoft: {', '.join(severities) if severities else 'no especificada en CVRF'}.",
        ]
        if exploit_status:
            summary_parts.append(f"Estado de explotación: {exploit_status}.")
        if remediations:
            summary_parts.append("Microsoft publicó actualizaciones o artículos de soporte asociados.")
        out.append(normalizar(
            fuente,
            title,
            public_url,
            release_date,
            " ".join(summary_parts),
            clave_id=f"msrc:{release_id}:{cve}",
            cves=[cve],
            vendor="Microsoft",
            product=title.replace(cve, "").replace("Vulnerability", "").strip(),
            release_id=release_id,
            release_title=document_title,
            exploit_status=exploit_status,
            publicly_disclosed="Publicly Disclosed:Yes" in exploit_status,
            exploited="Exploited:Yes" in exploit_status,
            impact=", ".join(impacts),
            severity=", ".join(severities),
            remediations=remediations[:5],
        ))
    return out


ADAPTADORES = {
    "rss": harvest_rss,
    "json_kev": harvest_kev,
    "scrape_ecucert": harvest_ecucert,
    "json_ransomware_ec": harvest_ransomware_ec,
    "sitemap_diff": harvest_sitemap,
    "msrc_cvrf_actual": harvest_msrc_cvrf_actual,
}


def load_existing_ids() -> set[str]:
    ids = set()
    if ITEMS.exists():
        with ITEMS.open("r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    ids.add(json.loads(line)["id"])
                except Exception:
                    continue
    return ids


def append_items(items: list[dict]) -> int:
    STORE.mkdir(parents=True, exist_ok=True)
    existing = load_existing_ids()
    new = 0
    with ITEMS.open("a", encoding="utf-8") as fh:
        for item in items:
            if item["id"] in existing:
                continue
            fh.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
            existing.add(item["id"])
            new += 1
    return new


def append_items_with_stats(items: list[dict]) -> tuple[int, dict[str, dict[str, int]]]:
    STORE.mkdir(parents=True, exist_ok=True)
    existing = load_existing_ids()
    stats: dict[str, dict[str, int]] = {}
    new = 0
    with ITEMS.open("a", encoding="utf-8") as fh:
        for item in items:
            source = item.get("fuente_id", "unknown")
            stats.setdefault(source, {"leidos": 0, "nuevos": 0})
            stats[source]["leidos"] += 1
            if item["id"] in existing:
                continue
            fh.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
            existing.add(item["id"])
            stats[source]["nuevos"] += 1
            new += 1
    return new, stats


def enrich() -> None:
    result = {"epss": {}, "poc_github": [], "updated": utcnow(), "catalogos": {}}
    try:
        raw = fetch(ENRIQUECIMIENTO["epss"], timeout=90)
        with gzip.GzipFile(fileobj=__import__("io").BytesIO(raw)) as gz:
            text = gz.read().decode("utf-8", "replace").splitlines()
        reader = csv.DictReader(line for line in text if not line.startswith("#"))
        for row in reader:
            cve = row.get("cve", "").upper()
            if cve:
                result["epss"][cve] = {
                    "epss": float(row.get("epss") or 0),
                    "percentile": float(row.get("percentile") or 0),
                }
        result["catalogos"]["epss_total"] = len(result["epss"])
        log(f"OK enriquecimiento=epss cves={len(result['epss'])}")
    except Exception as exc:
        log(f"WARN enriquecimiento=epss error={exc}")
    try:
        text = fetch(ENRIQUECIMIENTO["poc_github"], timeout=90).decode("utf-8", "replace")
        result["poc_github"] = sorted(set(cves_from(text)))
        result["catalogos"]["poc_github_total"] = len(result["poc_github"])
        log(f"OK enriquecimiento=poc_github cves={len(result['poc_github'])}")
    except Exception as exc:
        log(f"WARN enriquecimiento=poc_github error={exc}")
    ENRICH.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listar", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--solo")
    ap.add_argument("--solo-enriquecer", action="store_true")
    ap.add_argument("--sin-enriquecer", action="store_true")
    args = ap.parse_args()

    STORE.mkdir(parents=True, exist_ok=True)
    if args.listar:
        for fuente in FUENTES:
            print(f"{fuente['id']}\t{fuente['tipo']}\t{fuente['url']}")
        return 0
    if args.solo_enriquecer:
        enrich()
        return 0

    selected = [f for f in FUENTES if not args.solo or f["id"] == args.solo]
    all_items = []
    run_audit = {
        "started": utcnow(),
        "sources_expected": len(selected),
        "sources": {},
        "errors": [],
    }
    for fuente in selected:
        start = time.time()
        try:
            items = ADAPTADORES[fuente["tipo"]](fuente)
            all_items.extend(items)
            run_audit["sources"][fuente["id"]] = {"leidos": len(items), "segundos": round(time.time() - start, 2)}
            log(f"OK fuente={fuente['id']} items={len(items)} segundos={time.time() - start:.1f}")
        except Exception as exc:
            run_audit["errors"].append({"fuente": fuente["id"], "error": str(exc)})
            log(f"ERROR fuente={fuente['id']} error={exc}")
    if args.dry_run:
        print(json.dumps({"fuentes": len(selected), "items": len(all_items), "dry_run": True}, ensure_ascii=False, indent=2))
        return 0
    new, stats = append_items_with_stats(all_items)
    for source, source_stats in stats.items():
        run_audit["sources"].setdefault(source, {}).update(source_stats)
    for source_stats in run_audit["sources"].values():
        source_stats.setdefault("leidos", 0)
        source_stats.setdefault("nuevos", 0)
    audit_path = STORE / "harvest-run.json"
    if args.solo and audit_path.exists():
        try:
            previous = json.loads(audit_path.read_text(encoding="utf-8"))
            previous_sources = previous.get("sources", {}) if isinstance(previous, dict) else {}
            previous_sources.update(run_audit["sources"])
            run_audit["sources"] = previous_sources
            run_audit["sources_expected"] = len(FUENTES)
        except Exception:
            pass
    run_audit["total_leidos"] = sum(int(s.get("leidos", 0)) for s in run_audit["sources"].values())
    run_audit["total_nuevos"] = sum(int(s.get("nuevos", 0)) for s in run_audit["sources"].values())
    run_audit["finished"] = utcnow()
    audit_path.write_text(json.dumps(run_audit, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"OK cosecha total={len(all_items)} nuevos={new}")
    if not args.sin_enriquecer:
        enrich()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
