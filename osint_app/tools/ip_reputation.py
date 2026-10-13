"""
IP Reputation — inteligencia de amenazas real, gratuita y sin clave.

Por qué: las 5 herramientas CTI del proyecto (IntelOwl, OpenCTI, MISP, Cortex, IntelMQ) son plantillas vacías
que solo responden "servidor no configurado". Esta herramienta da CTI real desde el primer momento combinando
fuentes públicas verificadas en vivo (2026-10-04):

  · Shodan InternetDB  — puertos abiertos, hostnames, software (CPE), etiquetas y CVE conocidos de la IP.
  · GreyNoise Community — si la IP escanea Internet y su clasificación (malicious / suspicious / benign).
  · Tor Project         — lista oficial de nodos de salida de Tor.
  · Spamhaus DROP       — redes secuestradas o de operadores criminales ("no enrutar").
  · FireHOL nivel 1     — agregado de listas de bloqueo con muy pocos falsos positivos.
  · URLhaus (abuse.ch)  — URLs que distribuyen malware en los últimos 30 días.

Las listas (Tor, DROP, FireHOL) se descargan una vez y se reutilizan unas horas.
"""
import ipaddress
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

import requests

from ..core.base_tool import OSINTTool
from ..core.models import QueryParameters, SearchResult, ToolRequirements
from ..utils.sanitizer import validate_ip

logger = logging.getLogger(__name__)

USER_AGENT = "SENTINEL-OSINT/2.0 (https://github.com/HernanSanz1/OSINT-quantum_entanglement)"
TIMEOUT = 20
LIST_TTL = 6 * 3600

INTERNETDB = "https://internetdb.shodan.io/{ip}"
GREYNOISE = "https://api.greynoise.io/v3/community/{ip}"
LISTS = {
    "tor": "https://check.torproject.org/torbulkexitlist",
    "drop": "https://www.spamhaus.org/drop/drop_v4.json",
    "firehol": "https://iplists.firehol.org/files/firehol_level1.netset",
    # URLs que distribuyen malware AHORA (últimos 30 días). Sin ella, una IP que repartía malware salía "riesgo 0"
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_recent/",
    # URLs de phishing activas (feed público gratuito de OpenPhish, ~300 URLs, se renueva cada pocas horas)
    "openphish": "https://openphish.com/feed.txt",
}

_lists_lock = threading.Lock()
_lists: Dict[str, Tuple[float, object]] = {}      # nombre → (momento de descarga, contenido procesado)


def _download_list(name: str):
    """Lista ya procesada: set de IPs (tor) o lista de redes (drop, firehol). None si no se pudo descargar."""
    with _lists_lock:
        cached = _lists.get(name)
        if cached and time.time() - cached[0] < LIST_TTL:
            return cached[1]
    try:
        resp = requests.get(LISTS[name], headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.warning(f"IP Reputation: no se pudo descargar la lista {name} ({type(e).__name__})")
        return None
    if name == "tor":
        parsed = {line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")}
    elif name in ("urlhaus", "openphish"):
        from urllib.parse import urlsplit
        parsed = {}
        for line in resp.text.split():
            if line.startswith(("http://", "https://")):
                try:
                    host = (urlsplit(line).hostname or "").lower()
                except ValueError:
                    continue
                if host:
                    parsed.setdefault(host, []).append(line)
    else:
        nets = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if name == "drop":
                import json
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                cidr, label = item.get("cidr"), item.get("sblid", "")
            else:
                cidr, label = line, ""
            try:
                nets.append((ipaddress.ip_network(cidr, strict=False), label))
            except (ValueError, TypeError):
                continue
        parsed = nets
    with _lists_lock:
        _lists[name] = (time.time(), parsed)
    return parsed


def _norm_url(url: str) -> str:
    return (url or "").strip().rstrip("/").lower()


# Plataformas compartidas: que alojen ALGUNA página maliciosa no dice nada del resto de sus páginas
SHARED_HOSTS = {
    "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "github.com", "raw.githubusercontent.com", "gist.github.com", "dropbox.com",
    "www.dropbox.com", "dl.dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "forms.office.com",
    "cdn.discordapp.com", "t.me", "bit.ly", "tinyurl.com", "linktr.ee", "pastebin.com", "ipfs.io",
}


def feed_hits(urls: List[str]) -> List[Tuple[str, str]]:
    """[(severidad, texto)] si alguna URL (o su servidor) está en OpenPhish o URLhaus. Lo usa Link Shield.

    URL exacta en la lista → "alta". Solo el servidor → "media": servicios compartidos (docs.google.com,
    blogspot) también alojan páginas maliciosas sin que todo el servidor lo sea.
    """
    from urllib.parse import urlsplit
    found: List[Tuple[str, str]] = []
    for feed, label in (("openphish", "phishing activo (OpenPhish)"), ("urlhaus", "malware activo (URLhaus, abuse.ch)")):
        data = _download_list(feed)
        if not data:
            continue
        for url in urls:
            try:
                host = (urlsplit(url if "://" in url else "http://" + url).hostname or "").lower()
            except ValueError:
                continue
            listed = data.get(host) or []
            if not listed:
                continue
            target = _norm_url(url if "://" in url else "http://" + url)
            exact = any(_norm_url(u) == target or _norm_url(u).split("://", 1)[-1] == target.split("://", 1)[-1] for u in listed)
            if exact:
                found.append(("alta", f"La URL está en una lista pública de {label}"))
            elif host in SHARED_HOSTS or host.endswith((".sharepoint.com", ".blogspot.com", ".pages.dev", ".web.app")):
                continue
            else:
                found.append(("media", f"El servidor {host} aloja {len(listed)} URL(s) de {label}"))
            break
    return found


def _in_networks(ip: ipaddress._BaseAddress, nets) -> Optional[Tuple[str, str]]:
    for net, label in nets or []:
        if ip.version == net.version and ip in net:
            return str(net), label
    return None


class IpReputationTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "IP Reputation",
            "Reputación de una IP: puertos/CVE (Shodan InternetDB), escáneres (GreyNoise), Tor y listas de bloqueo",
            ToolRequirements(
                mandatory=["ip"],
                optional=[],
                produces=["domain", "note"],
                hint="Necesita una IP pública. Obtenla con dnspython o de un subdominio.",
            ),
        )
        self._python_pkgs = ["requests"]
        self._install_cmd = "pip install requests"

    def check_available(self) -> bool:
        return True

    def _internetdb(self, ip: str) -> Tuple[Optional[dict], str]:
        try:
            resp = requests.get(INTERNETDB.format(ip=ip), headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        except requests.RequestException as e:
            return None, f"sin conexión ({type(e).__name__})"
        if resp.status_code == 404:
            return {}, ""                                    # Shodan no la tiene registrada: no es un error
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"
        try:
            return resp.json(), ""
        except ValueError:
            return None, "respuesta no válida"

    def _greynoise(self, ip: str) -> Tuple[Optional[dict], str]:
        try:
            resp = requests.get(GREYNOISE.format(ip=ip), headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        except requests.RequestException as e:
            return None, f"sin conexión ({type(e).__name__})"
        if resp.status_code == 429:
            return None, "límite diario gratuito agotado"
        if resp.status_code not in (200, 404):               # 404 = "no observada escaneando": dato válido
            return None, f"HTTP {resp.status_code}"
        try:
            return resp.json(), ""
        except ValueError:
            return None, "respuesta no válida"

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        raw = (query_params.ip or "").strip()
        if not raw or not validate_ip(raw):
            # Antes: "0 resultados" sin decir por qué (prueba real con "hola mundo" guardado como IP)
            self._report_progress(f"⚠️ IP Reputation: «{raw[:60]}» no es una dirección IP válida (ejemplo: 8.8.8.8); "
                                  "se omite. Corrígela en la pestaña Datos.")
            return []
        ip = ipaddress.ip_address(raw)
        if not ip.is_global:
            self._report_progress(f"ℹ️ IP Reputation: {raw} es una IP privada o reservada; no tiene reputación pública.")
            return [SearchResult(title=f"IP no pública: {raw}", url="", snippet="IP privada, reservada o local: "
                                 "no aparece en fuentes públicas de amenazas.", source_tool=self.name,
                                 category="Network", relevance_score=30)]

        self._report_progress(f"🔍 IP Reputation: consultando 6 fuentes para {raw}…")
        findings: List[Tuple[str, str, int]] = []          # (nivel, texto, puntos de riesgo)
        sources_failed = []
        facts = []

        idb, err = self._internetdb(raw)
        if idb is None:
            sources_failed.append(f"InternetDB ({err})")
        elif idb:
            ports = idb.get("ports") or []
            vulns = idb.get("vulns") or []
            if ports:
                facts.append(f"Puertos abiertos: {', '.join(map(str, ports[:20]))}")
            if idb.get("hostnames"):
                facts.append(f"Hostnames: {', '.join(idb['hostnames'][:5])}")
            if idb.get("cpes"):
                facts.append(f"Software: {', '.join(idb['cpes'][:5])}")
            if idb.get("tags"):
                facts.append(f"Etiquetas Shodan: {', '.join(idb['tags'])}")
            if vulns:
                findings.append(("ALTA" if len(vulns) >= 5 else "MEDIA",
                                 f"{len(vulns)} vulnerabilidad(es) posibles según Shodan (inferidas por la versión del "
                                 f"software, sin comprobar): {', '.join(sorted(vulns)[:8])}",
                                 35 if len(vulns) >= 5 else 20))
            risky = {23: "Telnet", 445: "SMB", 3389: "RDP (escritorio remoto)", 5900: "VNC", 6379: "Redis",
                     9200: "Elasticsearch", 27017: "MongoDB", 11211: "Memcached", 2375: "Docker sin TLS"}
            exposed = [f"{p} {risky[p]}" for p in ports if p in risky]
            if exposed:
                findings.append(("MEDIA", f"Servicios sensibles expuestos a Internet: {', '.join(exposed)}", 15))
        else:
            facts.append("Shodan no tiene datos de esta IP")

        gn, err = self._greynoise(raw)
        if gn is None:
            sources_failed.append(f"GreyNoise ({err})")
        else:
            cls = (gn.get("classification") or "").lower()
            if gn.get("riot"):
                facts.append(f"GreyNoise: servicio conocido y legítimo ({gn.get('name') or 'RIOT'})")
            elif gn.get("noise"):
                level, pts = {"malicious": ("ALTA", 40), "suspicious": ("MEDIA", 20)}.get(cls, ("BAJA", 5))
                findings.append((level, f"GreyNoise la ve escaneando Internet (clasificación: {cls or 'desconocida'}, "
                                        f"última vez {gn.get('last_seen', '?')})", pts))
            else:
                facts.append("GreyNoise: no la ha visto escaneando Internet")

        tor = _download_list("tor")
        if tor is None:
            sources_failed.append("Tor (lista no disponible)")
        elif raw in tor:
            findings.append(("MEDIA", "Es un nodo de SALIDA de Tor: el tráfico puede venir de cualquier usuario anónimo", 25))

        drop = _download_list("drop")
        if drop is None:
            sources_failed.append("Spamhaus DROP (lista no disponible)")
        else:
            hit = _in_networks(ip, drop)
            if hit:
                findings.append(("ALTA", f"Está en Spamhaus DROP ({hit[0]}, {hit[1]}): red de operadores criminales", 50))

        firehol = _download_list("firehol")
        if firehol is None:
            sources_failed.append("FireHOL (lista no disponible)")
        else:
            hit = _in_networks(ip, firehol)
            if hit:
                findings.append(("ALTA", f"Está en FireHOL nivel 1 (red {hit[0]}): listas de bloqueo de ataques", 35))

        urlhaus = _download_list("urlhaus")
        if urlhaus is None:
            sources_failed.append("URLhaus (lista no disponible)")
        elif raw in urlhaus:
            sample = urlhaus[raw]
            findings.append(("ALTA", f"Distribuye malware ahora mismo según URLhaus: {len(sample)} URL(s), p. ej. "
                                     f"{sample[0].replace('http', 'hxxp', 1)}", 50))

        score = min(100, sum(p for _, _, p in findings))
        risk = "alto" if score >= 50 else "medio" if score >= 20 else "bajo"
        summary = f"Riesgo {risk} {score} de 100 · " + " · ".join(facts or ["sin datos adicionales"])
        if sources_failed:
            summary += " · No respondieron: " + ", ".join(sources_failed)
        results = [SearchResult(
            title=f"Reputación de IP {raw}: riesgo {risk}",
            url=f"https://www.shodan.io/host/{raw}",
            snippet=summary,
            source_tool=self.name, category="Reputación IP",
            relevance_score=90 if risk == "alto" else 75 if risk == "medio" else 60,
            raw_data={"ip": raw, "score": score, "risk": risk, "internetdb": idb or {}, "greynoise": gn or {},
                      "findings": [{"level": lvl, "text": t} for lvl, t, _ in findings], "failed": sources_failed},
        )]
        for level, text, _ in findings:
            results.append(SearchResult(
                title=f"⚠️ {raw}: {text[:90]}", url=f"https://viz.greynoise.io/ip/{raw}" if "GreyNoise" in text else "",
                snippet=f"[{level}] {text}", source_tool=self.name, category="Alerta",
                relevance_score={"ALTA": 88, "MEDIA": 75}.get(level, 60),
            ))
        for host in (idb or {}).get("hostnames", [])[:10]:
            results.append(SearchResult(
                title=f"Hostname de {raw}: {host}", url=f"https://{host}",
                snippet=f"Nombre asociado a la IP {raw} según Shodan InternetDB", source_tool=self.name,
                category="Network", relevance_score=60, raw_data={"hostname": host, "ip": raw},
            ))
        self._report_progress(f"✅ IP Reputation: {raw} — riesgo {risk} ({score}/100), {len(findings)} señal(es)")
        return results
