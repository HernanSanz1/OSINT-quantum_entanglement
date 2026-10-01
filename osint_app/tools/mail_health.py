"""
Mail Health Tool — Salud del correo de un dominio (MX, SPF, DMARC, DKIM).

Solo consulta DNS público (pasivo, sin clave ni binarios). Sirve para saber qué
proveedor de correo usa un dominio y si se puede suplantar: sin DMARC (o con
p=none) cualquiera puede enviar correo "desde" ese dominio sin que el receptor
lo bloquee. Los selectores DKIM no se pueden listar: se prueban los más comunes,
así que no encontrarlos NO prueba que no exista.
"""
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional, Tuple

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import sanitize_input, sanitize_snippet, validate_domain
from ..utils.cache import CacheManager
from .domain_whois import candidate_domains

logger = logging.getLogger(__name__)

DNS_TIMEOUT = 6
SPF_MAX_LOOKUPS = 10            # límite del RFC 7208
SPF_MAX_DEPTH = 10
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
    "s1", "s2", "smtp", "mandrill", "mailgun", "sendgrid", "zoho", "protonmail",
)
MX_PROVIDERS = (   # (sufijo del host MX, proveedor)
    ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
    ("protection.outlook.com", "Microsoft 365"), ("outlook.com", "Microsoft 365"),
    ("zoho.com", "Zoho Mail"), ("zoho.eu", "Zoho Mail"),
    ("pphosted.com", "Proofpoint"), ("mimecast.com", "Mimecast"),
    ("secureserver.net", "GoDaddy"), ("yahoodns.net", "Yahoo"),
    ("protonmail.ch", "Proton Mail"), ("messagingengine.com", "Fastmail"),
    ("mailgun.org", "Mailgun"), ("ovh.net", "OVH"), ("registrar-servers.com", "Namecheap"),
)
SEVERITY_SCORE = {"alta": 88, "media": 75, "baja": 60}

REQUIREMENTS = ToolRequirements(
    mandatory=["domain"],
    optional=[],
    produces=["domain"],
    hint="Necesita un dominio (ej: empresa.com) para revisar su configuración de correo.",
)

Query = Callable[[str, str], Optional[List[str]]]   # (nombre, tipo) → registros | [] si no hay | None si falla el DNS


# ── Análisis (funciones puras, sin red) ──────────────────────────────────────

def parse_mx(records: List[str]) -> List[dict]:
    """'10 aspmx.l.google.com.' → [{'priority': 10, 'host': 'aspmx.l.google.com'}], ordenado."""
    out = []
    for rec in records or []:
        parts = str(rec).split()
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        out.append({"priority": int(parts[0]), "host": parts[1].lower().rstrip(".")})
    return sorted(out, key=lambda m: (m["priority"], m["host"]))


def is_null_mx(mx: List[dict]) -> bool:
    """MX nulo (RFC 7505): el dominio declara que NO recibe correo."""
    return len(mx) == 1 and mx[0]["host"] == ""


def detect_provider(mx: List[dict]) -> str:
    for m in mx:
        for suffix, name in MX_PROVIDERS:
            if m["host"] == suffix or m["host"].endswith("." + suffix):
                return name
    return ""


def parse_spf(record: str) -> dict:
    """Descompone un registro SPF en términos (qualifier, mecanismo, valor)."""
    terms: List[dict] = []
    redirect = ""
    for tok in str(record).split()[1:]:
        low = tok.lower()
        if low.startswith("redirect="):
            redirect = low.split("=", 1)[1]
            continue
        if low.startswith("exp=") or "=" in low.split(":", 1)[0]:
            continue                                   # modificadores sin efecto en el análisis
        qualifier = low[0] if low[0] in "+-~?" else "+"
        body = low.lstrip("+-~?")
        name = re.split(r"[:/]", body, maxsplit=1)[0]
        value = body.split(":", 1)[1].split("/", 1)[0] if ":" in body else ""
        terms.append({"qualifier": qualifier, "mechanism": name, "value": value})
    all_term = next((t for t in terms if t["mechanism"] == "all"), None)
    return {
        "terms": terms,
        "redirect": redirect,
        "all": all_term["qualifier"] if all_term else "",
        "includes": [t["value"] for t in terms if t["mechanism"] == "include" and t["value"]],
        "uses_ptr": any(t["mechanism"] == "ptr" for t in terms),
    }


def count_spf_lookups(spf: dict, fetch: Callable[[str], Optional[str]], depth: int = 0) -> int:
    """Cuenta las consultas DNS que exige evaluar el SPF (incluye include/redirect). Se detiene al pasar el límite."""
    total = 0
    targets = [(t["mechanism"], t["value"]) for t in spf["terms"]]
    if spf["redirect"]:
        targets.append(("redirect", spf["redirect"]))
    for mech, value in targets:
        if mech not in ("include", "a", "mx", "ptr", "exists", "redirect"):
            continue
        total += 1
        if mech in ("include", "redirect") and value and depth < SPF_MAX_DEPTH and total <= SPF_MAX_LOOKUPS:
            sub = fetch(value)
            if sub:
                total += count_spf_lookups(parse_spf(sub), fetch, depth + 1)
        if total > SPF_MAX_LOOKUPS:
            break
    return total


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in str(record).split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100
    return {
        "policy": tags.get("p", "").lower(),
        "subdomain_policy": tags.get("sp", "").lower(),
        "pct": pct,
        "rua": tags.get("rua", ""),
    }


def _only(records: List[str], prefix: str) -> List[str]:
    return [r for r in records or [] if r.strip().lower().startswith(prefix)]


def build_findings(info: dict) -> List[Tuple[str, str]]:
    """Hallazgos (gravedad, texto). Los avisos por falta de SPF/DMARC solo aplican si el dominio recibe correo."""
    out: List[Tuple[str, str]] = []
    uses_mail = bool(info["mx"]) and not info["null_mx"]

    if info["spf_count"] > 1:
        out.append(("alta", "Hay varios registros SPF: es un error (permerror) y los receptores lo ignoran"))
    elif info["spf_count"] == 0:
        if uses_mail:
            out.append(("alta", "Sin SPF: no hay lista de servidores autorizados a enviar por este dominio"))
    else:
        spf = info["spf"]
        if spf["all"] == "+":
            out.append(("alta", "SPF con +all: autoriza a CUALQUIER servidor a enviar como este dominio"))
        elif spf["all"] == "?":
            out.append(("media", "SPF con ?all: neutral, no protege contra suplantación"))
        elif not spf["all"] and not spf["redirect"]:
            out.append(("media", "SPF sin 'all' final: no define qué hacer con servidores no autorizados"))
        if info["spf_lookups"] > SPF_MAX_LOOKUPS:
            out.append(("media", f"SPF necesita más de {SPF_MAX_LOOKUPS} consultas DNS ({info['spf_lookups']}): "
                                 "los receptores pueden rechazarlo (permerror)"))
        if spf["uses_ptr"]:
            out.append(("baja", "SPF usa el mecanismo 'ptr', desaconsejado por lento e inseguro"))

    dmarc = info["dmarc"]
    if not dmarc:
        if uses_mail:
            out.append(("alta", "Sin DMARC: se puede enviar correo falso como este dominio sin que el receptor lo bloquee"))
    else:
        if not dmarc["policy"]:
            out.append(("media", "DMARC sin política (p=) válida: no tiene efecto"))
        elif dmarc["policy"] == "none":
            out.append(("media", "DMARC con p=none: solo monitorea, no bloquea correos falsos"))
        elif dmarc["pct"] < 100:
            out.append(("baja", f"DMARC se aplica solo al {dmarc['pct']}% de los correos (pct={dmarc['pct']})"))
    return out


def spoofing_risk(info: dict) -> str:
    """alto / medio / bajo / n/a (el dominio no recibe correo)."""
    if not info["mx"] or info["null_mx"]:
        return "n/a"
    sev = [s for s, _ in build_findings(info)]
    if "alta" in sev:
        return "alto"
    return "medio" if "media" in sev else "bajo"


# ── Herramienta ──────────────────────────────────────────────────────────────

class MailHealthTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Mail Health",
            "Salud del correo de un dominio: MX, SPF, DMARC y DKIM por DNS (sin clave); detecta si se puede suplantar",
            REQUIREMENTS,
        )
        self._python_pkgs = ["dns"]
        self._install_cmd = "pip install dnspython"
        self._cache = CacheManager(max_size=100, ttl=3600)

    def check_available(self) -> bool:
        try:
            import dns.resolver  # noqa: F401
            return True
        except ImportError:
            return False

    def _query(self, name: str, rtype: str) -> Optional[List[str]]:
        import dns.exception
        import dns.resolver
        try:
            answers = dns.resolver.resolve(name, rtype, lifetime=DNS_TIMEOUT)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.DNSException, OSError) as e:
            logger.warning(f"DNS {rtype} {name}: {type(e).__name__}")
            return None
        if rtype == "TXT":
            return ["".join(s.decode("utf-8", "replace") if isinstance(s, bytes) else str(s)
                            for s in r.strings) for r in answers]
        return [str(r) for r in answers]

    def _nxdomain(self, domain: str) -> bool:
        """True si el dominio no existe (NXDOMAIN); cualquier otra respuesta o fallo cuenta como 'existe'."""
        import dns.exception
        import dns.resolver
        try:
            dns.resolver.resolve(domain, "A", lifetime=DNS_TIMEOUT)
        except dns.resolver.NXDOMAIN:
            return True
        except (dns.exception.DNSException, OSError):
            pass
        return False

    def _spf_of(self, domain: str) -> Optional[str]:
        found = _only(self._query(domain, "TXT") or [], "v=spf1")
        return found[0] if found else None

    def _find_dmarc(self, domain: str) -> Tuple[Optional[dict], str]:
        """DMARC del dominio o, si no tiene, el del dominio padre (herencia de la organización)."""
        for cand in candidate_domains(domain):
            found = _only(self._query(f"_dmarc.{cand}", "TXT") or [], "v=dmarc1")
            if found:
                return parse_dmarc(found[0]), cand
        return None, ""

    def _find_dkim(self, domain: str) -> List[str]:
        def probe(sel):
            records = self._query(f"{sel}._domainkey.{domain}", "TXT") or []
            return sel if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records) else None
        with ThreadPoolExecutor(max_workers=8) as pool:
            return [s for s in pool.map(probe, DKIM_SELECTORS) if s]

    def collect(self, domain: str) -> Optional[dict]:
        """Reúne los registros de correo. None si el DNS no responde en absoluto."""
        mx_raw = self._query(domain, "MX")
        txt_raw = self._query(domain, "TXT")
        if mx_raw is None and txt_raw is None:
            return None
        mx = parse_mx(mx_raw or [])
        spf_records = _only(txt_raw or [], "v=spf1")
        spf = parse_spf(spf_records[0]) if spf_records else None
        dmarc, dmarc_domain = self._find_dmarc(domain)
        info = {
            "domain": domain,
            "mx": mx,
            "null_mx": is_null_mx(mx),
            "provider": detect_provider(mx),
            "spf_count": len(spf_records),
            "spf_record": spf_records[0] if spf_records else "",
            "spf": spf,
            "spf_lookups": count_spf_lookups(spf, self._spf_of) if spf else 0,
            "dmarc": dmarc,
            "dmarc_domain": dmarc_domain,
            "dkim_selectors": self._find_dkim(domain),
        }
        info["findings"] = build_findings(info)
        info["spoofing_risk"] = spoofing_risk(info)
        return info

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = sanitize_input(query_params.domain) if query_params.domain else ""
        domain = domain.strip().lower().lstrip(".")
        if not domain or not validate_domain(domain):
            logger.warning("MailHealthTool: dominio inválido o ausente")
            return []
        if not self.check_available():
            logger.error("dnspython no instalado — pip install dnspython")
            return []

        cached = self._cache.get({"domain": domain})
        if cached is not None:
            self._report_progress(f"📦 Mail Health: usando caché de {domain}")
            return cached

        self._report_progress(f"🔍 Mail Health: revisando MX, SPF, DMARC y DKIM de {domain}…")
        if self._nxdomain(domain):
            self._report_progress(f"⚠️ Mail Health: {domain} no existe (NXDOMAIN).")
            return []
        info = self.collect(domain)
        if info is None:
            self._report_progress("⚠️ Mail Health: el DNS no respondió.")
            return []

        if info["null_mx"]:
            mail = "MX nulo, no recibe correo"
        elif info["mx"]:
            mail = info["provider"] or info["mx"][0]["host"]
        else:
            mail = "sin MX, no recibe correo"
        if info["spf_count"] == 0:
            spf = "ausente"
        elif info["spf"]["all"]:
            spf = {"-": "-all (estricto)", "~": "~all (suave)", "?": "?all (neutral)", "+": "+all (abierto)"}[info["spf"]["all"]]
        else:
            spf = "sin 'all'"
        dmarc = f"p={info['dmarc']['policy'] or '?'}" if info["dmarc"] else "ausente"
        if info["dmarc"] and info["dmarc_domain"] != domain:
            dmarc += f" (heredado de {info['dmarc_domain']})"
        parts = [f"Correo: {mail}", f"SPF: {spf}", f"DMARC: {dmarc}",
                 "DKIM: " + (", ".join(info["dkim_selectors"]) if info["dkim_selectors"] else "no hallado en selectores comunes"),
                 f"Riesgo de suplantación: {info['spoofing_risk']}"]

        results = [SearchResult(
            title=f"Salud de correo: {domain}",
            url="",
            snippet=sanitize_snippet(" · ".join(parts)),
            source_tool=self.name,
            category="Network",
            relevance_score=75,
            raw_data={k: v for k, v in info.items() if k != "findings"},
        )]
        for severity, text in info["findings"]:
            results.append(SearchResult(
                title=f"⚠️ {domain}: {text}",
                url="",
                snippet=sanitize_snippet(f"[{severity.upper()}] {text}"),
                source_tool=self.name,
                category="Alerta",
                relevance_score=SEVERITY_SCORE[severity],
                raw_data={"domain": domain, "severity": severity, "alert": text},
            ))

        self._report_progress(f"✅ Mail Health: {domain} — riesgo de suplantación {info['spoofing_risk']}, "
                              f"{len(info['findings'])} hallazgo(s)")
        self._cache.set({"domain": domain}, results)
        return results
