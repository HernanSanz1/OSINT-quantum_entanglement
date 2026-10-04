"""
crt.sh Tool — Descubrimiento pasivo de subdominios vía Certificate Transparency.

Consulta los logs públicos de transparencia de certificados (https://crt.sh)
para un dominio y devuelve los subdominios que aparecen en certificados
emitidos. No necesita clave ni binarios externos (a diferencia de
Subfinder/Amass, que requieren Go).
"""
import logging
import random
import time
from typing import List

import requests

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import sanitize_input, validate_domain
from ..utils.rate_limiter import RateLimiter
from ..utils.cache import CacheManager

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
MAX_SUBDOMAINS = 500          # tope de resultados por consulta
REQUEST_TIMEOUT = 45          # crt.sh puede ser lento
MAX_RETRIES = 3               # crt.sh devuelve 502/503 de forma intermitente
RETRY_STATUS = {502, 503, 504}

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36',
]

REQUIREMENTS = ToolRequirements(
    mandatory=["domain"],
    optional=[],
    produces=["domain"],
    hint="Necesita un dominio (ej: empresa.com) para buscar sus subdominios.",
)


def parse_crtsh(entries: list, domain: str) -> List[str]:
    """Extrae subdominios únicos y en ámbito de la respuesta JSON de crt.sh.

    Función pura (sin red) para poder probarla. Limpia comodines (*.), pasa a
    minúsculas, deduplica y descarta lo que no pertenezca al dominio.
    """
    domain = (domain or "").strip().lower().lstrip(".")
    if not domain:
        return []

    suffix = "." + domain
    found = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for field in (entry.get("name_value", ""), entry.get("common_name", "")):
            for line in str(field or "").splitlines():
                name = line.strip().lower().lstrip("*.").rstrip(".")
                if not name or name in seen:
                    continue
                if name == domain or name.endswith(suffix):
                    seen.add(name)
                    found.append(name)
    found.sort()
    return found[:MAX_SUBDOMAINS]


CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"
FALLBACK_TIMEOUT = 25


def in_scope(name: str, domain: str) -> str:
    """Nombre limpio si pertenece al dominio (o es el dominio), "" si no."""
    name = (name or "").strip().lower().lstrip("*.").rstrip(".")
    return name if name and (name == domain or name.endswith("." + domain)) and validate_domain(name) else ""


class CrtShTool(OSINTTool):
    """Subdominios pasivos de TRES fuentes.

    Verificado en real 2026-10-04: crt.sh caído con HTTP 502 en todo el mundo; CertSpotter dio 59 subdominios de
    utpl.edu.ec y HackerTarget 50 con su IP. Antes solo había crt.sh: si fallaba, 0 resultados. Cada subdominio
    indica en qué fuentes aparece (más fuentes = más fiable). El nombre "crt.sh" se mantiene por compatibilidad.
    """

    def __init__(self):
        super().__init__(
            "crt.sh",
            "Subdominios pasivos: crt.sh + CertSpotter + HackerTarget (sin clave ni binarios)",
            REQUIREMENTS,
        )
        self._python_pkgs = ["requests"]
        self._install_cmd = "pip install requests"
        self._rate = RateLimiter(max_requests=5, time_window=60)
        self._cache = CacheManager(max_size=100, ttl=1800)

    def check_available(self) -> bool:
        return True

    # ── fuentes ──────────────────────────────────────────────────────────────
    def _from_crtsh(self, domain: str):
        """(subdominios, motivo del fallo o "")."""
        for attempt in range(MAX_RETRIES):
            if attempt:
                time.sleep(random.uniform(2.0, 4.0))
            try:
                resp = requests.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"},
                                    headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=REQUEST_TIMEOUT)
            except requests.RequestException as e:
                logger.warning(f"crt.sh error de red (intento {attempt + 1}): {type(e).__name__}")
                continue
            if resp.status_code in RETRY_STATUS:
                logger.warning(f"crt.sh HTTP {resp.status_code} (intento {attempt + 1})")
                continue
            if resp.status_code != 200:
                return [], f"HTTP {resp.status_code}"
            try:
                return parse_crtsh(resp.json(), domain), ""
            except ValueError:
                return [], "respuesta no válida"
        return [], "no respondió tras varios intentos"

    def _from_certspotter(self, domain: str):
        try:
            resp = requests.get(CERTSPOTTER_URL,
                                params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
                                headers={"User-Agent": "SENTINEL-OSINT/2.0"}, timeout=FALLBACK_TIMEOUT)
        except requests.RequestException as e:
            return [], f"sin conexión ({type(e).__name__})"
        if resp.status_code == 429:
            return [], "límite gratuito agotado (100 consultas/hora)"
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}"
        try:
            names = [in_scope(n, domain) for item in resp.json() for n in item.get("dns_names", [])]
        except (ValueError, AttributeError, TypeError):
            return [], "respuesta no válida"
        return sorted({n for n in names if n}), ""

    def _from_hackertarget(self, domain: str):
        """[(subdominio, ip)] de HackerTarget (gratis: 50 consultas al día por IP)."""
        try:
            resp = requests.get(HACKERTARGET_URL, params={"q": domain},
                                headers={"User-Agent": "SENTINEL-OSINT/2.0"}, timeout=FALLBACK_TIMEOUT)
        except requests.RequestException as e:
            return [], f"sin conexión ({type(e).__name__})"
        text = resp.text.strip()
        low = text.lower()
        if resp.status_code != 200 or low.startswith(("error", "api count exceeded")):
            return [], ("límite diario gratuito agotado" if "exceeded" in low else f"HTTP {resp.status_code}: {text[:60]}")
        pairs = []
        for line in text.splitlines():
            host, _, ip = line.partition(",")
            host = in_scope(host, domain)
            if host:
                pairs.append((host, ip.strip()))
        return pairs, ""

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = sanitize_input(query_params.domain) if query_params.domain else ""
        domain = domain.strip().lower().lstrip(".")
        if not domain or not validate_domain(domain):
            logger.warning("CrtShTool: dominio inválido o ausente")
            return []

        cached = self._cache.get({"domain": domain})
        if cached is not None:
            self._report_progress(f"📦 Subdominios: usando caché — {len(cached)} subdominios")
            return cached

        self._rate.wait_if_needed()
        self._report_progress(f"🔍 Subdominios de {domain}: consultando crt.sh, CertSpotter y HackerTarget…")

        sources: dict = {}
        ips: dict = {}
        crt, err1 = self._from_crtsh(domain)
        cs, err2 = self._from_certspotter(domain)
        ht, err3 = self._from_hackertarget(domain)
        status = [("crt.sh", len(crt), err1), ("CertSpotter", len(cs), err2), ("HackerTarget", len(ht), err3)]
        for name in crt:
            sources.setdefault(name, []).append("crt.sh")
        for name in cs:
            sources.setdefault(name, []).append("CertSpotter")
        for name, ip in ht:
            if "HackerTarget" not in sources.setdefault(name, []):
                sources[name].append("HackerTarget")
            if ip:
                ips[name] = ip

        detail = " · ".join(f"{n}: {c}" if not e else f"{n}: falló ({e})" for n, c, e in status)
        if not sources:
            if all(e for _, _, e in status):
                self._report_progress(f"⚠️ Subdominios: ninguna fuente respondió — {detail}")
            else:
                self._report_progress(f"✅ Subdominios: ninguno encontrado — {detail}")
            return []

        names = sorted(sources, key=lambda n: (-len(sources[n]), n))[:MAX_SUBDOMAINS]
        results = []
        for sub in names:
            found_in = sources[sub]
            ip = ips.get(sub, "")
            results.append(SearchResult(
                title=sub,
                url=f"https://{sub}",
                snippet=f"Subdominio de {domain} visto en {', '.join(found_in)}" + (f" · IP {ip}" if ip else ""),
                source_tool=self.name,
                category="Subdominio",
                relevance_score=min(90, 60 + 10 * len(found_in)),
                raw_data={"subdomain": sub, "domain": domain, "sources": found_in, "ip": ip},
            ))
        self._report_progress(f"✅ Subdominios: {len(results)} únicos — {detail}")
        if not any(e for _, _, e in status):
            self._cache.set({"domain": domain}, results)
        return results
