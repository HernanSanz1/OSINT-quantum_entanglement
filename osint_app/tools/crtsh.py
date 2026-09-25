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


class CrtShTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "crt.sh",
            "Descubre subdominios vía Certificate Transparency (sin clave ni binarios)",
            REQUIREMENTS,
        )
        self._python_pkgs = ["requests"]
        self._install_cmd = "pip install requests"
        self._rate = RateLimiter(max_requests=5, time_window=60)
        self._cache = CacheManager(max_size=100, ttl=1800)

    def check_available(self) -> bool:
        return True

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = sanitize_input(query_params.domain) if query_params.domain else ""
        domain = domain.strip().lower().lstrip(".")
        if not domain or not validate_domain(domain):
            logger.warning("CrtShTool: dominio inválido o ausente")
            return []

        cached = self._cache.get({"domain": domain})
        if cached is not None:
            self._report_progress(f"📦 crt.sh: usando caché — {len(cached)} subdominios")
            return cached

        self._rate.wait_if_needed()
        self._report_progress(f"🔍 crt.sh: consultando Certificate Transparency de {domain}…")

        # crt.sh devuelve 502/503 de forma intermitente: reintentar con espera.
        entries = None
        for attempt in range(MAX_RETRIES):
            if attempt:
                time.sleep(random.uniform(2.0, 4.0))
                self._report_progress(f"↻ crt.sh: reintentando ({attempt + 1}/{MAX_RETRIES})…")
            try:
                resp = requests.get(
                    CRTSH_URL,
                    params={"q": f"%.{domain}", "output": "json"},
                    headers={"User-Agent": random.choice(USER_AGENTS)},
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException as e:
                logger.warning(f"crt.sh error de red (intento {attempt + 1}): {type(e).__name__}")
                continue

            if resp.status_code in RETRY_STATUS:
                logger.warning(f"crt.sh HTTP {resp.status_code} (intento {attempt + 1})")
                continue
            if resp.status_code != 200:
                self._report_progress(f"⚠️ crt.sh: respuesta HTTP {resp.status_code}.")
                return []
            try:
                entries = resp.json()
                break
            except ValueError:
                self._report_progress("⚠️ crt.sh: respuesta no válida.")
                return []

        if entries is None:
            self._report_progress("⚠️ crt.sh: no respondió tras varios intentos. Prueba de nuevo en un momento.")
            return []

        subdomains = parse_crtsh(entries, domain)
        results = [
            SearchResult(
                title=sub,
                url=f"https://{sub}",
                snippet=f"Subdominio de {domain} visto en Certificate Transparency",
                source_tool=self.name,
                category="Subdominio",
                relevance_score=70,
                raw_data={"subdomain": sub, "domain": domain},
            )
            for sub in subdomains
        ]

        self._report_progress(f"✅ crt.sh: {len(results)} subdominios encontrados")
        self._cache.set({"domain": domain}, results)
        return results
