"""
Tech Detect — Identifica tecnologías/vendors de un objetivo web.

A partir del dominio hace UNA petición HTTP y deduce las tecnologías por sus
huellas (cabeceras, cookies, meta-generator, marcadores en el HTML): servidor
web, CMS, WAF, CDN y productos de seguridad. Los nombres se alinean con los
vendors del CTI para poder cruzar "el objetivo usa X" → CVEs activos de X.

detect_technologies() es una función pura (sin red) y por eso testeable.
"""
import logging
import random
import re
from typing import Dict, List, Optional

import requests

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import sanitize_input, validate_domain

logger = logging.getLogger(__name__)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36',
]

MAX_HTML = 200_000
REQUEST_TIMEOUT = 12

# Reglas de huella: (ubicación, texto_a_buscar, tecnología).
# ubicación ∈ {server, x-powered-by, via, cookie, meta-generator, header-any, html}
SIGNATURES = [
    # ── Servidores web ──
    ("server", "nginx", "nginx"),
    ("server", "apache", "Apache"),
    ("server", "microsoft-iis", "Microsoft IIS"),
    ("server", "litespeed", "LiteSpeed"),
    ("server", "openresty", "OpenResty"),
    ("via", "varnish", "Varnish"),
    # ── Lenguajes / frameworks ──
    ("x-powered-by", "asp.net", "Microsoft ASP.NET"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "express", "Express"),
    ("header-any", "x-aspnet-version", "Microsoft ASP.NET"),
    # ── CDN / WAF / seguridad (vendors del CTI) ──
    ("server", "cloudflare", "Cloudflare"),
    ("header-any", "cf-ray", "Cloudflare"),
    ("server", "akamaighost", "Akamai"),
    ("header-any", "x-akamai", "Akamai"),
    ("cookie", "bigipserver", "F5 BIG-IP"),
    ("header-any", "bigip", "F5 BIG-IP"),
    ("cookie", "incap_ses", "Imperva"),
    ("cookie", "visid_incap", "Imperva"),
    ("header-any", "incapsula", "Imperva"),
    ("header-any", "x-sucuri", "Sucuri"),
    ("cookie", "sucuri", "Sucuri"),
    ("header-any", "fortigate", "Fortinet"),
    ("header-any", "fortiweb", "Fortinet"),
    ("cookie", "fortiwafsid", "Fortinet"),
    ("header-any", "x-amz-cf-id", "Amazon CloudFront"),
    ("header-any", "x-amz", "Amazon Web Services"),
    ("header-any", "x-citrix", "Citrix"),
    ("cookie", "citrix_ns_id", "Citrix"),
    # ── CMS ──
    ("meta-generator", "wordpress", "WordPress"),
    ("html", "wp-content", "WordPress"),
    ("html", "wp-includes", "WordPress"),
    ("meta-generator", "drupal", "Drupal"),
    ("header-any", "x-drupal", "Drupal"),
    ("meta-generator", "joomla", "Joomla"),
    ("meta-generator", "shopify", "Shopify"),
    ("header-any", "x-shopify", "Shopify"),
    ("meta-generator", "wix", "Wix"),
    ("meta-generator", "hubspot", "HubSpot"),
    ("meta-generator", "typo3", "TYPO3"),
    # ── Colaboración / correo (vendors del CTI) ──
    ("header-any", "x-owa-version", "Microsoft Exchange"),
    ("header-any", "atlassian", "Atlassian"),
    ("header-any", "x-jira", "Atlassian Jira"),
]

REQUIREMENTS = ToolRequirements(
    mandatory=["domain"],
    optional=["url"],
    produces=["company"],
    hint="Necesita un dominio para identificar sus tecnologías (servidor, CMS, WAF…).",
)


def _meta_generator(html: str) -> str:
    m = re.search(
        r'<meta[^>]+name=[\'"]generator[\'"][^>]+content=[\'"]([^\'"]+)',
        html or "", re.I,
    )
    return m.group(1) if m else ""


def detect_technologies(headers: Dict[str, str], html: str = "",
                        meta_generator: Optional[str] = None) -> List[str]:
    """Devuelve las tecnologías detectadas (sin duplicados, orden de aparición).

    Función pura: recibe cabeceras y HTML ya obtenidos, no hace peticiones.
    """
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    server = h.get("server", "").lower()
    xpb = h.get("x-powered-by", "").lower()
    via = h.get("via", "").lower()
    cookie = h.get("set-cookie", "").lower()
    header_blob = " ".join(f"{k} {v}" for k, v in h.items()).lower()
    meta = (meta_generator if meta_generator is not None else _meta_generator(html)).lower()
    body = (html or "").lower()

    buckets = {
        "server": server, "x-powered-by": xpb, "via": via,
        "cookie": cookie, "meta-generator": meta,
        "header-any": header_blob, "html": body,
    }

    found: List[str] = []
    for location, needle, tech in SIGNATURES:
        if needle in buckets.get(location, "") and tech not in found:
            found.append(tech)
    return found


class TechDetectTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Tech Detect",
            "Identifica tecnologías/vendors de un sitio (servidor, CMS, WAF, CDN)",
            REQUIREMENTS,
        )
        self._python_pkgs = ["requests"]
        self._install_cmd = "pip install requests"

    def check_available(self) -> bool:
        return True

    def _fetch(self, target: str):
        """Devuelve (headers, html) o (None, None). Prueba https y luego http."""
        for scheme in ("https://", "http://"):
            try:
                resp = requests.get(
                    scheme + target,
                    headers={"User-Agent": random.choice(USER_AGENTS)},
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                return dict(resp.headers), (resp.text or "")[:MAX_HTML]
            except requests.RequestException:
                continue
        return None, None

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = sanitize_input(query_params.domain) if query_params.domain else ""
        url = sanitize_input(query_params.url) if query_params.url else ""
        target = (url or domain).strip().lower()
        target = re.sub(r"^https?://", "", target).rstrip("/")
        if not target or not validate_domain(target.split("/")[0]):
            logger.warning("TechDetectTool: dominio/URL inválido")
            return []

        self._report_progress(f"🔎 Tech Detect: analizando {target}…")
        headers, html = self._fetch(target)
        if headers is None:
            self._report_progress("⚠️ Tech Detect: el sitio no respondió.")
            return []

        techs = detect_technologies(headers, html)
        if not techs:
            self._report_progress("Tech Detect: no se identificaron tecnologías conocidas.")
            return []

        self._report_progress(f"✅ Tech Detect: {len(techs)} tecnologías — {', '.join(techs)}")
        return [
            SearchResult(
                title=tech,
                url=f"https://{target.split('/')[0]}",
                snippet=f"Tecnología detectada en {target}",
                source_tool=self.name,
                category="Technology",
                relevance_score=70,
                raw_data={"technology": tech, "domain": target.split("/")[0]},
            )
            for tech in techs
        ]
