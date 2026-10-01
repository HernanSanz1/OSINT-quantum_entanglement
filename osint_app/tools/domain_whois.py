"""
Domain WHOIS Tool — Registro de un dominio vía RDAP (el sucesor moderno de WHOIS).

Consulta https://rdap.org, que redirige al registro oficial de cada TLD
(Verisign para .com, NIC.ec para .ec, PIR para .org, …). No necesita clave ni
binarios. Devuelve registrador, fechas (alta, vencimiento, cambio), estado,
servidores de nombres, DNSSEC y contactos NO censurados.

Tras el RGPD/LOPDP la mayoría de contactos personales vienen censurados
("REDACTED FOR PRIVACY"); esos campos se descartan, no se intentan eludir.
"""
import logging
import random
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import sanitize_input, sanitize_snippet, validate_domain
from ..utils.rate_limiter import RateLimiter
from ..utils.cache import CacheManager

logger = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/domain/{domain}"
REQUEST_TIMEOUT = 25
MAX_RETRIES = 2
RETRY_STATUS = {429, 502, 503, 504}
NOT_A_DOMAIN = {400, 404}       # subdominio (400) o dominio inexistente (404): probar el padre
NO_RDAP = "no-rdap"             # la extensión (p. ej. .edu) no ofrece servicio RDAP
RECENT_DAYS = 30        # dominio "recién registrado" (señal típica de phishing)
EXPIRY_DAYS = 30        # vence pronto (riesgo de secuestro / caída de servicio)
CONTACT_ROLES = ("registrant", "administrative", "technical")

USER_AGENT = "Mozilla/5.0 (compatible; SENTINEL-OSINT/2.0)"

REQUIREMENTS = ToolRequirements(
    mandatory=["domain"],
    optional=[],
    produces=["domain", "company", "email"],
    hint="Necesita un dominio (ej: empresa.com) para consultar su registro WHOIS/RDAP.",
)


def _parse_date(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_redacted(text: str) -> bool:
    return "REDACTED" in (text or "").upper()


def _vcard_fields(entity: dict) -> Dict[str, str]:
    """Extrae nombre / organización / email de un vCard RDAP, omitiendo lo censurado."""
    out: Dict[str, str] = {}
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list)):
        return out
    wanted = {"fn": "name", "org": "org", "email": "email"}
    for item in vcard[1]:
        if not (isinstance(item, list) and len(item) >= 4):
            continue
        key = wanted.get(item[0])
        if not key:
            continue
        value = item[3]
        if isinstance(value, list):
            value = " ".join(str(v) for v in value if v)
        value = str(value or "").strip()
        if value and not _is_redacted(value):
            out[key] = value
    return out


def parse_rdap(data: dict, now: Optional[datetime] = None) -> dict:
    """Convierte la respuesta JSON de RDAP en un resumen plano.

    Función pura (sin red) para poder probarla. `now` se inyecta en las pruebas.
    """
    now = now or datetime.now(timezone.utc)
    if not isinstance(data, dict):
        return {}

    events = {}
    for ev in data.get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") and ev.get("eventDate"):
            events.setdefault(str(ev["eventAction"]).lower(), ev["eventDate"])
    registered = _parse_date(events.get("registration"))
    expires = _parse_date(events.get("expiration"))
    changed = _parse_date(events.get("last changed"))

    registrar = ""
    contacts: List[dict] = []
    for ent in data.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        fields = _vcard_fields(ent)
        if "registrar" in roles:
            registrar = fields.get("name", "") or fields.get("org", "")
        for role in CONTACT_ROLES:
            if role in roles and fields:
                contacts.append({"role": role, **fields})

    nameservers = sorted({
        str(ns.get("ldhName", "")).lower().rstrip(".")
        for ns in (data.get("nameservers") or [])
        if isinstance(ns, dict) and ns.get("ldhName")
    })

    secure = data.get("secureDNS") or {}
    return {
        "domain": str(data.get("ldhName") or "").lower(),
        "registrar": registrar,
        "registered": registered.date().isoformat() if registered else "",
        "expires": expires.date().isoformat() if expires else "",
        "last_changed": changed.date().isoformat() if changed else "",
        "age_days": (now - registered).days if registered else None,
        "days_to_expiry": (expires - now).days if expires else None,
        "status": [str(s) for s in (data.get("status") or [])],
        "nameservers": nameservers,
        "dnssec": bool(secure.get("delegationSigned")) if secure else False,
        "contacts": contacts,
    }


def is_empty_record(info: dict) -> bool:
    """Algunos registros responden 200 con un cascarón sin datos para nombres no registrables."""
    return not any(info.get(k) for k in ("registered", "expires", "registrar", "nameservers", "contacts"))


def build_alerts(info: dict) -> List[str]:
    """Señales de riesgo derivadas de las fechas del dominio."""
    alerts = []
    age = info.get("age_days")
    if age is not None and 0 <= age < RECENT_DAYS:
        alerts.append(f"Dominio registrado hace solo {age} días (típico de phishing o campañas nuevas)")
    left = info.get("days_to_expiry")
    if left is not None:
        if left < 0:
            alerts.append(f"Dominio VENCIDO hace {-left} días")
        elif left < EXPIRY_DAYS:
            alerts.append(f"Dominio vence en {left} días")
    return alerts


def candidate_domains(domain: str) -> List[str]:
    """Dominio dado y sus padres (sin llegar al TLD solo): a.b.empresa.com → [.., empresa.com]."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


class DomainWhoisTool(OSINTTool):
    def __init__(self):
        super().__init__(
            "Domain WHOIS",
            "Registro de un dominio vía RDAP: registrador, fechas, servidores de nombres, DNSSEC (sin clave)",
            REQUIREMENTS,
        )
        self._python_pkgs = ["requests"]
        self._install_cmd = "pip install requests"
        self._rate = RateLimiter(max_requests=10, time_window=60)
        self._cache = CacheManager(max_size=100, ttl=3600)

    def check_available(self) -> bool:
        return True

    def _fetch(self, domain: str):
        """Devuelve (json | None, http_status). 404 → (None, 404); fallo de red → (None, 0)."""
        status = 0
        for attempt in range(MAX_RETRIES):
            if attempt:
                time.sleep(random.uniform(1.5, 3.0))
            try:
                resp = requests.get(
                    RDAP_URL.format(domain=domain),
                    headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException as e:
                logger.warning(f"RDAP error de red (intento {attempt + 1}): {type(e).__name__}")
                continue
            status = resp.status_code
            if status in RETRY_STATUS:
                logger.warning(f"RDAP HTTP {status} (intento {attempt + 1})")
                continue
            if status == 404 and str(getattr(resp, "url", "")).startswith("https://rdap.org/"):
                return None, NO_RDAP         # rdap.org no redirigió: la extensión no publica RDAP
            if status != 200:
                return None, status
            try:
                return resp.json(), 200
            except ValueError:
                return None, 200
        return None, status

    def lookup(self, domain: str):
        """Registro RDAP de un dominio ya validado. Devuelve (info | None, dominio_resuelto, estado).

        Si el nombre no es registrable sube al dominio padre. estado == NO_RDAP si la extensión
        no publica RDAP. Lo usan también otras herramientas (p. ej. Link Shield, para la antigüedad).
        """
        status = 0
        for candidate in candidate_domains(domain):
            self._rate.wait_if_needed()
            data, status = self._fetch(candidate)
            if data is not None:
                parsed = parse_rdap(data)
                if not is_empty_record(parsed):
                    return parsed, candidate, 200
                continue                     # cascarón sin datos (p. ej. .ec): probar el padre
            if status == NO_RDAP:
                return None, domain, NO_RDAP
            if status not in NOT_A_DOMAIN:   # error real (red/servidor): no seguir subiendo de nivel
                break
        return None, domain, status

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        domain = sanitize_input(query_params.domain) if query_params.domain else ""
        domain = domain.strip().lower().lstrip(".")
        if not domain or not validate_domain(domain):
            logger.warning("DomainWhoisTool: dominio inválido o ausente")
            return []

        cached = self._cache.get({"domain": domain})
        if cached is not None:
            self._report_progress(f"📦 Domain WHOIS: usando caché de {domain}")
            return cached

        self._report_progress(f"🔍 Domain WHOIS: consultando el registro RDAP de {domain}…")
        info, resolved, status = self.lookup(domain)
        if status == NO_RDAP:
            tld = domain.rsplit(".", 1)[-1]
            self._report_progress(f"⚠️ Domain WHOIS: la extensión .{tld} no publica datos RDAP (no hay registro consultable).")
            return []
        if info is None:
            self._report_progress("⚠️ Domain WHOIS: no se pudo obtener el registro (no existe o el servicio no responde).")
            return []

        if not info.get("domain"):
            info["domain"] = resolved
        if resolved != domain:
            info["queried"] = domain         # el registro pertenece al dominio padre, no al consultado
        alerts = build_alerts(info)

        parts = [f"Registrador: {info['registrar'] or 'n/d'}"]
        if resolved != domain:
            parts.insert(0, f"(consultado {domain}: el registro es del dominio padre)")
        if info["registered"]:
            parts.append(f"Alta: {info['registered']}")
        if info["expires"]:
            parts.append(f"Vence: {info['expires']}")
        if info["nameservers"]:
            parts.append(f"NS: {', '.join(info['nameservers'][:4])}")
        parts.append("DNSSEC: " + ("sí" if info["dnssec"] else "no"))

        results = [SearchResult(
            title=f"WHOIS: {info['domain']}",
            url=f"https://rdap.org/domain/{info['domain']}",
            snippet=sanitize_snippet(" · ".join(parts)),
            source_tool=self.name,
            category="Network",
            relevance_score=80,
            raw_data=info,
        )]
        for alert in alerts:
            results.append(SearchResult(
                title=f"⚠️ {info['domain']}: {alert}",
                url=f"https://rdap.org/domain/{info['domain']}",
                snippet=sanitize_snippet(alert),
                source_tool=self.name,
                category="Alerta",
                relevance_score=85,
                raw_data={"domain": info["domain"], "alert": alert},
            ))
        for contact in info["contacts"]:
            label = contact.get("org") or contact.get("name") or contact.get("email", "")
            results.append(SearchResult(
                title=f"Contacto {contact['role']} de {info['domain']}: {label}",
                url="",
                snippet=sanitize_snippet(" · ".join(
                    f"{k}: {v}" for k, v in contact.items() if k != "role")),
                source_tool=self.name,
                category="Contacto",
                relevance_score=65,
                raw_data=contact,
            ))

        self._report_progress(f"✅ Domain WHOIS: {info['domain']} — {len(results)} resultado(s)")
        self._cache.set({"domain": domain}, results)
        return results
