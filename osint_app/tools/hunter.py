"""
Hunter.io tool v2.
"""
import logging
from typing import List
import requests

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool

logger = logging.getLogger(__name__)

REQUIREMENTS = ToolRequirements(
    mandatory=["domain"],
    optional=["target_name", "company", "email"],
    produces=["email", "name", "company"],
    hint="Necesita el dominio corporativo. Corre TheHarvester o GoogleDorks primero para obtenerlo.",
)


class HunterTool(OSINTTool):
    BASE = "https://api.hunter.io/v2"

    def __init__(self):
        super().__init__("Hunter.io", "Email discovery y verificación vía API", REQUIREMENTS)
        self.requires_api_key = True

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        if not self.api_key:
            logger.warning("Hunter.io: no API key")
            return []
        results = []
        if query_params.domain:
            results += self._domain_search(query_params.domain)
        if query_params.target_name and query_params.company:
            results += self._find_email(query_params.target_name, query_params.company)
        if query_params.email:
            results += self._verify(query_params.email)
        return results

    # Motivos legibles cuando Hunter rechaza la consulta (antes se devolvía {} sin decir nada)
    _HTTP_REASONS = {
        401: "la clave de API no es válida", 403: "la clave no tiene permiso", 429: "se agotó el límite de consultas",
        400: "Hunter no entendió la consulta", 404: "no encontró nada",
    }

    def _get(self, ep: str, params: dict) -> dict:
        # La clave va en una cabecera, NO en la URL: una URL con la clave acaba en registros y mensajes de error
        try:
            r = requests.get(f"{self.BASE}/{ep}", params=params, headers={"X-API-KEY": self.api_key}, timeout=15)
        except Exception as e:
            logger.error(f"Hunter error de red: {type(e).__name__}")       # solo el tipo: el texto del error puede incluir la URL
            self._report_progress(f"❌ Hunter.io: error de red ({type(e).__name__}).")
            return {}
        if r.status_code != 200:
            reason = self._HTTP_REASONS.get(r.status_code, "respondió con un error")
            self._report_progress(f"⚠️ Hunter.io: {reason} (HTTP {r.status_code}).")
            return {}
        try:
            return r.json()
        except ValueError:
            self._report_progress("⚠️ Hunter.io: respuesta que no es JSON.")
            return {}

    def _domain_search(self, domain: str) -> List[SearchResult]:
        data = self._get("domain-search", {"domain": domain, "limit": 100})
        out = []
        for e in ((data.get("data") or {}).get("emails") or []):
            email = e.get("value", "")
            conf  = e.get("confidence") or 0
            out.append(SearchResult(
                title=f"{e.get('first_name','')} {e.get('last_name','')} — {e.get('position','')}",
                url=f"https://hunter.io/verifier/{email}",
                snippet=f"Email: {email}  Confianza: {conf}%",
                source_tool=self.name, category="Email",
                relevance_score=int(conf), raw_data=e))
        return out

    def _find_email(self, name: str, company: str) -> List[SearchResult]:
        parts = name.split()
        if not parts:
            return []
        # Nombres hispanos de 4 palabras (N1 N2 A1 A2): el apellido es la 3.ª, no "Carlos Pérez Mora" entero
        last = parts[2] if len(parts) >= 4 else " ".join(parts[1:])
        data = self._get("email-finder", {"first_name": parts[0], "last_name": last, "company": company})
        e = data.get("data") or {}
        if not e: return []
        return [SearchResult(
            title=f"Email: {name} @ {company}",
            url=f"https://hunter.io/verifier/{e.get('value','')}",
            snippet=f"Email: {e.get('value','')}  Score: {e.get('score',0)}",
            source_tool=self.name, category="Email",
            relevance_score=int(e.get("score") or 0), raw_data=e)]

    def _verify(self, email: str) -> List[SearchResult]:
        data = self._get("email-verifier", {"email": email})
        e = data.get("data") or {}
        if not e: return []
        return [SearchResult(
            title=f"Verificación: {email}",
            url=f"https://hunter.io/verifier/{email}",
            snippet=f"Estado: {e.get('status','')} Resultado: {e.get('result','')} Score: {e.get('score',0)}",
            source_tool=self.name, category="Email Verification",
            relevance_score=int(e.get("score") or 0), raw_data=e)]
