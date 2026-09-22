"""
Hunter.io tool v2.
"""
import time, logging
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

    def _get(self, ep: str, params: dict) -> dict:
        params["api_key"] = self.api_key
        try:
            r = requests.get(f"{self.BASE}/{ep}", params=params, timeout=15)
            return r.json() if r.status_code == 200 else {}
        except Exception as e:
            logger.error(f"Hunter error: {e}")
            return {}

    def _domain_search(self, domain: str) -> List[SearchResult]:
        data = self._get("domain-search", {"domain": domain, "limit": 100})
        out = []
        for e in data.get("data", {}).get("emails", []):
            email = e.get("value", "")
            conf  = e.get("confidence", 0)
            out.append(SearchResult(
                title=f"{e.get('first_name','')} {e.get('last_name','')} — {e.get('position','')}",
                url=f"https://hunter.io/verifier/{email}",
                snippet=f"Email: {email}  Confianza: {conf}%",
                source_tool=self.name, category="Email",
                relevance_score=int(conf), raw_data=e))
        return out

    def _find_email(self, name: str, company: str) -> List[SearchResult]:
        parts = name.split()
        data = self._get("email-finder", {
            "first_name": parts[0], "last_name": " ".join(parts[1:]), "company": company
        })
        e = data.get("data", {})
        if not e: return []
        return [SearchResult(
            title=f"Email: {name} @ {company}",
            url=f"https://hunter.io/verifier/{e.get('value','')}",
            snippet=f"Email: {e.get('value','')}  Score: {e.get('score',0)}",
            source_tool=self.name, category="Email",
            relevance_score=int(e.get("score", 0)), raw_data=e)]

    def _verify(self, email: str) -> List[SearchResult]:
        data = self._get("email-verifier", {"email": email})
        e = data.get("data", {})
        if not e: return []
        return [SearchResult(
            title=f"Verificación: {email}",
            url=f"https://hunter.io/verifier/{email}",
            snippet=f"Estado: {e.get('status','')} Resultado: {e.get('result','')} Score: {e.get('score',0)}",
            source_tool=self.name, category="Email Verification",
            relevance_score=int(e.get("score", 0)), raw_data=e)]
