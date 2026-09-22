"""
Wayback Machine Tool — Queries the Internet Archive CDX API
Retrieves historical snapshots and archived endpoints for a given URL or Domain.
"""
import requests
import logging
from typing import List, Dict
import random
import time

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.sanitizer import sanitize_input
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36',
]

REQUIREMENTS = ToolRequirements(
    mandatory=[],
    optional=["url", "domain"],
    produces=["url", "domain"],
    hint="Necesita una URL o un Dominio para buscar en el archivo histórico.",
)

class WaybackMachineTool(OSINTTool):
    def __init__(self):
        super().__init__("Wayback Machine", "Exploras snapshots y endpoints históricos archivados", REQUIREMENTS)
        self._python_pkgs = ["requests"]
        self._install_cmd = "pip install requests"

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        target_domain = sanitize_input(query_params.domain) if query_params.domain else ""
        target_url = sanitize_input(query_params.url) if query_params.url else ""
        
        # Determine best target. Priority to URL, then domain.
        target = ""
        if target_url:
            # If it's a full URL, we strip scheme for the CDX query
            parsed = urlparse(target_url if target_url.startswith('http') else 'http://' + target_url)
            target = parsed.netloc + parsed.path
        elif target_domain:
            target = target_domain
            
        if not target:
            self._report_progress("⚠️ Wayback Machine: No se proporcionó Dominio ni URL.")
            return []

        # We append a wildcard to search the whole domain path
        if not target.endswith("/*"):
            # If it's just a domain like "example.com", we expand it. If it's a specific file, we search just the file.
            if target_domain and target == target_domain:
                target = f"{target}/*"

        self._report_progress(f"🔍 Consultando Wayback Machine CDX API para: {target}...")
        
        # CDX API endpoint
        url = "http://web.archive.org/cdx/search/cdx"
        
        # We limit to 300 to avoid freezing, filter by statuscode 200, and group by original URL so we don't get duplicates of the same page
        params = {
            "url": target,
            "output": "json",
            "collapse": "urlkey", # group identical urls
            "filter": "statuscode:200", # only successful snapshots
            "limit": 300, # Limit the output
            "fl": "original,timestamp,mimetype" # fields we want
        }

        try:
            jitter = random.uniform(1.0, 3.0)
            time.sleep(jitter)
            
            resp = requests.get(
                url, 
                params=params, 
                headers={"User-Agent": random.choice(USER_AGENTS)}, 
                timeout=30
            )
            
            if resp.status_code != 200:
                self._report_progress(f"❌ Error de API: Código {resp.status_code}")
                return []
                
            try:
                data = resp.json()
            except ValueError:
                self._report_progress("⚠️ Wayback Machine API retornó una respuesta inválida (no JSON).")
                return []
                
            if not data or len(data) <= 1:
                self._report_progress("⚠️ Wayback Machine: No se encontraron snapshots válidos.")
                return []
                
            # data[0] are the headers: ["original", "timestamp", "mimetype"]
            headers = data[0]
            rows = data[1:]
            
            results = []
            
            for row in rows:
                if self._is_cancelled:
                    self._report_progress("🛑 Ejecución cancelada por el usuario.")
                    break
                    
                item = dict(zip(headers, row))
                orig_url = item.get("original", "")
                timestamp = item.get("timestamp", "")
                mime = item.get("mimetype", "unknown")
                
                # Format timestamp from YYYYMMDDHHMMSS to somewhat readable
                if len(timestamp) >= 8:
                    year = timestamp[:4]
                    month = timestamp[4:6]
                    day = timestamp[6:8]
                    fmt_date = f"{year}-{month}-{day}"
                else:
                    fmt_date = timestamp
                
                # Create the direct link to the wayback snapshot
                snapshot_url = f"https://web.archive.org/web/{timestamp}/{orig_url}"
                
                # Determine intent/category based on file extension / mimetype
                category = "Endpoint Histórico"
                score = 50
                ext = orig_url.split("?")[0].split(".")[-1].lower()
                
                if ext in ["pdf", "doc", "docx", "xls", "xlsx", "txt", "csv", "sql", "bkp", "bak", "env"]:
                    category = "Archivo Histórico Expuesto"
                    score = 90
                elif "application/json" in mime or ext in ["json"]:
                    category = "API Endpoint"
                    score = 75
                elif "text/html" in mime:
                    category = "Página Web Archivada"
                    score = 40
                
                results.append(SearchResult(
                    title=f"📅 {fmt_date} | {orig_url[:60]}...",
                    url=snapshot_url,
                    snippet=f"Tipo: {mime} | Captura del {fmt_date}",
                    source_tool=self.name,
                    category=category,
                    relevance_score=score,
                    raw_data=item
                ))
                
            # Sort by score descending (sensitive files first), then by date
            sorted_results = sorted(results, key=lambda x: x.relevance_score, reverse=True)
            self._report_progress(f"✅ Wayback completado — {len(sorted_results)} registros únicos descubiertos.")
            return sorted_results
            
        except requests.exceptions.Timeout:
            self._report_progress("❌ Error: Timeout de 30s al consultar la base de datos masiva de Wayback.")
            return []
        except requests.exceptions.RequestException as e:
            self._report_progress(f"❌ Error de red: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Wayback Machine runtime error: {e}")
            return []
