"""
Google Dorks tool v2 — DuckDuckGo search with ToolRequirements and caching.
"""
import random, logging
from typing import List, Dict
import requests

from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool
from ..utils.person_match import name_match
from ..utils.rate_limiter import RateLimiter
from ..utils.cache import CacheManager
from ..utils.sanitizer import sanitize_input

logger = logging.getLogger(__name__)

REQUIREMENTS = ToolRequirements(
    mandatory=[],
    optional=["target_name", "email", "domain", "username", "company", "phone", "ip", "url"],
    produces=["email", "url", "domain", "username"],
    hint="Necesita al menos uno (Nombre, Email, Dominio, Username, URL, etc).",
)

DORK_TEMPLATES = [
    '{target_name}',
    '{target_name} (facebook OR twitter OR linkedin OR instagram OR github)',
    '{target_name} (filetype:pdf OR filetype:doc OR filetype:docx)',
    '{target_name} (filetype:xls OR filetype:xlsx OR filetype:csv)',
    '{email}',
    '{email} (forum OR comment OR discussion OR post)',
    '{email} (password OR secret OR token OR credential)',
    '{username} site:github.com',
    '{username} site:linkedin.com',
    '{target_name} site:{domain}',
    '{email} site:{domain}',
    '{target_name} "{company}"',
    '{target_name} (phone OR address OR contact OR location)',
    '{target_name} (linkedin OR "curriculum vitae" OR resume OR CV)',
    '{target_name} (university OR education OR degree OR thesis)',
    '{target_name} (article OR publication OR paper OR blog OR author)',
    '{target_name} (court OR legal OR lawsuit OR attorney)',
    '{target_name} (patent OR invention OR trademark OR copyright)',
    '{target_name} (investment OR stock OR portfolio)',
    '{target_name} (veteran OR military OR service)',
    '{email} (subscription OR membership OR account)',
    '{username} (git OR github OR bitbucket OR svn)',
    '{domain} -site:{domain} intext:{target_name}',
    '{target_name} (business OR company OR corporation)',
    '{target_name} (photo OR image OR picture OR avatar)',
]

CATEGORY_MAP = {
    "Document": ["filetype:pdf", "filetype:doc", "filetype:xls"],
    "Social Media": ["facebook", "twitter", "instagram", "linkedin"],
    "Code": ["github", "bitbucket", "git"],
    "Credentials": ["password", "secret", "credential", "token"],
    "Professional": ["linkedin", "resume", "cv", "curriculum"],
    "Legal": ["court", "legal", "lawsuit"],
    "Financial": ["investment", "stock", "portfolio"],
}

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36',
]

# Agregadores "people-search" que generan ruido (perfiles automáticos sin valor).
# Se excluyen de las búsquedas de contexto de identidad.
PEOPLE_SEARCH_NOISE = [
    "spokeo.com", "whitepages.com", "beenverified.com", "radaris.com",
]

# Plataformas donde suele reutilizarse el mismo username.
USERNAME_REUSE_SITES = [
    "instagram.com", "tiktok.com", "reddit.com", "t.me",
    "pinterest.com", "twitter.com",
]

# Registros públicos de Ecuador (debida diligencia / verificación de identidad).
EC_REGISTRY_SITES = ["sri.gob.ec", "supercias.gob.ec", "funcionjudicial.gob.ec"]


class GoogleDorksTool(OSINTTool):
    def __init__(self):
        super().__init__("Google Dorks", "Búsqueda avanzada con operadores (varios buscadores con respaldo)", REQUIREMENTS)
        self._rate = RateLimiter(max_requests=8, time_window=60)
        self._cache = CacheManager(max_size=100, ttl=1800)
        self._python_pkgs = ["requests", "bs4"]
        self._install_cmd = "pip install requests beautifulsoup4"

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        import concurrent.futures
        
        cached = self._cache.get(query_params.to_dict())
        if cached:
            self._report_progress(f"📦 Usando caché — {len(cached)} resultados previos")
            return cached

        queries_objs = self._build_queries(query_params)
        total = len(queries_objs)
        if total == 0:
            self._report_progress("⚠️ Google Dorks: No se pudieron generar consultas. Revisa que el caso tenga Nombre, Email o Dominio.")
            return []
            
        self._report_progress(f"🔍 Google Dorks: {total} consultas a enviar a los buscadores…")

        raw_hits = []
        for i, q_obj in enumerate(queries_objs, 1):
            if self._is_cancelled:
                self._report_progress("🛑 Ejecución cancelada por el usuario.")
                break

            q_text = q_obj["query"]
            self._report_progress(f"[{i}/{total}] ✨ Score {q_obj['score']} | {q_text[:70]}…")
            hits = self._search(q_text, max_results=5)
            outcome = getattr(self, "_last_outcome", None)
            if outcome is not None and outcome.all_blocked:
                # Todos los buscadores bloquean: seguir solo alarga la espera y empeora el bloqueo
                self._report_progress(f"⚠️ Google Dorks: {outcome.explain()}")
                self._report_progress(f"⏹️ Se detienen las {total - i} consultas restantes.")
                break
            
            # Canonicalize URLs to avoid deduplication issues 
            from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
            for h in hits:
                parsed = urlparse(h["url"])
                # Remove common tracking parameters
                qs = parse_qsl(parsed.query)
                clean_qs = [(k, v) for k, v in qs if not k.startswith(('utm_', 'fbclid', 'gclid'))]
                
                # Reconstruct and normalize trailing slash
                raw_path = parsed.path if parsed.path else "/"
                # Solo el subdominio móvil inicial ("m.facebook.com"); antes se borraba "m." en cualquier parte
                # del dominio y "forum.x.com" quedaba como "forux.com" (URL rota)
                netloc = parsed.netloc[2:] if parsed.netloc.lower().startswith("m.") else parsed.netloc
                clean_url = urlunparse((
                    parsed.scheme,
                    netloc,
                    raw_path,
                    parsed.params,
                    urlencode(clean_qs),
                    parsed.fragment
                ))
                h["url"] = clean_url
                h["intent"] = q_obj["intent"] # passthrough intent for category
                raw_hits.append(h)
                
            if hits:
                self._report_progress(f"  ↳ {len(hits)} hits obtenidos")
            else:
                self._report_progress(f"  ↳ sin resultados")

        if self._is_cancelled:
            return []

        # Deduplicate URLs
        unique_urls = set()
        deduped = []
        for h in raw_hits:
            if h["url"] not in unique_urls:
                unique_urls.add(h["url"])
                deduped.append(h)

        # STRICT HTML VERIFICATION & Confidence Scoring A/B/C
        self._report_progress(f"🛡️ Verificación Estricta (Anti-Falsos Positivos) de {len(deduped)} enlaces únicos...")
        
        # Helper to strip accents for robust matching
        import unicodedata
        def strip_accents(s):
            return ''.join(c for c in unicodedata.normalize('NFD', s) if unicodedata.category(c) != 'Mn')

        # Level A constraints (Strong Identity)
        level_a_checks = []
        if query_params.email: level_a_checks.append(query_params.email.lower())
        if query_params.username and " " not in query_params.username: 
            level_a_checks.append(query_params.username.lower())
        if query_params.phone: 
            cl_ph = ''.join(filter(str.isdigit, query_params.phone))
            if len(cl_ph) > 5: level_a_checks.append(cl_ph)
            
        # Level B constraints (Name + Context)
        level_b_checks = []
        full_name = ""
        if query_params.target_name:
            full_name = strip_accents(query_params.target_name.lower())
            level_b_checks.append(full_name)

        # Contexto que corrobora la identidad: dominio, empresa, universidad, ciudad y palabras del contexto del caso
        context_keywords = [strip_accents(c.lower()) for c in
                            [query_params.domain, query_params.company, query_params.university, query_params.location] if c]
        context_keywords += [strip_accents(w.lower()) for w in (query_params.context or "").split() if len(w) > 3]
        
        valid_hits = []
        if not level_a_checks and not level_b_checks:
            # Domain/IP only searches skip deep verification for identity
            for hit in deduped:
                hit["confidence"] = "POSIBLE"
                valid_hits.append(hit)
        else:
            def verify_url(hit):
                if self._is_cancelled: return None
                url = hit["url"]
                text_to_check = ""
                
                # Check directly on PDFs/DOCs to avoid loading to RAM
                if any(url.lower().endswith(ext) for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.zip']):
                    text_to_check = (hit.get("snippet", "") + " " + hit.get("title", "")).lower()
                else:
                    try:
                        r = requests.get(url, timeout=3.5, headers={"User-Agent": random.choice(USER_AGENTS)})
                        if r.status_code == 200:
                            text_to_check = strip_accents(r.text.lower())
                    except Exception:
                        # Fallback to snippet on block
                        text_to_check = (hit.get("snippet", "") + " " + hit.get("title", "")).lower()
                
                if not text_to_check: return None

                # Calculate confidence
                if any(a in text_to_check for a in level_a_checks):
                    hit["confidence"] = "CONFIRMADO (A)"
                    return hit

                # Nombre por palabras completas y sin tildes (person_match). Antes bastaba con UNA palabra del
                # nombre ("pérez") para dar el resultado como posible: en pruebas reales 4 de 5 eran otras personas.
                points, _ = name_match(query_params.target_name or "", text_to_check)
                hit["name_points"] = points
                if points >= 40 and context_keywords and any(c in text_to_check for c in context_keywords):
                    hit["confidence"] = "PROBABLE (B)"
                    return hit

                if points >= 25:
                    hit["confidence"] = "POSIBLE (C)"
                    return hit

                return None
                
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                results = executor.map(verify_url, deduped)
                for res in results:
                    if res:
                        valid_hits.append(res)
                        
        valid_hits_sorted = sorted(valid_hits, key=lambda x: self._score(query_params, x), reverse=True)
        
        results = []
        for h in valid_hits_sorted:
            # Prefix Category with Confidence level!
            conf = h.get("confidence", "POSIBLE")
            cat = h.get("intent", self._categorize(h["url"] + " " + h["title"]))
            merged_cat = f"[{conf}] {cat}"
            
            results.append(SearchResult(
                title=h["title"], url=h["url"], snippet=h["snippet"],
                source_tool=self.name,
                category=merged_cat,
                relevance_score=self._score(query_params, h),
                raw_data=h,
            ))

        self._report_progress(f"✅ Dorks completo — {len(results)} resultados legítimos verificados")
        self._cache.set(query_params.to_dict(), results)
        return results


    def _build_queries(self, p: QueryParameters) -> List[Dict]:
        """
        Normalizes inputs, generates permutations, applies adaptive anchoring,
        scores queries based on context, and returns a capped list of the best ones.
        """
        # ── 1. Nomalization ──
        t_name = sanitize_input(p.target_name) if p.target_name else ""
        email = sanitize_input(p.email).lower() if p.email else "" # Brutal normalization
        username = sanitize_input(p.username).lower() if p.username else ""
        domain = sanitize_input(p.domain).lower() if p.domain else ""
        company = f'"{sanitize_input(p.company)}"' if p.company else ""
        phone = sanitize_input(p.phone) if p.phone else ""
        university = f'"{sanitize_input(p.university)}"' if hasattr(p, 'university') and p.university else ""
        ip = sanitize_input(p.ip) if p.ip else ""
        
        # Parse URL to complement domain and exact searches
        raw_url = sanitize_input(p.url) if p.url else ""
        from urllib.parse import urlparse
        if raw_url:
            if not raw_url.startswith(("http://", "https://")):
                raw_url = "http://" + raw_url
            parsed_url = urlparse(raw_url)
            # Use the hostname as a fallback domain if no domain was provided
            if parsed_url.hostname and not domain:
                domain = parsed_url.hostname

        # Name Permutations (Only keeping sanity-checked ones)
        name_perms = []
        if t_name:
            parts = [pt for pt in t_name.split() if len(pt) > 1 and pt.lower() not in ("test", "user")]
            if len(parts) >= 2:
                name_perms.append(f'"{t_name}"') # Full Name
            # Convención hispana: N1 N2 A1 A2. Nunca "solo apellidos" ("Pérez Quezada" atrae a todos los homónimos)
            if len(parts) == 4:
                name_perms.extend([f'"{parts[0]} {parts[2]}"', f'"{parts[1]} {parts[2]}"', f'"{parts[0]} {parts[1]} {parts[2]}"'])
            elif len(parts) == 3:
                name_perms.extend([f'"{parts[0]} {parts[1]}"', f'"{parts[0]} {parts[2]}"'])
        name_perms = list(dict.fromkeys(n for n in name_perms if n))      # sin repetir y en orden (antes set: orden al azar)

        # Phone Permutations
        phone_perms = []
        if phone:
            clean_phone = ''.join(filter(str.isdigit, phone))
            if clean_phone:
                phone_perms.append(f'"{clean_phone}"')
                phone_perms.append(f'"+{clean_phone}"')
                if len(clean_phone) > 8:
                    phone_perms.append(f'"{clean_phone[-8:]}"') # Cut country code
        phone_perms = list(set(phone_perms))

        queries_dict = {}

        def _add_q(q: str, score: int, category: str):
            q_clean = q.strip().replace("  ", " ")
            if not q_clean: return
            if q_clean not in queries_dict or score > queries_dict[q_clean]["score"]:
                queries_dict[q_clean] = {"query": q_clean, "score": score, "intent": category}

        # ── 2. Adaptive Anchoring ──
        # Strong pivots are identity anchors that don't destroy infra results (mostly).
        # Weak pivots (Names) should ONLY anchor Docs and Social.
        strong_anchors = []
        if email: strong_anchors.append(f'"{email}"')
        if username: strong_anchors.append(f'"{username}"')
        
        # Primary anchor for infra (only use strong ones). If none, empty.
        infra_anchor = strong_anchors[0] + " " if strong_anchors else ""
        
        # General anchor for docs/social (can use names if no strong anchor exists)
        general_anchor = infra_anchor
        if not general_anchor and name_perms:
            general_anchor = name_perms[0] + " "

        # ── 3. Query Generation (by Intent) ──

        # --- INFRASTRUCTURE & REPOSITORIES (Uses infra_anchor) ---
        if raw_url:
            # Si pasaron una URL completa, buscamos copias cacheadas, referencias al archivo/endpoint o la URL literal
            clean_raw_url = raw_url.replace("http://", "").replace("https://", "").strip("/")
            _add_q(f'"{clean_raw_url}"', 15, "URL Match")
            _add_q(f'link:{clean_raw_url}', 12, "URL Backlinks")
            if parsed_url and parsed_url.path and parsed_url.path != "/":
                _add_q(f'{infra_anchor}inurl:"{parsed_url.path}"', 10, "URL Path")

        if domain:
            _add_q(f'{infra_anchor}site:{domain}', 5, "Infra")
            _add_q(f'{infra_anchor}site:*.{domain}', 5, "Infra")
            _add_q(f'{infra_anchor}site:{domain} inurl:admin OR inurl:login OR inurl:cpanel', 6, "Infra")
            _add_q(f'{infra_anchor}site:{domain} intitle:"index of" "parent directory"', 7, "Infra")
            _add_q(f'{infra_anchor}site:{domain} filetype:env OR filetype:log OR filetype:sql OR filetype:dbf', 8, "Infra")
            _add_q(f'{infra_anchor}site:{domain} inurl:".git" OR site:{domain} filetype:pem', 8, "Infra")
            _add_q(f'{infra_anchor}site:{domain} ext:bak OR ext:old', 6, "Infra")
            _add_q(f'{infra_anchor}site:{domain} intext:"fatal error" OR intext:"stack trace"', 7, "Infra")

        # --- IDENTITY & LEAKS (High Score) ---
        if email:
            _add_q(f'"{email}"', 10, "Identity")
            _add_q(f'"{email}" (password OR token OR api_key OR secret)', 12, "Leaks")
            _add_q(f'"{email}" site:pastebin.com OR site:justpaste.it', 10, "Leaks")

        if username:
            _add_q(f'"{username}"', 8, "Identity")
            _add_q(f'"{username}" site:github.com OR site:gitlab.com', 9, "Identity/Code")
            _add_q(f'"{username}" site:pastebin.com OR site:justpaste.it', 10, "Leaks")
            _add_q(f'"{username}" (password OR token OR secret)', 11, "Leaks")
            # Reutilización del mismo username en otras plataformas sociales.
            reuse = " OR ".join(f'site:{s}' for s in USERNAME_REUSE_SITES)
            _add_q(f'({reuse}) "{username}"', 8, "Social/Username")
            # Contexto limpio: excluye agregadores people-search que solo dan ruido.
            noise = " ".join(f'-site:{s}' for s in PEOPLE_SEARCH_NOISE)
            _add_q(f'"{username}" {noise}', 7, "Identity/Clean")

        # --- CONTEXTO LIMPIO DE EMAIL (sin agregadores de datos personales) ---
        if email:
            noise = " ".join(f'-site:{s}' for s in PEOPLE_SEARCH_NOISE)
            _add_q(f'"{email}" (foro OR forum OR comentario OR perfil) {noise}', 9, "Identity/Clean")

        # --- REGISTROS PÚBLICOS DE ECUADOR (identidad / debida diligencia) ---
        ec_registry = "(" + " OR ".join(f'site:{s}' for s in EC_REGISTRY_SITES) + ")"
        if name_perms:
            _add_q(f'{name_perms[0]} {ec_registry}', 6, "Registros EC")
        if company:
            _add_q(f'{company} {ec_registry}', 6, "Registros EC")

        for p_perm in phone_perms:
            _add_q(f'{p_perm}', 9, "Identity")
            _add_q(f'{p_perm} (scam OR spam)', 10, "Identity/Social")
            _add_q(f'{p_perm} filetype:xls OR filetype:csv', 9, "Docs")

        # --- DOCUMENTS & SOCIAL (Uses general_anchor) ---
        if domain:
            _add_q(f'{general_anchor}site:{domain} filetype:pdf OR filetype:xls OR filetype:doc', 7, "Docs")
            
        if company:
            _add_q(f'{general_anchor}{company} (business OR lawsuit OR confidential)', 6, "Docs")
            _add_q(f'{general_anchor}{company} filetype:pdf OR filetype:docx', 6, "Docs")

        if university:
            _add_q(f'{general_anchor}{university} (student OR alumni OR faculty)', 5, "Docs")
            _add_q(f'{general_anchor}{university} filetype:pdf', 5, "Docs")

        for n_perm in name_perms:
            _add_q(f'{n_perm} (linkedin OR resume OR "curriculum vitae")', 8, "Social")
            _add_q(f'{n_perm} site:facebook.com OR site:linkedin.com', 8, "Social")
            if domain: _add_q(f'{n_perm} site:{domain}', 9, "Docs")
            if company: _add_q(f'{n_perm} {company}', 8, "Docs")
            if university: _add_q(f'{n_perm} {university}', 7, "Docs")

        # ── 4. Fallback (Mega-Concat) ──
        # Only added if we have very few queries. And penalized with a negative score so it runs last.
        if len(queries_dict) < 5:
            valid_parts = [p for p in [t_name, email, username, domain, company, phone, ip] if p]
            if len(valid_parts) >= 2 and len(valid_parts) <= 3:
                 _add_q(" ".join(valid_parts), -5, "Fallback")

        # ── 5. Budgeting & Sorting ──
        # Sort queries by score descending
        sorted_queries = sorted(queries_dict.values(), key=lambda x: x["score"], reverse=True)
        
        # Establish budget based on input strength
        budget = 10 # Default for weak inputs
        if email or phone or raw_url: budget = 25
        elif username: budget = 18
        elif domain and t_name: budget = 15

        return sorted_queries[:budget]

    def _search(self, query: str, max_results: int = 10) -> List[Dict]:
        """Consulta la búsqueda multimotor (Brave/Yandex/Yahoo/Bing/DuckDuckGo); el ritmo lo controla esa capa."""
        from ..utils.search_engine import web_search

        self._rate.wait_if_needed()
        self._last_outcome = web_search(query, max_results=max_results)
        return self._last_outcome.hits

    def _categorize(self, q: str) -> str:
        ql = q.lower()
        for cat, kws in CATEGORY_MAP.items():
            if any(k in ql for k in kws):
                return cat
        return "General"

    def _score(self, p: QueryParameters, h: Dict) -> int:
        text = (h.get("title","") + " " + h.get("snippet","") + " " + h.get("url","")).lower()
        score = 0
        # Antes: el nombre completo literal y con tildes; "Jefferson Pérez" no puntuaba para "Jefferson Pérez Quezada"
        if p.target_name:
            score += {40: 20, 25: 12}.get(int(max(h.get("name_points", 0), name_match(p.target_name, text)[0])), 0)
        if p.email and p.email.lower() in text: score += 25
        if p.domain and p.domain.lower() in text: score += 10
        if p.username and p.username.lower() in text: score += 10
        return score
