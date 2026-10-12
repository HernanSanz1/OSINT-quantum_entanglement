"""
Web Search Tool - Búsqueda web para OSINT
Usa DuckDuckGo para evitar captchas de Google.
"""
import json
import re
import time
import logging
import os
import ssl
import urllib.parse
import urllib.request
from typing import List, Dict, Any
from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool

logger = logging.getLogger(__name__)

# SSL context — verifies certificates. Behind a corporate proxy that
# intercepts TLS, set OSINT_INSECURE_SSL=1 to disable verification.
SSL_CONTEXT = ssl.create_default_context()
if os.environ.get("OSINT_INSECURE_SSL") == "1":
    SSL_CONTEXT.check_hostname = False
    SSL_CONTEXT.verify_mode = ssl.CERT_NONE


_DDG_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36",
]


def _ddg_unwrap(href: str) -> str:
    """Deshace la redirección de DuckDuckGo (//duckduckgo.com/l/?uddg=...)."""
    from ..utils.search_engine import ddg_unwrap
    return ddg_unwrap(href)


def duckduckgo_search(query: str, max_results: int = 10) -> List[Dict[str, str]]:
    """Solo DuckDuckGo (html y respaldo lite) → [{title, url, snippet}]; [] si no hay resultados o hay captcha.

    Las herramientas usan `utils.search_engine.web_search`, que prueba varios buscadores y explica los bloqueos.
    """
    from ..utils.search_engine import EngineBlocked, _search_duckduckgo
    try:
        return _search_duckduckgo(query, max_results)
    except EngineBlocked as e:
        logger.warning(f"DuckDuckGo: {e}")
        return []


def github_unavailable_hint(status: int) -> str:
    """Texto claro cuando GitHub no pudo consultarse (no confundir con 'el usuario no existe')."""
    if status in (403, 429):
        return ("GitHub limitó las consultas (HTTP %s): sin token son solo 60 por hora. "
                "Esto NO significa que el usuario no exista. Añade un token de GitHub o reintenta más tarde." % status)
    return f"No se pudo contactar con GitHub (código {status or 'sin conexión'}). Esto NO significa que el usuario no exista."


def github_headers(token: str = None) -> Dict[str, str]:
    """Cabeceras para la API de GitHub.

    Si hay un token en el baúl (clave "GitHub") o en la variable de entorno
    GITHUB_TOKEN, se autentica y el límite sube de 60 a 5.000 peticiones/hora.
    Sin token funciona igual, solo con el límite anónimo.
    """
    headers = {
        "User-Agent": "SENTINEL-OSINT/1.0",
        "Accept": "application/vnd.github.v3+json",
    }
    if token is None:
        from ..utils.secret_vault import vault
        token = vault.get("GitHub")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# host → (categoría, relevancia base). Se compara el dominio exacto o un subdominio: 'x.com' no debe
# coincidir con linux.com ni netflix.com.
PLATFORMS = {
    "linkedin.com": ("LinkedIn", 90), "github.com": ("GitHub", 85), "twitter.com": ("Twitter/X", 85),
    "x.com": ("Twitter/X", 85), "facebook.com": ("Facebook", 80), "instagram.com": ("Instagram", 80),
}


def classify_url(url: str):
    """(categoría, relevancia) según el dominio de la URL; ('Web', 70) si no es una plataforma conocida."""
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return "Web", 70
    for domain, result in PLATFORMS.items():
        if host == domain or host.endswith("." + domain):
            return result
    return "Web", 70


class WebSearchTool(OSINTTool):
    """Búsqueda web con varios buscadores y respaldo (utils/search_engine)."""

    def __init__(self):
        super().__init__(
            "WebSearch",
            "Búsqueda web general para encontrar información pública",
            ToolRequirements(
                mandatory=["target_name"],
                optional=["domain", "observable"],
                produces=["url", "name", "note"],
                hint="Busca información pública sobre una persona, organización o dominio.",
            )
        )
        self.is_available = True
        self.is_heavy = False

    def check_available(self) -> bool:
        return True

    def _search(self, query: str, max_results: int = 20):
        """Búsqueda multimotor: devuelve el resultado completo (aciertos, motor usado e intentos)."""
        from ..utils.search_engine import web_search
        return web_search(query, max_results=max_results)

    def _search_duckduckgo(self, query: str, max_results: int = 20) -> List[Dict[str, str]]:
        """Compatibilidad: solo los aciertos de la búsqueda multimotor."""
        return self._search(query, max_results).hits

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        results = []
        queries = []

        # Build search queries based on available data
        name = query_params.target_name or ""
        domain = query_params.domain or ""
        # Contexto extra (universidad, país, ciudad): el de los casos viene en `context`; el del perfilador, en `observable`
        observable = query_params.context or query_params.observable or ""

        if name:
            # Main name search
            queries.append(f'"{name}"')

            # With context
            if observable:
                queries.append(f'"{name}" {observable}')

            # Social media searches
            queries.append(f'"{name}" site:linkedin.com')
            queries.append(f'"{name}" site:github.com')
            queries.append(f'"{name}" site:twitter.com OR site:x.com')

        if domain:
            queries.append(f'site:{domain}')
            if name:
                queries.append(f'"{name}" site:{domain}')

        # El ritmo entre consultas lo controla la capa de búsqueda (search_engine)
        seen_urls = set()
        engines_used = set()
        for query in queries[:6]:  # Limit to avoid rate limiting
            if self._is_cancelled:
                break
            outcome = self._search(query, max_results=10)
            if outcome.all_blocked:
                # Antes: 0 resultados en silencio tras ~200 s de esperas inútiles
                self._report_progress(f"⚠️ WebSearch: {outcome.explain()}")
                break
            if outcome.engine:
                engines_used.add(outcome.engine)
            search_results = outcome.hits

            for r in search_results:
                if r['url'] not in seen_urls:
                    seen_urls.add(r['url'])

                    category, relevance = classify_url(r['url'])

                    results.append(SearchResult(
                        title=r['title'],
                        url=r['url'],
                        snippet=r['snippet'] or f"Encontrado en búsqueda: {query}",
                        source_tool=self.name,
                        category=category,
                        relevance_score=relevance,
                        extra_data={"query": query},
                    ))

        if results:
            self._report_progress(f"✅ WebSearch: {len(results)} resultados (buscadores: {', '.join(sorted(engines_used))})")
        return results


class GitHubOSINTTool(OSINTTool):
    """OSINT de perfiles GitHub via API pública."""

    def __init__(self):
        super().__init__(
            "GitHubOSINT",
            "Extrae información de perfiles y repositorios de GitHub",
            ToolRequirements(
                mandatory=["username"],
                optional=["target_name"],
                produces=["url", "email", "name", "note"],
                hint="Necesita un username de GitHub.",
            )
        )
        self.is_available = True
        self.is_heavy = False

    def check_available(self) -> bool:
        return True

    def _api_request(self, endpoint: str):
        """GET a la API de GitHub. Devuelve (datos | None, estado HTTP); estado 0 = fallo de red."""
        try:
            url = f"https://api.github.com{endpoint}"
            req = urllib.request.Request(url, headers=github_headers())
            with urllib.request.urlopen(req, timeout=15, context=SSL_CONTEXT) as response:
                return json.loads(response.read().decode('utf-8')), response.status
        except urllib.error.HTTPError as e:
            logger.warning(f"GitHub API HTTP {e.code}")
            return None, e.code
        except Exception as e:
            logger.warning(f"GitHub API error: {e}")
            return None, 0

    def _api_get(self, endpoint: str) -> Dict[str, Any]:
        """GET a la API de GitHub; {} si falla (para datos secundarios como repos y actividad)."""
        data, _status = self._api_request(endpoint)
        return data if data is not None else {}

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        results = []
        username = query_params.username

        if not username:
            return results
        # Nombres de GitHub: letras, números y guiones (máx. 39). Uno con "_" o "." (moises_caicedo55, de
        # Instagram) no puede existir en GitHub: antes se consultaba y el "no encontrado" salía como candidato
        username = username.strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", username):
            self._report_progress(f"ℹ️ GitHubOSINT: '{username}' no es un nombre de usuario válido en GitHub; se omite.")
            return results

        # Get user profile
        user, status = self._api_request(f"/users/{username}")
        if status in (403, 429) or (user is None and status != 404):
            return [SearchResult(
                title=f"No se pudo consultar GitHub para {username}",
                url="",
                snippet=github_unavailable_hint(status),
                source_tool=self.name,
                category="Aviso",
                relevance_score=10,
            )]
        if not user or 'login' not in user:
            return [SearchResult(
                title=f"Usuario no encontrado: {username}",
                url=f"https://github.com/{username}",
                snippet="El perfil no existe o no es accesible públicamente.",
                source_tool=self.name,
                category="Sin resultado",           # no es un dato de la persona: no debe salir como candidato
                relevance_score=50,
            )]

        # Main profile result
        profile_info = []
        if user.get('name'):
            profile_info.append(f"Nombre: {user['name']}")
        if user.get('company'):
            profile_info.append(f"Empresa: {user['company']}")
        if user.get('location'):
            profile_info.append(f"Ubicación: {user['location']}")
        if user.get('bio'):
            profile_info.append(f"Bio: {user['bio']}")
        if user.get('email'):
            profile_info.append(f"Email: {user['email']}")
        if user.get('blog'):
            profile_info.append(f"Web: {user['blog']}")
        if user.get('twitter_username'):
            profile_info.append(f"Twitter: @{user['twitter_username']}")

        profile_info.append(f"Repos públicos: {user.get('public_repos', 0)}")
        profile_info.append(f"Seguidores: {user.get('followers', 0)}")
        profile_info.append(f"Siguiendo: {user.get('following', 0)}")
        profile_info.append(f"Creado: {user.get('created_at', 'N/A')}")

        results.append(SearchResult(
            title=f"GitHub: {user.get('name') or username}",
            url=user.get('html_url', f"https://github.com/{username}"),
            snippet=" | ".join(profile_info),
            source_tool=self.name,
            category="GitHub Profile",
            relevance_score=95,
            extra_data={
                'avatar_url': user.get('avatar_url'),
                'name': user.get('name'),
                'email': user.get('email'),
                'company': user.get('company'),
                'location': user.get('location'),
                'bio': user.get('bio'),
                'twitter': user.get('twitter_username'),
                'repos_count': user.get('public_repos'),
                'followers': user.get('followers'),
            }
        ))

        results.extend(self._social_accounts(username, user))

        # Get repositories
        repos = self._api_get(f"/users/{username}/repos?per_page=30&sort=updated")
        if repos and isinstance(repos, list):
            results.extend(self._commit_emails(username, user, repos))
        if repos and isinstance(repos, list):
            languages = {}
            topics = set()

            for repo in repos[:20]:
                lang = repo.get('language')
                if lang:
                    languages[lang] = languages.get(lang, 0) + 1

                # Get topics
                for topic in repo.get('topics', []):
                    topics.add(topic)

                # Add repo as result
                desc = repo.get('description') or 'Sin descripción'
                results.append(SearchResult(
                    title=f"Repo: {repo['name']}",
                    url=repo.get('html_url', ''),
                    snippet=f"{desc} | {lang or 'N/A'} | ⭐{repo.get('stargazers_count', 0)}",
                    source_tool=self.name,
                    category="GitHub Repo",
                    relevance_score=75,
                    extra_data={
                        'language': lang,
                        'stars': repo.get('stargazers_count'),
                        'forks': repo.get('forks_count'),
                        'topics': repo.get('topics', []),
                    }
                ))

            # Summary of languages
            if languages:
                top_langs = sorted(languages.items(), key=lambda x: -x[1])[:5]
                lang_str = ", ".join([f"{l}({c})" for l, c in top_langs])
                results.append(SearchResult(
                    title=f"Lenguajes principales de {username}",
                    url=f"https://github.com/{username}?tab=repositories",
                    snippet=f"Top lenguajes: {lang_str}",
                    source_tool=self.name,
                    category="GitHub Analysis",
                    relevance_score=80,
                ))

            if topics:
                results.append(SearchResult(
                    title=f"Temas/Topics de {username}",
                    url=f"https://github.com/{username}",
                    snippet=f"Topics encontrados: {', '.join(list(topics)[:15])}",
                    source_tool=self.name,
                    category="GitHub Analysis",
                    relevance_score=75,
                ))

        # Get recent activity
        events = self._api_get(f"/users/{username}/events/public?per_page=10")
        if events and isinstance(events, list) and events:
            recent_activity = []
            for event in events[:5]:
                event_type = event.get('type', '').replace('Event', '')
                repo_name = event.get('repo', {}).get('name', 'N/A')
                created = event.get('created_at', '')[:10]
                recent_activity.append(f"{created}: {event_type} en {repo_name}")

            if recent_activity:
                results.append(SearchResult(
                    title=f"Actividad reciente de {username}",
                    url=f"https://github.com/{username}",
                    snippet=" | ".join(recent_activity),
                    source_tool=self.name,
                    category="GitHub Activity",
                    relevance_score=70,
                ))

        return results

    # Pivotes que el perfil no muestra pero la API pública sí (verificado en real 2026-10-04: kentcdodds → X,
    # YouTube y Bluesky + 2 correos; gaearon → dan.abramov@gmail.com). Antes no se consultaban.
    COMMIT_REPOS = 3
    _NOREPLY = ("noreply.github.com", "noreply@github.com", "users.noreply.github.com")

    def _social_accounts(self, username: str, user: Dict[str, Any]) -> List[SearchResult]:
        accounts = self._api_get(f"/users/{username}/social_accounts")
        out = []
        for acc in accounts if isinstance(accounts, list) else []:
            url = acc.get("url") or ""
            if not url.startswith(("http://", "https://")):
                continue
            provider = (acc.get("provider") or "web").capitalize()
            out.append(SearchResult(
                title=f"{provider} vinculado al GitHub de {username}",
                url=url,
                snippet=f"El propio usuario de GitHub '{username}' ({user.get('name') or 'sin nombre'}) enlaza esta "
                        f"cuenta {provider} en su perfil.",
                source_tool=self.name, category="Social Media", relevance_score=90,
                extra_data={"name": user.get("name"), "platform": provider, "linked_from": f"github:{username}"},
            ))
        return out

    def _commit_emails(self, username: str, user: Dict[str, Any], repos: List[Dict[str, Any]]) -> List[SearchResult]:
        """Correos con los que el usuario firma sus commits públicos (dato clásico de OSINT en GitHub)."""
        emails: Dict[str, Dict[str, Any]] = {}
        own = [r for r in repos if not r.get("fork") and r.get("name")][:self.COMMIT_REPOS]
        for repo in own:
            commits = self._api_get(f"/repos/{username}/{urllib.parse.quote(repo['name'])}/commits?author={username}&per_page=30")
            for c in commits if isinstance(commits, list) else []:
                author = (c.get("commit") or {}).get("author") or {}
                email = (author.get("email") or "").strip().lower()
                if not email or "@" not in email or any(email.endswith(n) for n in self._NOREPLY):
                    continue
                entry = emails.setdefault(email, {"names": set(), "repos": set(), "count": 0})
                entry["names"].add(author.get("name") or "")
                entry["repos"].add(repo["name"])
                entry["count"] += 1
        out = []
        for email, info in emails.items():
            names = ", ".join(sorted(n for n in info["names"] if n))
            out.append(SearchResult(
                title=f"Correo en commits de {username}: {email}",
                url=f"https://github.com/{username}",
                snippet=f"{email} firma {info['count']} commit(s) públicos de {username} en "
                        f"{', '.join(sorted(info['repos']))}. Autor: {names or 'sin nombre'}.",
                source_tool=self.name, category="Email", relevance_score=85,
                extra_data={"email": email, "name": names.split(", ")[0] if names else user.get("name"),
                            "source": "commits públicos de GitHub"},
            ))
        return out


class _OrderedSet(dict):
    """Set mínimo que conserva el orden de inserción (add / update)."""

    def add(self, item: str) -> None:
        self[item] = None

    def update(self, items) -> None:
        for item in items:
            self[item] = None


def score_github_match(target_name: str, user: Dict[str, Any]):
    """(relevancia, nota) de una cuenta de GitHub que existe, según cuánto se parece su nombre al objetivo.

    Antes toda cuenta existente puntuaba 90 aunque fuera de otra persona con un nombre común.
    """
    from ..utils.person_match import name_match
    profile_name = (user.get("name") or "").strip()
    if not profile_name:
        return 55, "el perfil no tiene nombre: no se puede confirmar que sea la persona"
    points, kind = name_match(target_name, profile_name)
    if kind == "name":
        return 90, "el nombre del perfil coincide con el objetivo"
    if kind == "name_partial":
        return 70, "el nombre del perfil coincide en parte"
    return 40, "el nombre del perfil NO coincide: probablemente es otra persona"


class UsernameVariantsTool(OSINTTool):
    """Genera y busca variantes de un username."""

    def __init__(self):
        super().__init__(
            "UsernameVariants",
            "Genera variantes de username y busca en múltiples plataformas",
            ToolRequirements(
                mandatory=["target_name"],
                optional=["username"],
                produces=["username", "url"],
                hint="Genera posibles usernames a partir de un nombre.",
            )
        )
        self.is_available = True
        self.is_heavy = False

    def check_available(self) -> bool:
        return True

    def _generate_variants(self, name: str, year: str = None, context: str = "") -> List[str]:
        """
        Genera variantes exhaustivas de username.

        Patrones incluidos:
        - Combinaciones nombre/apellido: ivanortiz, ivan.ortiz, ivan_ortiz, ortizivan
        - Iniciales: iortiz, i.ortiz, io, i_ortiz
        - Con años: ivanortiz2000, ivanortiz00, ivan.ortiz.00
        - Con contexto: ivanortiz_udla, ivan.udla
        - Leet speak: iv4n0rt1z, 1van0rt1z
        - Diminutivos latinos: ivancho, ivancito
        - Sufijos comunes: ivan_dev, ivan.ec, ivanortizoficial
        - Separadores múltiples: ivan--ortiz, ivan__ortiz
        - Truncados: ivanort, iortiz99
        """
        # Conjunto ORDENADO: las variantes se generan de más a menos probables
        # y luego se recorta a 200 (y solo se consultan las 10 primeras).
        # Con un set() normal el recorte descartaba variantes al azar.
        variants = _OrderedSet()

        # Limpiar y separar nombre
        name_clean = name.lower().strip()
        # Remover acentos comunes
        replacements = {'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u', 'ñ': 'n', 'ü': 'u'}
        for old, new in replacements.items():
            name_clean = name_clean.replace(old, new)

        parts = name_clean.replace('-', ' ').replace('_', ' ').replace('.', ' ').split()

        if len(parts) == 0:
            return []

        # Convención hispana N1 N2 A1 A2: el apellido de uso es el PATERNO (3.ª palabra de 4). Antes se tomaba la
        # última: "María José Vásquez Mora" daba "mariamora" (y en GitHub aparecía otra MARIA MORA).
        # Con 3 palabras no se sabe si es N N A o N A A: se generan ambas lecturas, intercaladas al principio.
        first = parts[0]
        mother = ""
        alt_last = ""
        if len(parts) >= 4:
            middle, last, mother = parts[1], parts[-2], parts[-1]
        elif len(parts) == 3:
            middle, last, alt_last = parts[1], parts[2], parts[1]
        else:
            middle, last = "", (parts[-1] if len(parts) >= 2 else "")

        if alt_last:
            for a, b in ((first, last), (first, alt_last)):
                variants.update([f"{a}{b}", f"{a}.{b}", f"{a}_{b}"])
            variants.update([f"{first[0]}{last}", f"{first[0]}{alt_last}"])
        if mother:
            # jperezm / juan.perez.m: muy usados en correos y usuarios corporativos de Ecuador
            variants.update([f"{first}{last}", f"{first}.{last}", f"{first[0]}{last}{mother[0]}",
                             f"{first}{last}{mother[0]}", f"{first}.{last}.{mother[0]}", f"{first[0]}{last}{mother}"])

        # ═══════════════════════════════════════════════════════════════════════
        # COMBINACIONES BÁSICAS
        # ═══════════════════════════════════════════════════════════════════════
        if last:
            # Orden normal
            variants.update([
                f"{first}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first}-{last}",
                f"{first}{last}",
                # Orden invertido
                f"{last}{first}",
                f"{last}.{first}",
                f"{last}_{first}",
                f"{last}-{first}",
                # Solo apellido
                last,
            ])
        variants.add(first)

        # ═══════════════════════════════════════════════════════════════════════
        # VARIANTES CON INICIALES
        # ═══════════════════════════════════════════════════════════════════════
        if last:
            f1 = first[0]
            l1 = last[0]
            variants.update([
                f"{f1}{last}",       # iortiz
                f"{f1}.{last}",      # i.ortiz
                f"{f1}_{last}",      # i_ortiz
                f"{f1}-{last}",      # i-ortiz
                f"{first}{l1}",      # ivano
                f"{f1}{l1}",         # io
                f"{f1}{last}{l1}",   # iortizo
                f"{last}{f1}",       # ortizi
            ])
            # Con iniciales de dos primeras letras
            if len(first) >= 2:
                variants.update([
                    f"{first[:2]}{last}",   # ivortiz
                    f"{first[:2]}_{last}",  # iv_ortiz
                    f"{first[:2]}.{last}",  # iv.ortiz
                ])
            if len(last) >= 2:
                variants.update([
                    f"{first}{last[:2]}",   # ivanor
                    f"{f1}{last[:3]}",      # iort
                ])

        # ═══════════════════════════════════════════════════════════════════════
        # INICIAL + APELLIDO + AÑO DEL OBJETIVO (jriofrio2006, jriofrio06, juanr2006)
        # El bloque de años de más abajo solo usa las primeras variantes básicas y nunca llegaba a estas.
        # Rescatado de smart_profiler.
        # ═══════════════════════════════════════════════════════════════════════
        if year and last:
            f1, l1 = first[0], last[0]
            initial_bases = [f"{f1}{last}", f"{f1}.{last}", f"{f1}_{last}", f"{first}{l1}", f"{last}{f1}"]
            if middle:
                initial_bases.append(f"{f1}{middle[0]}{last}")
            for base in initial_bases:
                for y in (year, year[-2:]):
                    variants.update([f"{base}{y}", f"{base}_{y}", f"{base}.{y}"])

        # ═══════════════════════════════════════════════════════════════════════
        # CON MIDDLE NAME
        # ═══════════════════════════════════════════════════════════════════════
        if middle and last:
            variants.update([
                f"{first}{middle[0]}{last}",   # ivanaortiz
                f"{first}.{middle[0]}.{last}", # ivan.a.ortiz
                f"{first}_{middle[0]}_{last}", # ivan_a_ortiz
                f"{first[0]}{middle[0]}{last}",# iaortiz
            ])

        # ═══════════════════════════════════════════════════════════════════════
        # CON AÑOS (si se proporciona o común)
        # ═══════════════════════════════════════════════════════════════════════
        years = []
        if year:
            years.append(year)
            years.append(year[-2:])  # 2000 -> 00
        # Años comunes de nacimiento para adultos jóvenes
        for y in ['85', '86', '87', '88', '89', '90', '91', '92', '93', '94', '95',
                  '96', '97', '98', '99', '00', '01', '02', '03', '04', '05']:
            years.append(y)
            years.append(f"19{y}" if int(y) > 50 else f"20{y}")

        base_variants = list(variants)[:15]  # Top bases para no explotar
        for base in base_variants:
            for y in years[:10]:  # Limitar años
                variants.add(f"{base}{y}")
                variants.add(f"{base}_{y}")
                variants.add(f"{base}.{y}")

        # ═══════════════════════════════════════════════════════════════════════
        # CON CONTEXTO (universidad, empresa, país)
        # ═══════════════════════════════════════════════════════════════════════
        context_words = []
        ctx = (context or "").lower()
        # Extraer palabras clave del contexto
        if 'udla' in ctx:
            context_words.extend(['udla', 'udlaec', 'udelasamericas'])
        ctx_words = set(re.findall(r"[a-z0-9]+", ctx))
        if 'ecuador' in ctx or 'ec' in ctx_words:      # antes `'ec' in ctx`: cualquier "tecnología" activaba EC
            context_words.extend(['ec', 'ecu', 'ecuador', '593'])
        if 'quito' in ctx:
            context_words.extend(['quito', 'qto', 'uio'])
        if 'guayaquil' in ctx or 'gye' in ctx:
            context_words.extend(['gye', 'guayaquil'])
        if 'ingenier' in ctx:
            context_words.extend(['dev', 'developer', 'ing', 'engineer'])
        if 'seguridad' in ctx or 'security' in ctx or 'cyber' in ctx:
            context_words.extend(['sec', 'security', 'cyber', 'hacker', 'infosec'])

        for base in base_variants[:10]:
            for ctx_word in context_words[:5]:
                variants.update([
                    f"{base}_{ctx_word}",
                    f"{base}.{ctx_word}",
                    f"{base}{ctx_word}",
                    f"{ctx_word}_{base}",
                    f"{ctx_word}{base}",
                ])

        # ═══════════════════════════════════════════════════════════════════════
        # LEET SPEAK
        # ═══════════════════════════════════════════════════════════════════════
        leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        if last:
            base_leet = f"{first}{last}"
            leet_version = base_leet
            for char, leet in leet_map.items():
                leet_version = leet_version.replace(char, leet)
            if leet_version != base_leet:
                variants.add(leet_version)
            # Solo vocales en leet
            partial_leet = base_leet
            for char in ['a', 'e', 'i', 'o']:
                partial_leet = partial_leet.replace(char, leet_map[char])
            if partial_leet != base_leet:
                variants.add(partial_leet)

        # ═══════════════════════════════════════════════════════════════════════
        # DIMINUTIVOS LATINOS
        # ═══════════════════════════════════════════════════════════════════════
        diminutivos = {
            'ivan': ['ivancho', 'ivancito', 'ivo', 'vani'],
            'juan': ['juancho', 'juanito', 'juani'],
            'carlos': ['carlitos', 'carl', 'charly'],
            'jose': ['pepe', 'joselo', 'chepe'],
            'francisco': ['paco', 'pancho', 'fran', 'cisco'],
            'roberto': ['beto', 'robert', 'rob'],
            'manuel': ['manu', 'manolo', 'manuelito'],
            'gabriel': ['gabo', 'gabi', 'gabito'],
            'daniel': ['dani', 'dan', 'danielito'],
            'miguel': ['migue', 'mike', 'miguelito'],
            'antonio': ['toño', 'tony', 'anto'],
            'fernando': ['fer', 'nando', 'fercho'],
            'luis': ['lucho', 'luisito', 'luchito'],
            'david': ['dave', 'davo', 'davidcito'],
            'andres': ['andy', 'andresito'],
            'pablo': ['pablito', 'paul'],
            'pedro': ['pete', 'pedrito'],
            'jorge': ['coque', 'jorgito'],
            'alejandro': ['alex', 'ale', 'alejito'],
            'ricardo': ['ricky', 'rick', 'richard'],
            'eduardo': ['edu', 'lalo', 'eddy'],
            'hernan': ['nani', 'herni'],
        }

        if first in diminutivos:
            for dim in diminutivos[first]:
                variants.add(dim)
                if last:
                    variants.update([
                        f"{dim}{last}",
                        f"{dim}_{last}",
                        f"{dim}.{last}",
                    ])

        # ═══════════════════════════════════════════════════════════════════════
        # SUFIJOS COMUNES DE REDES SOCIALES
        # ═══════════════════════════════════════════════════════════════════════
        suffixes = [
            'oficial', '_oficial', '.oficial',
            'real', '_real', '.real', 'thereal',
            '_', '__', '1', '01', '001', '123',
            '_dev', 'dev', '.dev',
            '_ec', 'ec', '.ec',
            '_gt', '_co', '_mx', '_pe', '_cl', '_ar',
            'x', 'xx', 'xd', '_xd',
            '_ok', 'ok',
        ]

        for base in base_variants[:8]:
            for suffix in suffixes:
                variants.add(f"{base}{suffix}")

        # ═══════════════════════════════════════════════════════════════════════
        # PREFIJOS COMUNES
        # ═══════════════════════════════════════════════════════════════════════
        prefixes = ['the', 'el', 'la', 'soy', 'im', 'mr', 'real', 'its', 'just']
        for base in [first, f"{first}{last}" if last else first][:2]:
            for prefix in prefixes:
                variants.update([
                    f"{prefix}{base}",
                    f"{prefix}_{base}",
                    f"{prefix}.{base}",
                ])

        # Limitar a 200 variantes máximo para no explotar
        return list(variants)[:200]

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        results = []
        name = query_params.target_name or ""

        if not name:
            return results

        # Extract year if present in observable
        year = None
        observable = query_params.context or query_params.observable or ""
        import re
        year_match = re.search(r'(19|20)\d{2}', observable + name)
        if year_match:
            year = year_match.group()

        # Construir contexto desde los parámetros disponibles
        context = f"{observable} {query_params.company or ''} {query_params.domain or ''}"

        variants = self._generate_variants(name, year, context)

        results.append(SearchResult(
            title=f"Variantes de username para: {name}",
            url="",
            snippet=f"Posibles usernames: {', '.join(variants[:20])}",
            source_tool=self.name,
            category="Username Generation",
            relevance_score=60,
            extra_data={'variants': variants}
        ))

        # Check GitHub for each variant
        checked = 0
        limited = False
        for variant in variants[:10]:
            try:
                url = f"https://api.github.com/users/{variant}"
                req = urllib.request.Request(url, headers=github_headers())
                with urllib.request.urlopen(req, timeout=5, context=SSL_CONTEXT) as response:
                    user = json.loads(response.read().decode('utf-8'))
                checked += 1
                if user.get('login'):
                    relevance, note = score_github_match(name, user)
                    results.append(SearchResult(
                        title=f"GitHub encontrado: {variant}",
                        url=f"https://github.com/{variant}",
                        snippet=f"Nombre: {user.get('name') or 'N/A'} | Repos: {user.get('public_repos', 0)} | {note}",
                        source_tool=self.name,
                        category="GitHub Match",
                        relevance_score=relevance,
                        extra_data={'avatar_url': user.get('avatar_url')}
                    ))
            except urllib.error.HTTPError as e:
                if e.code in (403, 429):          # límite de GitHub: parar y avisar, no seguir golpeando
                    limited = True
                    break
                checked += 1                      # 404: ese usuario no existe
            except Exception:
                pass

            time.sleep(0.5)  # Rate limiting

        if limited:
            results.append(SearchResult(
                title="GitHub limitó las consultas de variantes de usuario",
                url="",
                snippet=f"Se revisaron {checked} de {min(len(variants), 10)} variantes. " + github_unavailable_hint(403),
                source_tool=self.name,
                category="Aviso",
                relevance_score=10,
            ))

        return results
