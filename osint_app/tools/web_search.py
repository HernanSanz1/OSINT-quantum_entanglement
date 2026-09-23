"""
Web Search Tool - Búsqueda web para OSINT
Usa DuckDuckGo para evitar captchas de Google.
"""
import json
import time
import logging
import ssl
import urllib.parse
import urllib.request
from typing import List, Dict, Any
from ..core.models import ToolRequirements, QueryParameters, SearchResult
from ..core.base_tool import OSINTTool

logger = logging.getLogger(__name__)

# SSL context that doesn't verify (for proxies/corporate networks)
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


class WebSearchTool(OSINTTool):
    """Búsqueda web usando DuckDuckGo HTML."""

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

    def _search_duckduckgo(self, query: str, max_results: int = 20) -> List[Dict[str, str]]:
        """Busca en DuckDuckGo y extrae resultados."""
        results = []
        try:
            # DuckDuckGo HTML search
            encoded = urllib.parse.quote_plus(query)
            url = f"https://html.duckduckgo.com/html/?q={encoded}"

            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
            })

            with urllib.request.urlopen(req, timeout=15, context=SSL_CONTEXT) as response:
                html = response.read().decode('utf-8', errors='ignore')

            # Parse results (simple regex-free parsing)
            # Look for result links
            import re
            # DuckDuckGo HTML results are in <a class="result__a" href="...">
            pattern = r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)</a>'
            matches = re.findall(pattern, html, re.IGNORECASE)

            for href, title in matches[:max_results]:
                # DuckDuckGo wraps URLs, extract actual URL
                if 'uddg=' in href:
                    actual_url = urllib.parse.unquote(href.split('uddg=')[1].split('&')[0])
                else:
                    actual_url = href

                results.append({
                    'url': actual_url,
                    'title': title.strip(),
                    'snippet': ''
                })

            # Also try to get snippets
            snippet_pattern = r'<a class="result__snippet"[^>]*>([^<]+)</a>'
            snippets = re.findall(snippet_pattern, html, re.IGNORECASE)
            for i, snippet in enumerate(snippets):
                if i < len(results):
                    results[i]['snippet'] = snippet.strip()

        except Exception as e:
            logger.warning(f"DuckDuckGo search error: {e}")

        return results

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        results = []
        queries = []

        # Build search queries based on available data
        name = query_params.target_name or ""
        domain = query_params.domain or ""
        observable = query_params.observable or ""  # Extra context like university

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

        # Execute searches with delay
        seen_urls = set()
        for query in queries[:6]:  # Limit to avoid rate limiting
            search_results = self._search_duckduckgo(query, max_results=10)

            for r in search_results:
                if r['url'] not in seen_urls:
                    seen_urls.add(r['url'])

                    # Categorize by URL
                    category = "Web"
                    relevance = 70
                    url_lower = r['url'].lower()

                    if 'linkedin.com' in url_lower:
                        category = "LinkedIn"
                        relevance = 90
                    elif 'github.com' in url_lower:
                        category = "GitHub"
                        relevance = 85
                    elif 'twitter.com' in url_lower or 'x.com' in url_lower:
                        category = "Twitter/X"
                        relevance = 85
                    elif 'facebook.com' in url_lower:
                        category = "Facebook"
                        relevance = 80
                    elif 'instagram.com' in url_lower:
                        category = "Instagram"
                        relevance = 80

                    results.append(SearchResult(
                        title=r['title'],
                        url=r['url'],
                        snippet=r['snippet'] or f"Encontrado en búsqueda: {query}",
                        source_tool=self.name,
                        category=category,
                        relevance_score=relevance,
                    ))

            time.sleep(1)  # Rate limiting

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

    def _api_get(self, endpoint: str) -> Dict[str, Any]:
        """GET request a GitHub API."""
        try:
            url = f"https://api.github.com{endpoint}"
            req = urllib.request.Request(url, headers={
                'User-Agent': 'SENTINEL-OSINT/1.0',
                'Accept': 'application/vnd.github.v3+json'
            })
            with urllib.request.urlopen(req, timeout=15, context=SSL_CONTEXT) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as e:
            logger.warning(f"GitHub API error: {e}")
            return {}

    def execute(self, query_params: QueryParameters) -> List[SearchResult]:
        results = []
        username = query_params.username

        if not username:
            return results

        # Get user profile
        user = self._api_get(f"/users/{username}")
        if not user or 'login' not in user:
            return [SearchResult(
                title=f"Usuario no encontrado: {username}",
                url=f"https://github.com/{username}",
                snippet="El perfil no existe o no es accesible públicamente.",
                source_tool=self.name,
                category="GitHub",
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

        # Get repositories
        repos = self._api_get(f"/users/{username}/repos?per_page=30&sort=updated")
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
        variants = set()

        # Limpiar y separar nombre
        name_clean = name.lower().strip()
        # Remover acentos comunes
        replacements = {'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u', 'ñ': 'n', 'ü': 'u'}
        for old, new in replacements.items():
            name_clean = name_clean.replace(old, new)

        parts = name_clean.replace('-', ' ').replace('_', ' ').replace('.', ' ').split()

        if len(parts) == 0:
            return []

        first = parts[0]
        last = parts[-1] if len(parts) >= 2 else ""
        middle = parts[1] if len(parts) >= 3 else ""

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
        if 'ecuador' in ctx or 'ec' in ctx:
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
        observable = query_params.observable or ""
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
        for variant in variants[:10]:
            try:
                url = f"https://api.github.com/users/{variant}"
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'SENTINEL-OSINT/1.0'
                })
                with urllib.request.urlopen(req, timeout=5, context=SSL_CONTEXT) as response:
                    user = json.loads(response.read().decode('utf-8'))
                    if user.get('login'):
                        results.append(SearchResult(
                            title=f"GitHub encontrado: {variant}",
                            url=f"https://github.com/{variant}",
                            snippet=f"Nombre: {user.get('name', 'N/A')} | Repos: {user.get('public_repos', 0)}",
                            source_tool=self.name,
                            category="GitHub Match",
                            relevance_score=90,
                            extra_data={'avatar_url': user.get('avatar_url')}
                        ))
            except urllib.error.HTTPError:
                pass  # User doesn't exist
            except Exception:
                pass

            time.sleep(0.5)  # Rate limiting

        return results
