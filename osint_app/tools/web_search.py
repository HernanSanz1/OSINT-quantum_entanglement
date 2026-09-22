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

    def _generate_variants(self, name: str, year: str = None) -> List[str]:
        """Genera variantes de username."""
        variants = []

        # Clean and split name
        name = name.lower().strip()
        parts = name.replace('-', ' ').replace('_', ' ').split()

        if len(parts) >= 2:
            first = parts[0]
            last = parts[-1]

            # Basic variants
            variants.extend([
                f"{first}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first}-{last}",
                f"{last}{first}",
                f"{first[0]}{last}",
                f"{first}{last[0]}",
                f"{first[0]}.{last}",
                f"{first[0]}_{last}",
            ])

            # With year
            if year:
                for v in variants.copy():
                    variants.append(f"{v}{year}")
                    variants.append(f"{v}{year[-2:]}")

            # With common suffixes
            for suffix in ['_', '1', '01', '123', '_oficial', 'ec']:
                variants.append(f"{first}{last}{suffix}")

        return list(set(variants))

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

        variants = self._generate_variants(name, year)

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
