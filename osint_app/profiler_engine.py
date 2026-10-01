"""
Profiler Engine v2 — Motor de perfilamiento que lanza TODAS las herramientas en paralelo.

Flujo:
1. Recibe datos semilla (nombre, contexto, pais, username, email, etc)
2. Lanza herramientas en paralelo segun los datos disponibles
3. Recolecta TODOS los resultados
4. La IA filtra y correlaciona los que coinciden con el objetivo
5. Presenta candidatos al usuario para feedback
6. Con el feedback, refina la busqueda

Herramientas utilizadas:
- Google Dorks (masivo)
- GitHub OSINT
- Username Variants + Sherlock/Maigret
- Hunter.io (emails)
- Holehe (email en servicios)
- Wayback Machine
- Phone Numbers
- Censys
- SpiderFoot
"""
import json
import logging
import re
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field

from .tools import build_tool_registry, ALL_TOOLS
from .core.models import QueryParameters, SearchResult
from .correlation_engine import CorrelationEngine
from .utils import homonyms

logger = logging.getLogger(__name__)


@dataclass
class SeedData:
    """Datos semilla del objetivo."""
    name: str
    context: str = ""
    country: str = ""
    email: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    domain: Optional[str] = None
    company: Optional[str] = None

    def to_query_params(self) -> QueryParameters:
        """Convierte a QueryParameters para las herramientas.

        context y country se pasan en `observable`: WebSearch y
        UsernameVariants lo usan como contexto extra de búsqueda y para
        extraer el año. (Antes se perdían por el camino.)
        """
        observable = " ".join(p for p in (self.context, self.country) if p).strip()
        return QueryParameters(
            target_name=self.name,
            email=self.email or "",
            domain=self.domain or "",
            username=self.username or "",
            company=self.company or "",
            phone=self.phone or "",
            observable=observable,
        )


@dataclass
class ToolResult:
    """Resultado de una herramienta."""
    tool_name: str
    status: str  # 'ok', 'error', 'timeout', 'unavailable'
    results: List[SearchResult] = field(default_factory=list)
    error: str = ""
    duration_seconds: float = 0.0


@dataclass
class Candidate:
    """Un candidato encontrado por las herramientas."""
    source_tool: str
    url: str
    title: str
    snippet: str
    confidence: float  # 0-100
    category: str
    matched_fields: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    user_verdict: Optional[str] = None  # 'confirmed', 'rejected', 'pending'
    warning: str = ""                   # aviso de posible homónimo (no descarta)


class ProfilerEngine:
    """
    Motor de perfilamiento que orquesta todas las herramientas.
    """

    # Cuánto baja la confianza de un candidato con señal de homónimo (no se borra).
    HOMONYM_PENALTY = 30.0

    # Búsqueda encadenada (segunda ronda): con los usernames descubiertos en la
    # primera ronda, se relanzan estas herramientas. Se limita el número de
    # usernames para no disparar el número de peticiones.
    CHAINED_USERNAME_TOOLS = ["GitHubOSINT", "Sherlock", "Maigret"]
    MAX_CHAINED_USERNAMES = 3

    # Herramientas por prioridad y tipo de dato requerido
    # 'required' son opciones OR - si tiene CUALQUIERA de estos datos, corre
    TOOL_PRIORITY = {
        # Alta prioridad - siempre correr si hay nombre
        'Google Dorks': {'required': ['name', 'email', 'username', 'domain'], 'priority': 1},
        'GitHubOSINT': {'required': ['name', 'username'], 'priority': 1},
        'WebSearch': {'required': ['name', 'email', 'username'], 'priority': 1},
        'UsernameVariants': {'required': ['name'], 'priority': 1},

        # Media prioridad
        'Sherlock': {'required': ['username', 'name'], 'priority': 2},
        'Maigret': {'required': ['username', 'name'], 'priority': 2},
        'Holehe': {'required': ['email'], 'priority': 2},
        'Hunter.io': {'required': ['domain', 'email', 'name'], 'priority': 2},

        # Herramientas de infraestructura
        'Wayback Machine': {'required': ['domain'], 'priority': 3},
        'crt.sh': {'required': ['domain'], 'priority': 3},
        'Tech Detect': {'required': ['domain'], 'priority': 3},
        'Domain WHOIS': {'required': ['domain'], 'priority': 3},
        'Mail Health': {'required': ['domain'], 'priority': 3},
        'CENSYS': {'required': ['domain'], 'priority': 3},
        'dnspython': {'required': ['domain'], 'priority': 3},
        'phonenumbers': {'required': ['phone'], 'priority': 3},
        'Subfinder': {'required': ['domain'], 'priority': 3},
        'OWASP AMASS': {'required': ['domain'], 'priority': 3},
        'SpiderFoot': {'required': ['domain', 'name'], 'priority': 3},
    }

    def __init__(self, progress_callback: Callable[[str], None] = None):
        self.tools = build_tool_registry()
        self.progress_callback = progress_callback or (lambda x: None)
        self.results: List[ToolResult] = []
        self.candidates: List[Candidate] = []
        self.confirmed: List[Candidate] = []
        self.rejected: List[Candidate] = []

    def _log(self, msg: str):
        """Log y callback de progreso."""
        logger.info(msg)
        self.progress_callback(msg)

    def get_available_tools(self) -> List[str]:
        """Retorna herramientas disponibles."""
        return [name for name, tool in self.tools.items() if tool.is_available]

    def get_tools_for_seed(self, seed: SeedData) -> List[str]:
        """Determina que herramientas correr segun los datos semilla."""
        available = []

        for tool_name, config in self.TOOL_PRIORITY.items():
            if tool_name not in self.tools:
                continue
            if not self.tools[tool_name].is_available:
                continue

            # Verificar si tenemos los datos requeridos
            required = config['required']
            has_data = False

            for req in required:
                if req == 'name' and seed.name:
                    has_data = True
                elif req == 'email' and seed.email:
                    has_data = True
                elif req == 'username' and seed.username:
                    has_data = True
                elif req == 'domain' and seed.domain:
                    has_data = True
                elif req == 'phone' and seed.phone:
                    has_data = True

            if has_data:
                available.append((tool_name, config['priority']))

        # Ordenar por prioridad
        available.sort(key=lambda x: x[1])
        return [t[0] for t in available]

    def _select_tools_to_run(self, seed: SeedData, only_tools: List[str] = None) -> List[str]:
        """Herramientas aplicables, filtradas por la selección del usuario.

        only_tools vacía o None = todas las aplicables. Si se pasa una lista,
        solo esas (que además estén disponibles y tengan datos). Registra las
        seleccionadas que se omiten para que el usuario sepa por qué.
        """
        tools_to_run = self.get_tools_for_seed(seed)
        if only_tools:
            requested = set(only_tools)
            filtered = [t for t in tools_to_run if t in requested]
            skipped = requested - set(filtered)
            if skipped:
                self._log(f"Seleccionadas pero omitidas (no disponibles o sin datos): {', '.join(sorted(skipped))}")
            tools_to_run = filtered
        return tools_to_run

    def run_parallel(self, seed: SeedData, max_workers: int = 6,
                     timeout_per_tool: int = 120,
                     only_tools: List[str] = None,
                     chain: bool = False) -> List[ToolResult]:
        """
        Ejecuta las herramientas aplicables en paralelo.

        only_tools: si se pasa una lista no vacía, solo se ejecutan esas
        herramientas (además de estar disponibles y tener los datos que
        necesitan). Vacía o None = todas las aplicables.
        chain: si es True, tras la primera ronda lanza una segunda ronda con
        los usernames descubiertos (búsqueda encadenada).
        """
        tools_to_run = self._select_tools_to_run(seed, only_tools)

        if not tools_to_run:
            self._log("No hay herramientas disponibles para los datos proporcionados")
            return []

        self._log(f"Herramientas a ejecutar: {', '.join(tools_to_run)}")
        self._log(f"Ejecutando {len(tools_to_run)} herramientas en paralelo...")

        query_params = seed.to_query_params()
        results = []

        def run_tool(tool_name: str) -> ToolResult:
            """Ejecuta una herramienta individual."""
            start = datetime.now()
            try:
                tool = self.tools[tool_name]
                self._log(f"  [{tool_name}] Iniciando...")

                tool_results = tool.execute(query_params)

                duration = (datetime.now() - start).total_seconds()
                self._log(f"  [{tool_name}] Completado: {len(tool_results)} resultados en {duration:.1f}s")

                return ToolResult(
                    tool_name=tool_name,
                    status='ok',
                    results=tool_results,
                    duration_seconds=duration
                )
            except Exception as e:
                duration = (datetime.now() - start).total_seconds()
                self._log(f"  [{tool_name}] Error: {str(e)[:50]}")
                return ToolResult(
                    tool_name=tool_name,
                    status='error',
                    error=str(e),
                    duration_seconds=duration
                )

        # Ejecutar en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tool = {
                executor.submit(run_tool, tool_name): tool_name
                for tool_name in tools_to_run
            }

            for future in concurrent.futures.as_completed(future_to_tool, timeout=timeout_per_tool * 2):
                tool_name = future_to_tool[future]
                try:
                    result = future.result(timeout=timeout_per_tool)
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    self._log(f"  [{tool_name}] Timeout")
                    results.append(ToolResult(
                        tool_name=tool_name,
                        status='timeout',
                        error='Timeout exceeded'
                    ))
                except Exception as e:
                    self._log(f"  [{tool_name}] Excepcion: {str(e)[:50]}")
                    results.append(ToolResult(
                        tool_name=tool_name,
                        status='error',
                        error=str(e)
                    ))

        self.results = results

        if chain:
            round1_hits = [sr for tr in results for sr in tr.results]
            discovered = extract_usernames_from_results(round1_hits)
            self.run_second_round(
                seed, discovered, max_workers=max_workers,
                timeout_per_tool=timeout_per_tool, only_tools=only_tools,
            )

        return self.results

    def _execute_tool(self, tool_name: str, query_params: QueryParameters,
                      label: str = None) -> ToolResult:
        """Ejecuta una herramienta y devuelve su ToolResult (nunca lanza).

        `label` permite anotar la procedencia, p.ej. 'Sherlock:jperez' en la
        segunda ronda encadenada.
        """
        name = label or tool_name
        start = datetime.now()
        try:
            results = self.tools[tool_name].execute(query_params)
            duration = (datetime.now() - start).total_seconds()
            self._log(f"  [{name}] Completado: {len(results)} resultados en {duration:.1f}s")
            return ToolResult(tool_name=name, status='ok', results=results,
                              duration_seconds=duration)
        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            self._log(f"  [{name}] Error: {str(e)[:50]}")
            return ToolResult(tool_name=name, status='error', error=str(e),
                              duration_seconds=duration)

    def run_second_round(self, seed: SeedData, discovered_usernames: List[str],
                         max_workers: int = 6, timeout_per_tool: int = 90,
                         only_tools: List[str] = None) -> List[ToolResult]:
        """Segunda ronda encadenada: relanza las herramientas de username sobre
        los usernames descubiertos que no estaban en la semilla.

        Devuelve solo los ToolResults nuevos (que además se añaden a self.results).
        """
        seed_user = (seed.username or "").lower()
        usernames = []
        for u in discovered_usernames:
            if u.lower() != seed_user and u not in usernames:
                usernames.append(u)
        usernames = usernames[:self.MAX_CHAINED_USERNAMES]
        if not usernames:
            return []

        requested = set(only_tools) if only_tools else None
        tools = [
            t for t in self.CHAINED_USERNAME_TOOLS
            if t in self.tools and self.tools[t].is_available
            and (requested is None or t in requested)
        ]
        if not tools:
            return []

        self._log(f"🔗 Segunda ronda: {len(usernames)} usernames × {len(tools)} herramientas")

        tasks = []
        for u in usernames:
            qp = seed.to_query_params()
            qp.username = u
            for tool_name in tools:
                tasks.append((tool_name, qp, f"{tool_name}:{u}"))

        new_results: List[ToolResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_label = {
                executor.submit(self._execute_tool, tn, qp, label): label
                for (tn, qp, label) in tasks
            }
            for future in concurrent.futures.as_completed(future_to_label, timeout=timeout_per_tool * 2):
                label = future_to_label[future]
                try:
                    new_results.append(future.result(timeout=timeout_per_tool))
                except concurrent.futures.TimeoutError:
                    self._log(f"  [{label}] Timeout")
                    new_results.append(ToolResult(tool_name=label, status='timeout',
                                                  error='Timeout exceeded'))
                except Exception as e:
                    self._log(f"  [{label}] Excepcion: {str(e)[:50]}")
                    new_results.append(ToolResult(tool_name=label, status='error', error=str(e)))

        self.results.extend(new_results)
        return new_results

    def extract_candidates(self, seed: SeedData, min_confidence: float = 30.0) -> List[Candidate]:
        """
        Extrae candidatos de los resultados de las herramientas.
        Aplica filtrado basico de correlacion con los datos semilla.
        """
        self._log(f"Extrayendo candidatos de {len(self.results)} herramientas...")

        all_candidates = []

        for tool_result in self.results:
            if tool_result.status != 'ok':
                continue

            for sr in tool_result.results:
                # Calcular confianza basica
                confidence, matched = self._calculate_confidence(sr, seed)

                if confidence >= min_confidence:
                    # Señal de homónimo (enfoque A): avisa y penaliza, no descarta.
                    text = f"{sr.title} {sr.snippet} {sr.url}"
                    warning = homonyms.homonym_warning(text, seed.country) or ""
                    if warning:
                        confidence = max(0.0, confidence - self.HOMONYM_PENALTY)

                    candidate = Candidate(
                        source_tool=tool_result.tool_name,
                        url=sr.url,
                        title=sr.title,
                        snippet=sr.snippet,
                        confidence=confidence,
                        category=sr.category,
                        matched_fields=matched,
                        raw_data=sr.raw_data if sr.raw_data else {},
                        user_verdict='pending',
                        warning=warning,
                    )
                    all_candidates.append(candidate)

        # Deduplicar por URL
        seen_urls = set()
        unique_candidates = []
        for c in all_candidates:
            if c.url not in seen_urls:
                seen_urls.add(c.url)
                unique_candidates.append(c)

        # Ordenar por confianza
        unique_candidates.sort(key=lambda x: x.confidence, reverse=True)

        self.candidates = unique_candidates
        self._log(f"Candidatos extraidos: {len(unique_candidates)} unicos")

        return unique_candidates

    def _calculate_confidence(self, result: SearchResult, seed: SeedData) -> tuple:
        """
        Calcula confianza de un resultado vs datos semilla.
        Retorna (score 0-100, campos coincidentes).
        """
        text = f"{result.title} {result.snippet} {result.url}".lower()
        score = 0.0
        matched = []

        # Nombre completo
        if seed.name:
            name_lower = seed.name.lower()
            if name_lower in text:
                score += 40
                matched.append('name')
            else:
                # Partes del nombre
                parts = seed.name.lower().split()
                matches = sum(1 for p in parts if p in text and len(p) > 2)
                if matches >= 2:
                    score += 25
                    matched.append('name_partial')
                elif matches == 1:
                    score += 10

        # Email (muy alto valor)
        if seed.email and seed.email.lower() in text:
            score += 35
            matched.append('email')

        # Username
        if seed.username and seed.username.lower() in text:
            score += 25
            matched.append('username')

        # Pais/contexto
        if seed.country and seed.country.lower() in text:
            score += 10
            matched.append('country')

        if seed.context:
            context_words = [w for w in seed.context.lower().split() if len(w) > 3]
            context_matches = sum(1 for w in context_words if w in text)
            if context_matches >= 2:
                score += 15
                matched.append('context')

        # Dominio
        if seed.domain and seed.domain.lower() in text:
            score += 15
            matched.append('domain')

        # Phone
        if seed.phone:
            clean_phone = ''.join(c for c in seed.phone if c.isdigit())
            if len(clean_phone) > 5 and clean_phone in text:
                score += 30
                matched.append('phone')

        # Ajustar por categoria del resultado (si ya viene con nivel de confianza)
        if hasattr(result, 'category') and result.category:
            if 'CONFIRMADO' in result.category.upper():
                score += 20
            elif 'PROBABLE' in result.category.upper():
                score += 10

        return min(score, 100), matched

    def confirm_candidate(self, candidate_url: str):
        """Marca un candidato como confirmado."""
        for c in self.candidates:
            if c.url == candidate_url:
                c.user_verdict = 'confirmed'
                self.confirmed.append(c)
                self._log(f"Confirmado: {c.title[:50]}")
                return True
        return False

    def reject_candidate(self, candidate_url: str):
        """Marca un candidato como rechazado."""
        for c in self.candidates:
            if c.url == candidate_url:
                c.user_verdict = 'rejected'
                self.rejected.append(c)
                self._log(f"Rechazado: {c.title[:50]}")
                return True
        return False

    def refine_with_confirmed(self, seed: SeedData) -> SeedData:
        """
        Refina los datos semilla con informacion de candidatos confirmados.
        Retorna seed enriquecido para nueva busqueda.
        """
        for c in self.confirmed:
            # Extraer datos utiles del candidato
            raw = c.raw_data or {}

            # Si encontramos username nuevo
            if not seed.username and raw.get('username'):
                seed.username = raw['username']
                self._log(f"Nuevo username: {seed.username}")

            # Si encontramos email nuevo
            if not seed.email and raw.get('email'):
                seed.email = raw['email']
                self._log(f"Nuevo email: {seed.email}")

            # Si encontramos dominio
            if not seed.domain and raw.get('domain'):
                seed.domain = raw['domain']
                self._log(f"Nuevo dominio: {seed.domain}")

        return seed

    def save_to_case(self, seed: SeedData, case_id: int = None) -> int:
        """Persiste la semilla y los resultados de las herramientas en un caso.

        Si no se pasa case_id, crea un caso nuevo con la semilla. Devuelve el
        case_id. Debe llamarse después de run_parallel(). Antes, los resultados
        del perfilamiento se perdían al cerrar la ventana.
        """
        from .db.feedback_db import db
        from .case_manager import CaseManager
        from .core.models import ToolReport, TargetData

        if case_id is None:
            case = CaseManager().create(
                f"Perfil: {seed.name}",
                f"Contexto: {seed.context} | País: {seed.country}",
            )
            case_id = case.id
            seed_fields = [
                ("name", seed.name), ("context", seed.context), ("country", seed.country),
                ("email", seed.email), ("username", seed.username),
                ("phone", seed.phone), ("domain", seed.domain), ("company", seed.company),
            ]
            for field_type, value in seed_fields:
                if value:
                    db.add_target_data(TargetData(
                        case_id=case_id, field_type=field_type, value=value,
                        source="seed", confidence=100,
                    ))

        for tr in self.results:
            report = ToolReport(
                case_id=case_id, tool_name=tr.tool_name,
                raw_json=json.dumps([r.to_dict() for r in tr.results], ensure_ascii=False),
                summary=f"{len(tr.results)} resultados",
                status=tr.status,
                execution_time=round(tr.duration_seconds, 2),
                results_count=len(tr.results),
            )
            db.save_report(report)

        self._promote_profile_fields(case_id)
        return case_id

    def _promote_profile_fields(self, case_id: int) -> None:
        """Guarda como datos del caso los campos estructurados de los perfiles
        de GitHub encontrados (nombre, email, empresa, ubicación, Twitter).

        Migrado de profiler.OSINTProfiler._run_github_osint. Deduplica contra
        lo que ya hay en el caso para no repetir.
        """
        from .db.feedback_db import db
        from .core.models import TargetData

        existing = {(d.field_type, d.value) for d in db.get_target_data(case_id)}

        def _add(field_type: str, value, confidence: int):
            if not value:
                return
            value = str(value).strip()
            if not value or (field_type, value) in existing:
                return
            db.add_target_data(TargetData(
                case_id=case_id, field_type=field_type, value=value,
                source="GitHub", confidence=confidence,
            ))
            existing.add((field_type, value))

        for tool_result in self.results:
            for sr in tool_result.results:
                if getattr(sr, "category", "") != "GitHub Profile":
                    continue
                extra = getattr(sr, "extra_data", None)
                if not isinstance(extra, dict):
                    continue
                _add("name", extra.get("name"), 90)
                _add("email", extra.get("email"), 95)
                _add("company", extra.get("company"), 85)
                _add("location", extra.get("location"), 80)
                tw = extra.get("twitter")
                if tw:
                    _add("twitter", f"@{str(tw).lstrip('@')}", 90)

    def get_summary(self) -> Dict[str, Any]:
        """Retorna resumen del perfilamiento."""
        return {
            'timestamp': datetime.now().isoformat(),
            'tools_executed': len(self.results),
            'tools_ok': len([r for r in self.results if r.status == 'ok']),
            'tools_error': len([r for r in self.results if r.status == 'error']),
            'total_results': sum(len(r.results) for r in self.results),
            'candidates': len(self.candidates),
            'confirmed': len(self.confirmed),
            'rejected': len(self.rejected),
            'pending': len([c for c in self.candidates if c.user_verdict == 'pending']),
        }

    def export_report(self) -> Dict[str, Any]:
        """Exporta reporte completo del perfilamiento."""
        return {
            'summary': self.get_summary(),
            'confirmed': [
                {
                    'url': c.url,
                    'title': c.title,
                    'source': c.source_tool,
                    'confidence': c.confidence,
                    'matched_fields': c.matched_fields,
                }
                for c in self.confirmed
            ],
            'candidates': [
                {
                    'url': c.url,
                    'title': c.title,
                    'source': c.source_tool,
                    'confidence': c.confidence,
                    'verdict': c.user_verdict,
                }
                for c in self.candidates[:50]  # Top 50
            ],
            'tool_results': [
                {
                    'tool': r.tool_name,
                    'status': r.status,
                    'count': len(r.results),
                    'duration': r.duration_seconds,
                }
                for r in self.results
            ]
        }


_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
_GITHUB_USER_RE = re.compile(r'github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)', re.I)
# Primeros segmentos de github.com que NO son un usuario.
_GITHUB_RESERVED = {
    "search", "orgs", "topics", "about", "login", "settings", "explore",
    "users", "sponsors", "marketplace", "collections", "trending",
    "features", "pricing", "notifications", "new",
}
_LINKEDIN_RE = re.compile(r'linkedin\.com/in/([A-Za-z0-9\-_%.]+)', re.I)
_TWITTER_RE = re.compile(r'(?:twitter\.com|x\.com)/([A-Za-z0-9_]+)', re.I)
_TWITTER_RESERVED = {"search", "explore", "i", "home", "hashtag", "share", "intent", "settings"}


def extract_usernames_from_results(results) -> List[str]:
    """Usernames descubiertos en las URLs de los resultados (GitHub, LinkedIn,
    Twitter/X), para encadenar una segunda ronda de búsqueda.

    Preserva el orden de aparición y elimina duplicados. Migrado de
    profiler.OSINTProfiler._extract_entities_from_results.
    """
    found: List[str] = []

    def _add(value: str):
        if value and value not in found:
            found.append(value)

    for r in results:
        url = getattr(r, "url", "") if not isinstance(r, dict) else r.get("url", "")
        if not url:
            continue

        m = _GITHUB_USER_RE.search(url)
        if m and m.group(1).lower() not in _GITHUB_RESERVED:
            _add(m.group(1))

        m = _LINKEDIN_RE.search(url)
        if m:
            _add(m.group(1))

        m = _TWITTER_RE.search(url)
        if m and m.group(1).lower() not in _TWITTER_RESERVED:
            _add(m.group(1))

    return found


def enrich_seed_from_candidates(seed: "SeedData", candidates: List[Dict]) -> "SeedData":
    """Rellena los campos vacíos de la semilla con datos de candidatos confirmados.

    Solo completa lo que falta (nunca pisa lo que el usuario ya puso). Extrae
    username de URLs de GitHub, email del texto y dominio del email.
    """
    import copy
    new = copy.copy(seed)
    for c in candidates:
        url = c.get("url") or ""
        text = f"{c.get('title', '')} {c.get('snippet', '')}"

        if not new.username:
            m = _GITHUB_USER_RE.search(url)
            if m and m.group(1).lower() not in _GITHUB_RESERVED:
                new.username = m.group(1)

        if not new.email:
            m = _EMAIL_RE.search(text)
            if m:
                new.email = m.group(0)

        if not new.domain and new.email and "@" in new.email:
            new.domain = new.email.split("@", 1)[1]

    return new


# Funcion de conveniencia para uso simple
def profile_person(name: str, context: str = "", country: str = "",
                   email: str = None, username: str = None,
                   progress_callback: Callable = None) -> Dict[str, Any]:
    """
    Perfila una persona usando todas las herramientas disponibles.

    Ejemplo:
        from osint_app.profiler_engine import profile_person
        result = profile_person(
            name="Juan Riofrio",
            context="UDLA Ecuador ingeniero software",
            country="Ecuador",
            progress_callback=print
        )
    """
    seed = SeedData(
        name=name,
        context=context,
        country=country,
        email=email,
        username=username
    )

    engine = ProfilerEngine(progress_callback=progress_callback)

    # Correr herramientas
    engine.run_parallel(seed)

    # Extraer candidatos
    candidates = engine.extract_candidates(seed)

    return {
        'seed': {
            'name': seed.name,
            'context': seed.context,
            'country': seed.country,
        },
        'summary': engine.get_summary(),
        'candidates': [
            {
                'source': c.source_tool,
                'url': c.url,
                'title': c.title,
                'snippet': c.snippet[:200] if c.snippet else '',
                'confidence': c.confidence,
                'matched_fields': c.matched_fields,
            }
            for c in candidates[:30]  # Top 30
        ]
    }
