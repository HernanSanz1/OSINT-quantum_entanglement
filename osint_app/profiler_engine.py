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
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field

from .tools import build_tool_registry, ALL_TOOLS
from .core.models import QueryParameters, SearchResult
from .correlation_engine import CorrelationEngine

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
        """Convierte a QueryParameters para las herramientas."""
        return QueryParameters(
            target_name=self.name,
            email=self.email or "",
            domain=self.domain or "",
            username=self.username or "",
            company=self.company or "",
            phone=self.phone or "",
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


class ProfilerEngine:
    """
    Motor de perfilamiento que orquesta todas las herramientas.
    """

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

    def run_parallel(self, seed: SeedData, max_workers: int = 6,
                     timeout_per_tool: int = 120) -> List[ToolResult]:
        """
        Ejecuta todas las herramientas aplicables en paralelo.
        """
        tools_to_run = self.get_tools_for_seed(seed)

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
        return results

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
                    candidate = Candidate(
                        source_tool=tool_result.tool_name,
                        url=sr.url,
                        title=sr.title,
                        snippet=sr.snippet,
                        confidence=confidence,
                        category=sr.category,
                        matched_fields=matched,
                        raw_data=sr.raw_data if sr.raw_data else {},
                        user_verdict='pending'
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
