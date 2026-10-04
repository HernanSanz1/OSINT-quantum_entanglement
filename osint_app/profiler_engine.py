"""
Profiler Engine v2 — Motor de perfilamiento que lanza TODAS las herramientas en paralelo.

Flujo:
1. Recibe datos semilla (nombre, contexto, pais, username, email, etc)
2. Lanza herramientas en paralelo segun los datos disponibles
3. Recolecta TODOS los resultados
4. Puntúa y correlaciona los que coinciden con el objetivo
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
from typing import List, Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field

from .tools import build_tool_registry
from .core.models import QueryParameters, SearchResult
from .utils import homonyms
from .utils.person_match import name_match, normalize_text, normalize_url, phone_in_text, username_in_text
from .utils.entity_filters import FREEMAIL_DOMAINS, ROLE_ACCOUNTS, is_valid_email
from .utils.identity import name_from_profile_title, parse_profile_url, profile_key
from .utils.directories import is_directory_result

logger = logging.getLogger(__name__)


def unique_values(values, strip_at: bool = False) -> List[str]:
    """Valores sin vacíos ni repetidos (sin distinguir mayúsculas), en el orden en que llegaron."""
    out: List[str] = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if strip_at:
            text = text.lstrip("@").strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
    return out


def parse_list(text: str, strip_at: bool = False) -> List[str]:
    """'a@x.com, b@y.com; c@z.com' → ['a@x.com', 'b@y.com', 'c@z.com']. Para los campos de varios valores."""
    return unique_values(re.split(r"[,;\n]+", text or ""), strip_at=strip_at)


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
    company: Optional[str] = None            # empleador
    # Más datos del objetivo (todos opcionales)
    city: str = ""
    university: str = ""
    aliases: List[str] = field(default_factory=list)          # apodos y variantes del nombre ("Carlos Andrade León")
    extra_emails: List[str] = field(default_factory=list)
    extra_usernames: List[str] = field(default_factory=list)
    extra_phones: List[str] = field(default_factory=list)

    def all_names(self) -> List[str]:
        return unique_values([self.name, *self.aliases])

    def all_emails(self) -> List[str]:
        return unique_values([self.email, *self.extra_emails])

    def all_usernames(self) -> List[str]:
        return unique_values([self.username, *self.extra_usernames], strip_at=True)

    def all_phones(self) -> List[str]:
        return unique_values([self.phone, *self.extra_phones])

    def to_query_params(self) -> QueryParameters:
        """Convierte a QueryParameters para las herramientas.

        Contexto, país y ciudad van en `context` (texto libre para buscadores y para extraer el año).
        Antes iban en `observable`, que es para indicadores concretos (dominio, IP, correo): las herramientas
        de amenazas e Instaloader lo tomaban como objetivo.
        """
        context = " ".join(p for p in (self.context, self.country, self.city) if p).strip()
        return QueryParameters(
            target_name=self.name,
            email=self.email or "",
            domain=self.domain or "",
            username=self.username or "",
            company=self.company or "",
            phone=self.phone or "",
            context=context,
            location=self.city or "",
            university=self.university or "",
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
    extra_data: Dict[str, Any] = field(default_factory=dict)   # datos estructurados del resultado (GitHub: empresa, ubicación…)


class ProfilerEngine:
    """
    Motor de perfilamiento que orquesta todas las herramientas.
    """

    # Cuánto baja la confianza de un candidato con señal de homónimo (no se borra).
    HOMONYM_PENALTY = homonyms.STRONG_PENALTY

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
        'Wikidata': {'required': ['name'], 'priority': 1},       # personas públicas: datos y cuentas oficiales

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

        # Ejecutar en paralelo. Los resultados ya obtenidos se conservan aunque alguna herramienta se cuelgue.
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        future_to_tool = {executor.submit(run_tool, tool_name): tool_name for tool_name in tools_to_run}
        results = self._gather(executor, future_to_tool, timeout_per_tool * 2)

        self.results = results

        self.run_extra_identifiers(seed, max_workers=max_workers, timeout_per_tool=timeout_per_tool, only_tools=only_tools)

        if chain:
            # Solo se encadenan usuarios de resultados que SÍ parecen la persona (nombre o correo coinciden).
            # Antes se tomaban de cualquier URL: las variantes que UsernameVariants marcaba como "NO coincide,
            # probablemente es otra persona" (github.com/kent, github.com/dodds) lanzaban 198 resultados ajenos.
            round1_hits = [sr for tr in results for sr in tr.results if self._is_about_target(sr, seed)]
            discovered = extract_usernames_from_results(round1_hits)
            self.run_second_round(
                seed, discovered, max_workers=max_workers,
                timeout_per_tool=timeout_per_tool, only_tools=only_tools,
            )

        return self.results

    CHAIN_MIN_CONFIDENCE = 40

    def _is_about_target(self, result: SearchResult, seed: SeedData) -> bool:
        """True si el resultado coincide con la persona por nombre (completo o nombre+apellido) o por correo."""
        confidence, matched = self._calculate_confidence(result, seed)
        return confidence >= self.CHAIN_MIN_CONFIDENCE and bool({"name", "alias", "email"} & set(matched))

    def _gather(self, executor, future_to_name: Dict, total_timeout: float) -> List[ToolResult]:
        """Recoge los resultados de las tareas lanzadas, sin perder ninguno si el tiempo se agota.

        Las tareas que no terminaron a tiempo se marcan 'timeout' y no se espera por ellas
        (un hilo colgado no puede detenerse, pero tampoco debe bloquear ni tirar el perfilamiento).
        """
        results: List[ToolResult] = []
        try:
            for future in concurrent.futures.as_completed(future_to_name, timeout=total_timeout):
                name = future_to_name[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    self._log(f"  [{name}] Excepcion: {str(e)[:50]}")
                    results.append(ToolResult(tool_name=name, status='error', error=str(e)))
        except concurrent.futures.TimeoutError:
            pass
        for future, name in future_to_name.items():
            if not future.done():
                future.cancel()
                self._log(f"  [{name}] Timeout")
                results.append(ToolResult(tool_name=name, status='timeout', error='Timeout exceeded'))
        executor.shutdown(wait=False, cancel_futures=True)
        return results

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
        return self._run_labelled_tasks(tasks, max_workers, timeout_per_tool)

    def _run_labelled_tasks(self, tasks: List[Tuple[str, QueryParameters, str]], max_workers: int,
                            timeout_per_tool: int) -> List[ToolResult]:
        """Ejecuta (herramienta, parámetros, etiqueta) en paralelo y añade los resultados a self.results."""
        if not tasks:
            return []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        future_to_label = {executor.submit(self._execute_tool, tn, qp, label): label for (tn, qp, label) in tasks}
        new_results = self._gather(executor, future_to_label, timeout_per_tool * 2)
        self.results.extend(new_results)
        return new_results

    # Herramientas que se relanzan por cada identificador adicional de la semilla
    EXTRA_TOOLS = {
        "username": CHAINED_USERNAME_TOOLS,
        "email": ["Holehe", "Google Dorks"],
        "phone": ["phonenumbers", "Google Dorks"],
        "alias": ["WebSearch", "UsernameVariants"],
    }
    MAX_EXTRA_PER_KIND = 3

    def run_extra_identifiers(self, seed: SeedData, max_workers: int = 6, timeout_per_tool: int = 90,
                              only_tools: List[str] = None) -> List[ToolResult]:
        """Relanza las herramientas adecuadas por cada alias, correo, usuario o teléfono ADICIONAL de la semilla.

        La primera ronda ya cubrió el principal. Se limita a MAX_EXTRA_PER_KIND de cada tipo para no
        multiplicar las peticiones (y que los buscadores no bloqueen).
        """
        requested = set(only_tools) if only_tools else None

        def usable(names):
            return [t for t in names if t in self.tools and self.tools[t].is_available
                    and (requested is None or t in requested)]

        def extras(values, primary, strip_at=False):
            skip = (primary or "").lower().lstrip("@")
            return [v for v in unique_values(values, strip_at=strip_at) if v.lower().lstrip("@") != skip][:self.MAX_EXTRA_PER_KIND]

        plan = (
            ("username", extras(seed.extra_usernames, seed.username, strip_at=True), "username"),
            ("email", extras(seed.extra_emails, seed.email), "email"),
            ("phone", extras(seed.extra_phones, seed.phone), "phone"),
            ("alias", extras(seed.aliases, seed.name), "target_name"),
        )
        tasks = []
        for kind, values, param in plan:
            tools = usable(self.EXTRA_TOOLS[kind])
            for value in values:
                for tool_name in tools:
                    qp = seed.to_query_params()
                    setattr(qp, param, value)
                    tasks.append((tool_name, qp, f"{tool_name}:{value}"))
        if not tasks:
            return []
        self._log(f"➕ Datos adicionales de la semilla: {len(tasks)} búsquedas")
        return self._run_labelled_tasks(tasks, max_workers, timeout_per_tool)

    def extract_candidates(self, seed: SeedData, min_confidence: float = 30.0) -> List[Candidate]:
        """
        Extrae candidatos de los resultados de las herramientas.
        Aplica filtrado basico de correlacion con los datos semilla.
        """
        self._log(f"Extrayendo candidatos de {len(self.results)} herramientas...")

        all_candidates = []
        self.skipped_listings: Dict[str, int] = {}

        for tool_result in self.results:
            if tool_result.status != 'ok':
                continue

            for sr in tool_result.results:
                # Los listados de personas ("600+ perfiles", directorios) no son candidatos; siguen en los reportes
                listing = is_directory_result(sr.title, sr.url)
                if listing:
                    self.skipped_listings[listing] = self.skipped_listings.get(listing, 0) + 1
                    continue

                # Calcular confianza basica
                confidence, matched = self._calculate_confidence(sr, seed)

                if confidence >= min_confidence:
                    # Señales de homónimo (enfoque A): avisan y penalizan según su fuerza, nunca descartan.
                    text = f"{sr.title} {sr.snippet} {sr.url}"
                    signals = homonyms.homonym_signals(text, sr.url, seed.country, f"{seed.context} {seed.city}")
                    warning = homonyms.warning_text(signals)
                    if signals:
                        confidence = max(0.0, confidence - homonyms.total_penalty(signals))

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
                        extra_data=sr.extra_data if isinstance(sr.extra_data, dict) else {},
                    )
                    all_candidates.append(candidate)

        # Deduplicar: la misma página escrita distinto (http/https, www, barra, rastreo) cuenta una vez;
        # los resultados sin URL se distinguen por título y texto.
        seen_keys = set()
        unique_candidates = []
        for c in all_candidates:
            key = normalize_url(c.url) if c.url else (c.source_tool, c.title, c.snippet)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_candidates.append(c)

        # Ordenar por confianza
        unique_candidates.sort(key=lambda x: x.confidence, reverse=True)

        self.candidates = unique_candidates
        self._log(f"Candidatos extraidos: {len(unique_candidates)} unicos")
        if self.skipped_listings:
            detail = ", ".join(f"{n} {kind}" for kind, n in self.skipped_listings.items())
            self._log(f"Omitidos {sum(self.skipped_listings.values())} listados que no son una persona ({detail}); siguen en los reportes")

        return unique_candidates

    def _calculate_confidence(self, result: SearchResult, seed: SeedData) -> tuple:
        """
        Calcula confianza de un resultado vs datos semilla.
        Retorna (score 0-100, campos coincidentes).
        """
        text = f"{result.title} {result.snippet} {result.url}".lower()
        score = 0.0
        matched = []

        # Nombre o alias: palabras completas, sin depender de tildes, mayúsculas ni del orden
        names = seed.all_names()
        if names:
            (points, kind), used = max(((name_match(n, text), n) for n in names), key=lambda r: r[0][0])
            score += points
            if kind:
                matched.append(kind if used == seed.name else ("alias" if kind == "name" else "alias_partial"))

        # Email (muy alto valor)
        if any(e.lower() in text for e in seed.all_emails()):
            score += 35
            matched.append('email')

        # Username: el mismo usuario que dio el analista en otra plataforma ya es un candidato a revisar (30).
        # Antes valía 25, por debajo del mínimo: Sherlock encontraba 40 perfiles de "kentcdodds" y se descartaban todos.
        if any(username_in_text(u, text) for u in seed.all_usernames()):
            score += 30
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

        # Empleador, universidad y ciudad: corroboran que es la persona correcta (y no un homónimo)
        norm = normalize_text(text)
        for label, value, points in (("company", seed.company, 15), ("university", seed.university, 15), ("city", seed.city, 10)):
            phrase = normalize_text(value or "")
            if len(phrase) >= 3 and re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", norm):
                score += points
                matched.append(label)

        # Dominio
        if seed.domain and seed.domain.lower() in text:
            score += 15
            matched.append('domain')

        # Phone
        if any(phone_in_text(p, text) for p in seed.all_phones()):
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
                ("location", seed.city), ("university", seed.university),
            ]
            for field_type, value in seed_fields:
                if value:
                    db.add_target_data(TargetData(
                        case_id=case_id, field_type=field_type, value=value,
                        source="seed", confidence=100,
                    ))
            # Los datos adicionales quedan con confianza algo menor: el principal sigue siendo el objetivo
            for field_type, values in (("name", seed.aliases), ("email", seed.extra_emails),
                                       ("username", seed.extra_usernames), ("phone", seed.extra_phones)):
                for value in unique_values(values, strip_at=(field_type == "username")):
                    db.add_target_data(TargetData(
                        case_id=case_id, field_type=field_type, value=value,
                        source="seed", confidence=95,
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


# Plataformas donde el usuario del perfil se puede usar como username en otras búsquedas
_USERNAME_PLATFORMS = {"github", "x", "instagram", "tiktok", "reddit", "telegram", "medium", "youtube"}


def identity_from_candidate(candidate: Dict) -> Dict[str, str]:
    """Datos de identidad que aporta un candidato: username, email, empresa, ubicación, nombre y perfil.

    Solo de lo estructurado: la URL del perfil, los campos de su resultado (GitHub) y un correo escrito
    en el texto. Los correos de rol (info@, ventas@) no se toman: son de una organización, no de la persona.
    """
    out: Dict[str, str] = {}
    url = candidate.get("url") or ""
    extra = candidate.get("extra") if isinstance(candidate.get("extra"), dict) else {}
    parsed = parse_profile_url(url)
    if parsed:
        platform, handle, canonical = parsed
        out["profile"] = canonical
        if platform in _USERNAME_PLATFORMS and "/" not in handle:
            out["username"] = handle
        name = (extra.get("name") or "").strip() or name_from_profile_title(candidate.get("title", ""), platform, handle)
        if name:
            out["name"] = name
    if extra.get("company"):
        out["company"] = str(extra["company"]).strip().lstrip("@").strip()
    if extra.get("location"):
        out["location"] = str(extra["location"]).strip()
    text = f"{candidate.get('title', '')} {candidate.get('snippet', '')}"
    for match in _EMAIL_RE.finditer(text):
        email = match.group(0)
        if is_valid_email(email) and email.split("@")[0].lower() not in ROLE_ACCOUNTS:
            out["email"] = email
            break
    return {k: v for k, v in out.items() if v}


def enrich_seed_from_candidates(seed: "SeedData", candidates: List[Dict]) -> "SeedData":
    """Rellena los campos vacíos de la semilla con datos de candidatos confirmados.

    Solo completa lo que falta (nunca pisa lo que el usuario ya puso). Toma el username del perfil
    (GitHub, X, Instagram, TikTok…), el email del texto, la empresa si el resultado la trae y el
    dominio del email, salvo que sea de un proveedor gratuito (gmail.com no es el dominio de nadie).
    """
    import copy
    new = copy.copy(seed)
    for c in candidates:
        found = identity_from_candidate(c)
        if not new.username and found.get("username"):
            new.username = found["username"]
        if not new.email and found.get("email"):
            new.email = found["email"]
        if not new.company and found.get("company"):
            new.company = found["company"]
        if not new.domain and new.email and "@" in new.email:
            email_domain = new.email.split("@", 1)[1].lower()
            if email_domain not in FREEMAIL_DOMAINS:
                new.domain = email_domain
    return new


def promote_confirmed_to_case(case_id: int, candidates: List[Dict]) -> List[Tuple[str, str]]:
    """Guarda como datos del caso lo que aportan los candidatos que el investigador confirmó.

    Son datos confirmados (confianza 90, origen "confirmado"), a diferencia de lo meramente descubierto
    (prefijo found_). No duplica lo que ya está en el caso ni cambia el objetivo. Devuelve lo añadido.
    """
    from .db.feedback_db import db
    from .core.models import TargetData

    def key(field_type: str, value: str) -> str:
        if field_type in ("username", "email"):
            return value.lower().lstrip("@")
        if field_type == "profile":
            return profile_key(value)
        return normalize_text(value)

    existing = {(d.field_type, key(d.field_type, d.value)) for d in db.get_target_data(case_id)
                if not d.field_type.startswith("found_")}
    added: List[Tuple[str, str]] = []
    for candidate in candidates:
        for field_type, value in identity_from_candidate(candidate).items():
            if (field_type, key(field_type, value)) in existing:
                continue
            db.add_target_data(TargetData(case_id=case_id, field_type=field_type, value=value,
                                          source="confirmado", confidence=90))
            existing.add((field_type, key(field_type, value)))
            added.append((field_type, value))
    return added


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
