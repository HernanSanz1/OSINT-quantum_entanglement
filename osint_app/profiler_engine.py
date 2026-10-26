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
from urllib.parse import urlsplit
from dataclasses import asdict, dataclass, field

from .tools import build_tool_registry
from .core.models import QueryParameters, SearchResult
from .utils import homonyms
from .utils.person_match import name_match, normalize_text, normalize_url, phone_in_text, username_in_text
from .utils.entity_filters import FREEMAIL_DOMAINS, ROLE_ACCOUNTS, is_valid_email
from .utils.identity import is_content_url, name_from_profile_title, parse_profile_url, profile_key
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


def _host_of(url: str) -> str:
    try:
        host = (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


# "Username Generation": la lista de variantes que se generan para probar no es un hallazgo (salía en el top 10)
NON_CANDIDATE_CATEGORIES = {"Aviso", "Error", "Config Error", "Alerta", "Sin resultado", "Username Generation"}
# Cuentas y web oficiales que da Wikidata de la ficha identificada sin dudas: nunca por debajo de esto
OFFICIAL_CONFIDENCE = 85.0


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
        # Los avisos de cada herramienta ("los buscadores bloquearon", "se agotó el tiempo"…) se perdían: ahora
        # llegan al registro del perfilamiento (solo avisos y errores, no cada paso)
        for tool_name, tool in self.tools.items():
            tool._progress_cb = self._tool_message_forwarder(tool_name)
        self.results: List[ToolResult] = []
        self.warnings: Dict[str, str] = {}
        self.candidates: List[Candidate] = []
        self.confirmed: List[Candidate] = []
        self.rejected: List[Candidate] = []

    def _tool_message_forwarder(self, tool_name: str):
        def forward(message: str):
            if any(mark in str(message) for mark in ("⚠️", "❌", "🛑")):
                self._log(f"    {message}")
                if "⚠️" in str(message) and "búsqueda web INCOMPLETA" in str(message):
                    # Se guardan para la ficha: una búsqueda bloqueada no debe parecer "no hay nada". Solo los de
                    # búsqueda web incompleta (no "Wikidata: 2 personas con ese nombre", ni el de Maigret "muchos
                    # sitios fallaron por red o DNS", que salía en todos los perfiles: siguen en el registro)
                    self.warnings[tool_name] = str(message).replace("⚠️", "").strip()
        return forward

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

            # Si la herramienta exige un dato que la semilla no tiene (Sherlock sin usuario, GitHub sin usuario…),
            # no se lanza: antes corría, devolvía 0 al instante y el informe decía "ok, 0 resultados".
            if has_data and not self._missing_mandatory(tool_name, seed):
                available.append((tool_name, config['priority']))

        # Ordenar por prioridad
        available.sort(key=lambda x: x[1])
        return [t[0] for t in available]

    _SEED_FIELD = {"target_name": "name", "username": "username", "email": "email", "domain": "domain",
                   "phone": "phone", "company": "company"}

    def _missing_mandatory(self, tool_name: str, seed: SeedData) -> bool:
        reqs = getattr(self.tools[tool_name], "requirements", None)
        for field_name in getattr(reqs, "mandatory", []) or []:
            attr = self._SEED_FIELD.get(field_name)
            if attr and not getattr(seed, attr, None):
                return True
        return False

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
        if {"WebSearch", "Google Dorks"} & set(tools_to_run):
            # En segundo plano: comprobar Docker no debe retrasar las búsquedas
            import threading
            from .utils.search_engine import searxng_problem

            def _check_searxng():
                problem = searxng_problem()
                if problem:
                    self._log(problem)
            threading.Thread(target=_check_searxng, daemon=True).start()
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
                if tool_name in self.warnings:
                    self._log(f"  ⚠️ [{tool_name}] Terminado con avisos: {len(tool_results)} resultados en {duration:.1f}s (incompleto)")
                else:
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
            discovered = corroborated_usernames(round1_hits)
            self.run_second_round(
                seed, discovered, max_workers=max_workers,
                timeout_per_tool=timeout_per_tool, only_tools=only_tools,
            )

        return self.results

    CHAIN_MIN_CONFIDENCE = 40

    def _is_about_target(self, result: SearchResult, seed: SeedData) -> bool:
        """True si el resultado coincide con la persona: nombre completo o correo, o nombre+apellido corroborado
        por país, ciudad, contexto, empresa o universidad (el X de Jefferson Pérez: nombre+apellido y Ecuador)."""
        confidence, matched = self._calculate_confidence(result, seed)
        fields = set(matched)
        if confidence >= self.CHAIN_MIN_CONFIDENCE and {"name", "alias", "email"} & fields:
            return True
        corroborated = {"country", "city", "context", "company", "university"} & fields
        return confidence >= 35 and bool({"name_partial", "alias_partial"} & fields) and bool(corroborated)

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
        # Se recuerdan para puntuar: un perfil con este usuario ES un candidato (se descubrió desde un resultado
        # verificado). Antes Sherlock/Maigret encontraban 14 perfiles de "jeffersonperezq" y se descartaban todos.
        self.chained_usernames = list(dict.fromkeys([*getattr(self, "chained_usernames", []), *usernames]))

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

    def _own_sites(self, seed: SeedData):
        """Webs del propio objetivo: la oficial que da Wikidata y los dominios con su nombre (jeffersonperez.com).

        Devuelve (hosts oficiales, claves de nombre, cuentas oficiales). La clave es nombre + primer apellido sin
        espacios, y solo si es larga (≥ 10 letras), para no confundir dominios cortos o genéricos. Las cuentas
        oficiales son (plataforma, usuario) que da Wikidata: su X sigue siendo suyo aunque diga que vive en
        Canadá (Andersson Boscán, prueba real 2026-10-13).
        """
        hosts = set()
        profiles = set()
        for tr in self.results:
            for sr in tr.results:
                extra = sr.extra_data if isinstance(sr.extra_data, dict) else {}
                if extra.get("official_site") and sr.url:
                    hosts.add(_host_of(sr.url))
                if sr.source_tool == "Wikidata" and sr.url and not extra.get("ambiguous") and not extra.get("discarded"):
                    parsed = parse_profile_url(sr.url)
                    if parsed:
                        profiles.add(parsed[:2])
        keys = set()
        for full in [seed.name] + list(seed.aliases or []):
            words = re.findall(r"[a-z0-9]+", normalize_text(full or ""))
            if len(words) >= 2:
                key = words[0] + words[1] if len(words) < 4 else words[0] + words[-2]
                if len(key) >= 10:
                    keys.add(key)
        return hosts - {""}, keys, profiles

    def _public_card_places(self) -> str:
        """Nacionalidad y lugar de nacimiento de la ficha de Wikidata del objetivo (si se identificó sin dudas).

        Sirven para no tomar por homónimo un resultado que menciona esos países: Noboa nació en Miami, Boscán es
        venezolano. Las fichas ambiguas o descartadas (otra persona) no cuentan.
        """
        places = []
        for tr in self.results:
            for sr in tr.results:
                extra = sr.extra_data if isinstance(sr.extra_data, dict) else {}
                if not (sr.category or "").startswith("Persona pública") or extra.get("ambiguous") or extra.get("discarded"):
                    continue
                raw = sr.raw_data if isinstance(sr.raw_data, dict) else {}
                for key in ("Nacionalidad", "Lugar de nacimiento"):
                    places.extend(str(v) for v in (raw.get(key) or []))
        return " · ".join(places)

    def extract_candidates(self, seed: SeedData, min_confidence: float = 30.0) -> List[Candidate]:
        """
        Extrae candidatos de los resultados de las herramientas.
        Aplica filtrado basico de correlacion con los datos semilla.
        """
        self._log(f"Extrayendo candidatos de {len(self.results)} herramientas...")

        all_candidates = []
        self.skipped_listings: Dict[str, int] = {}
        known_places = self._public_card_places()
        own_hosts, name_keys, own_profiles = self._own_sites(seed)

        for tool_result in self.results:
            if tool_result.status != 'ok':
                continue

            for sr in tool_result.results:
                # Avisos y errores de las herramientas ("GitHub limitó las consultas", "integración pendiente") no
                # son datos de la persona: antes aparecían como candidatos de 30 puntos sin URL
                if (sr.category or "").split(" /")[0] in NON_CANDIDATE_CATEGORIES:
                    continue
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
                    host = _host_of(sr.url)
                    own_site = bool(host) and (host in own_hosts or any(k in host.replace("-", "") for k in name_keys))
                    profile = parse_profile_url(sr.url) if sr.url else None
                    own_site = own_site or (profile is not None and profile[:2] in own_profiles)
                    signals = homonyms.homonym_signals(text, sr.url, seed.country, f"{seed.context} {seed.city}",
                                                       known_places=known_places, own_site=own_site,
                                                       aliases=seed.aliases, name=seed.name)
                    warning = homonyms.warning_text(signals)
                    if signals:
                        confidence = max(0.0, confidence - homonyms.total_penalty(signals))
                    extra = sr.extra_data if isinstance(sr.extra_data, dict) else {}
                    if sr.source_tool == "Wikidata" and (extra.get("platform") or extra.get("official_site")):
                        # Cuenta o web oficial de la ficha que Wikidata identificó sin dudas. Puntuada como cualquier
                        # resultado, un canal de YouTube (UCECJDeK0…) o una web (jeffersonperez.com) no llevan el
                        # nombre y bajaban a 50 y 25: la ficha los daba por "otra persona" (prueba real 2026-10-21).
                        confidence = max(confidence, OFFICIAL_CONFIDENCE)
                        extra = {**extra, "official": True}

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
                        extra_data=extra,
                    )
                    all_candidates.append(candidate)

        # Deduplicar: la misma página escrita distinto (http/https, www, barra, rastreo) cuenta una vez;
        # los resultados sin URL se distinguen por título y texto.
        # Entre repetidos se queda el mejor (antes, el primero en llegar): si WebSearch traía x.com/jeffersonperezq
        # antes que Wikidata, la cuenta perdía la marca de oficial según el orden en que acabaran las herramientas.
        best: Dict[Any, Candidate] = {}
        for c in all_candidates:
            key = normalize_url(c.url) if c.url else (c.source_tool, c.title, c.snippet)
            kept = best.get(key)
            if kept is None:
                best[key] = c
                continue
            winner, other = (c, kept) if c.confidence > kept.confidence else (kept, c)
            if other.extra_data.get("official") and not winner.extra_data.get("official"):
                winner.extra_data = {**winner.extra_data, "official": True}
                winner.confidence = max(winner.confidence, other.confidence)
            best[key] = winner
        unique_candidates = list(best.values())

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
        # Una PUBLICACIÓN de otra cuenta que solo menciona el usuario (un tuit que nombra a @jorgeulloaaa) es una
        # mención, no su perfil: vale 10 (en la prueba real puntuaba 80-95 como si fuera su cuenta).
        usernames = [(u, 'username') for u in seed.all_usernames()] +                     [(u, 'username_chained') for u in getattr(self, "chained_usernames", [])]
        hit = next((label for u, label in usernames if username_in_text(u, text)), None)
        if hit:
            parsed = parse_profile_url(result.url or "")
            author = parsed[1].lower() if parsed else ""
            if is_content_url(result.url or "") and author and author not in {u.lower().lstrip("@") for u, _ in usernames}:
                score += 10
                matched.append('mention')
            else:
                score += 30
                matched.append(hit)

        # Pais/contexto. Por país reconocido (también el gentilicio: "ecuatoriano"); antes era texto literal y con
        # País = "Otro" la palabra "otro" de cualquier frase sumaba puntos
        if seed.country and homonyms.mentions_country(text, seed.country):
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
        # La semilla exacta y los avisos: con esto y los informes de arriba, la ficha se rehace desde el caso
        db.save_profile_run(case_id, asdict(seed), dict(getattr(self, "warnings", {}) or {}))
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
            'warnings': dict(self.warnings),
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

    # Analizador estricto de perfiles (utils/identity): el dominio debe ser exactamente el de la plataforma.
    # Antes una expresión sin anclar encontraba "github.com/<algo>" dentro de cualquier URL y en la prueba real
    # con Kent C. Dodds lanzó la segunda ronda sobre el usuario inexistente "profiles" (197 resultados ajenos).
    for r in results:
        url = getattr(r, "url", "") if not isinstance(r, dict) else r.get("url", "")
        parsed = parse_profile_url(url) if url else None
        if not parsed:
            continue
        platform, handle, _canonical = parsed
        # Publicaciones (x.com/radio/status/…, tiktok.com/@radio/video/…): su autor suele ser OTRA cuenta que
        # menciona a la persona. LinkedIn: sus identificadores ("jorge-ulloa-chávez-7bab3a3b") no son usuarios
        # reutilizables en otras redes. Prueba real con Jorge Ulloa: se encadenaban una radio y otro Jorge Ulloa.
        if "/" in handle or platform not in _USERNAME_PLATFORMS or is_content_url(url):
            continue
        _add(handle)
    return found


# Fuentes ESTRUCTURADAS: la cuenta la vincula la propia persona (redes enlazadas en su GitHub) o una base con
# referencias (Wikidata). Un usuario que venga de ellas no necesita aparecer en más plataformas.
TRUSTED_LINK_SOURCES = {"Wikidata", "GitHubOSINT"}


def corroborated_usernames(results) -> List[str]:
    """Usuarios para la segunda ronda: los vistos en >= 2 plataformas distintas o dados por una fuente estructurada.

    Prueba real con Jorge Ulloa: el suyo ("jorgeulloaaa") salía en Instagram, Facebook y X; los de homónimos
    ("jorgemarioulloa", un colombiano; "jorgeulloa", otra persona en GitHub) aparecían UNA sola vez y arrastraban
    ~90 perfiles ajenos. Se ordenan por número de plataformas.
    """
    platforms: Dict[str, set] = {}
    trusted: set = set()
    order: List[str] = []
    for r in results:
        url = getattr(r, "url", "") if not isinstance(r, dict) else r.get("url", "")
        source = getattr(r, "source_tool", "") if not isinstance(r, dict) else r.get("source_tool", "")
        for handle in extract_usernames_from_results([{"url": url}]):
            key = handle.lower()
            if key not in platforms:
                platforms[key] = set()
                order.append(handle)
            platforms[key].add(parse_profile_url(url)[0])
            if str(source).split(":")[0] in TRUSTED_LINK_SOURCES:
                trusted.add(key)
    chosen = [h for h in order if len(platforms[h.lower()]) >= 2 or h.lower() in trusted]
    return sorted(chosen, key=lambda h: -len(platforms[h.lower()]))


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
