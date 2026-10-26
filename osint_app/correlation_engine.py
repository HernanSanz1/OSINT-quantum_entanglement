"""
SENTINEL - Motor de Correlación Automática

Ciclo de inteligencia:
1. Ingreso de datos semilla (nombre, email, dominio, etc.)
2. Ejecución automática de herramientas según tipo de dato
3. Extracción de entidades de resultados
4. Correlación con datos existentes
5. Scoring de coincidencias
6. Enriquecimiento progresivo del perfil

Basado en metodología de inteligencia militar:
- Collection (recolección de fuentes)
- Processing (normalización y limpieza)
- Analysis (correlación y patrones)
- Dissemination (reportes)
"""
import re
from urllib.parse import urlsplit
import json
import hashlib
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from itertools import combinations, product

from .db.feedback_db import db
from .core.models import TargetData
from .utils.entity_filters import (
    is_platform_domain,
    DOMAIN_PATTERN, FREEMAIL_DOMAINS, PHONE_PATTERN, ROLE_ACCOUNTS, is_code_handle, is_dns_txt_record,
    is_noise_domain, is_plausible_phone, is_public_ip, is_valid_email,
)
from .utils.identity import (
    find_profile_urls, handle_matches_name, name_from_profile_title, parse_profile_url, profile_key,
)
from .utils.person_match import name_match, normalize_text


@dataclass
class Entity:
    """Entidad extraída de datos raw"""
    entity_type: str  # email, domain, ip, username, phone, name, org
    value: str
    source: str  # tool name or manual
    confidence: int = 50
    metadata: Dict = field(default_factory=dict)

    def normalized(self) -> str:
        """Valor normalizado para comparación"""
        v = self.value.lower().strip()
        if self.entity_type == "email":
            return v
        elif self.entity_type == "domain":
            return v[4:] if v.startswith("www.") else v
        elif self.entity_type == "phone":
            return re.sub(r'[^\d+]', '', v)
        elif self.entity_type == "username":
            return v.lstrip("@")
        elif self.entity_type == "cve":
            return self.value.strip().upper()
        elif self.entity_type == "profile":
            return profile_key(self.value)
        elif self.entity_type in ("name", "company", "location"):
            return normalize_text(self.value)         # sin tildes ni mayúsculas: "José Muñoz" = "jose munoz"
        return v

    def fingerprint(self) -> str:
        """Hash único para deduplicación"""
        return hashlib.md5(f"{self.entity_type}:{self.normalized()}".encode(), usedforsecurity=False).hexdigest()[:12]


@dataclass
class Correlation:
    """Correlación entre dos entidades"""
    entity_a: Entity
    entity_b: Entity
    relation_type: str  # same_person, same_org, linked, owns, uses
    confidence: int
    evidence: str


class EntityExtractor:
    """Extrae entidades de texto raw"""

    # Patrones regex
    PATTERNS = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "domain": DOMAIN_PATTERN,
        "ip": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "phone": PHONE_PATTERN,
        "username": r'(?<![a-zA-Z0-9._%+-])@[a-zA-Z0-9_]{3,30}(?![a-zA-Z0-9_-])',   # no el "@dominio" de un email, ni "@epicweb" de "@epicweb-dev"
        "hash_md5": r'\b[a-fA-F0-9]{32}\b',
        "hash_sha256": r'\b[a-fA-F0-9]{64}\b',
        "cve": r'[Cc][Vv][Ee]-\d{4}-\d{4,7}',   # para cruzar con el CTI
    }

    @classmethod
    def extract(cls, text: str, source: str = "unknown") -> List[Entity]:
        """Extrae todas las entidades de un texto"""
        entities = []
        seen = set()

        for entity_type, pattern in cls.PATTERNS.items():
            for match in re.finditer(pattern, text):
                value = match.group()

                # Filtrar falsos positivos
                if entity_type == "phone" and not is_plausible_phone(value):
                    continue
                if entity_type == "email" and not is_valid_email(value):
                    continue
                if entity_type == "ip" and not is_public_ip(value):
                    continue
                if entity_type == "username" and is_code_handle(value):
                    continue
                if entity_type == "domain":
                    # Ignorar nombres de archivo, extensiones inexistentes e infraestructura de las herramientas
                    if is_noise_domain(value):
                        continue
                    # Ignorar si ya se capturó como email
                    if any(value in e.value for e in entities if e.entity_type == "email"):
                        continue

                entity = Entity(
                    entity_type=entity_type,
                    value=value,
                    source=source
                )

                fp = entity.fingerprint()
                if fp not in seen:
                    seen.add(fp)
                    entities.append(entity)

        for platform, handle, canonical in find_profile_urls(text):
            entity = Entity("profile", canonical, source, confidence=60, metadata={"platform": platform, "handle": handle})
            fp = entity.fingerprint()
            if fp not in seen:
                seen.add(fp)
                entities.append(entity)

        return entities

    @classmethod
    def extract_identity(cls, item: Dict, source: str = "unknown") -> List[Entity]:
        """Nombre, empresa y ubicación de una persona a partir de un resultado ESTRUCTURADO (perfil).

        No se adivina nada del texto libre: solo de campos que la herramienta entregó como datos
        (GitHub) o del título de una página de perfil reconocida (LinkedIn, X, Instagram…).
        """
        found: List[Entity] = []
        extra = item.get("extra_data") if isinstance(item.get("extra_data"), dict) else {}
        # Variantes de usuario que la herramienta ya marcó como de OTRA persona o sin confirmar (GitHub Match < 70)
        if item.get("category") == "GitHub Match" and (item.get("relevance_score") or 0) < 70:
            return []
        if extra.get("official_site"):
            host = (urlsplit(item.get("url") or "").hostname or "").lower()
            if host.startswith("www."):
                host = host[4:]
            if host:
                found.append(Entity("domain", host, source, confidence=75))
        parsed = parse_profile_url(item.get("url") or "")
        canonical = parsed[2] if parsed else ""
        origin = f"{source} @ {canonical}" if canonical else source

        if parsed:
            found.append(Entity("profile", canonical, source, confidence=60,
                                metadata={"platform": parsed[0], "handle": parsed[1]}))
            name = (extra.get("name") or "").strip() or name_from_profile_title(item.get("title", ""), parsed[0], parsed[1])
            if name:
                found.append(Entity("name", name, origin, confidence=60))
            if extra.get("company"):
                found.append(Entity("company", str(extra["company"]).strip().lstrip("@"), origin, confidence=55))
            if extra.get("location"):
                found.append(Entity("location", str(extra["location"]).strip(), origin, confidence=50))
        twitter = str(extra.get("twitter") or "").lstrip("@")
        if twitter:
            tw = parse_profile_url(f"https://x.com/{twitter}")
            if tw:
                found.append(Entity("profile", tw[2], source, confidence=60, metadata={"platform": "x", "handle": tw[1]}))
        return [e for e in found if e.value]

    @classmethod
    def extract_from_json(cls, data: Dict, source: str = "unknown") -> List[Entity]:
        """Extrae entidades de un dict JSON recursivamente"""
        text_parts = []

        def recurse(obj):
            if isinstance(obj, str):
                text_parts.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    recurse(v)
            elif isinstance(obj, list):
                for item in obj:
                    recurse(item)

        recurse(data)
        return cls.extract(" ".join(text_parts), source)


_IMAGE_KEYS = ("image", "avatar", "photo", "picture", "thumbnail", "icon")


def _without_location_noise(item: Dict) -> Dict:
    """El resultado sin su URL (dice DÓNDE se encontró: tiktok.com, wikipedia.org…) ni URLs de imágenes (CDN).

    Antes cada plataforma y cada CDN de avatares salía como "dominio" del objetivo (27 en un caso real) y eso
    disparaba sugerencias absurdas como Subfinder. La URL se sigue usando para reconocer el perfil.
    """
    clean = {k: v for k, v in item.items() if k != "url"}
    for key in ("extra_data", "raw_data"):
        inner = clean.get(key)
        if isinstance(inner, dict):
            clean[key] = {k: v for k, v in inner.items()
                          if k.lower() != "url" and not any(w in k.lower() for w in _IMAGE_KEYS)}
    return clean


class CorrelationEngine:
    """Motor de correlación automática para un caso"""

    # Pesos de correlación por tipo
    CORRELATION_WEIGHTS = {
        ("email", "domain"): 0.9,      # email@domain -> alta correlación
        ("email", "username"): 0.7,    # mismo prefijo de email y username
        ("username", "username"): 0.95, # mismo username en diferentes plataformas
        ("name", "email"): 0.6,        # nombre en email
        ("domain", "ip"): 0.8,         # resolución DNS
        ("phone", "phone"): 0.95,      # mismo teléfono
    }

    # Pares de tipos que se comparan (un solo tipo = entidades del mismo tipo entre sí)
    CORRELATED_TYPES = (
        ("email", "domain"), ("email", "username"), ("domain",),
        ("profile",), ("profile", "username"), ("profile", "email"), ("profile", "name"),
        ("name",), ("name", "email"), ("name", "username"),
    )

    # Tipos de identidad: lo que se descubre se guarda aparte ("found_…") para que un nombre hallado en el
    # perfil de un homónimo nunca sustituya al nombre que puso el investigador al lanzar otras herramientas.
    IDENTITY_TYPES = ("profile", "name", "company", "location")

    def __init__(self, case_id: int):
        self.case_id = case_id
        self.entities: Dict[str, Entity] = {}  # fingerprint -> Entity
        self.correlations: List[Correlation] = []
        self._load_existing()
        self._recompute_correlations()

    def _load_existing(self):
        """Carga entidades de datos existentes del caso"""
        target_data = db.get_target_data(self.case_id)
        # Nombre(s) del objetivo dados por el analista: sirven para no atribuirle lo que habla de otra persona
        self.target_names = [td.value for td in target_data if (td.field_type or "").lower() == "name" and td.source == "seed" and td.value]
        for td in target_data:
            # La pestaña Datos guarda "DOMAIN" o "IP" y el resto del programa "domain" o "ip": sin pasarlo a
            # minúsculas, lo que el analista metía a mano no se relacionaba con nada (visto en el caso real #23)
            field_type = (td.field_type or "").lower()
            found = field_type.startswith("found_")
            entity = Entity(
                entity_type=field_type[len("found_"):] if found else field_type,
                value=td.value,
                source=td.source,
                confidence=td.confidence
            )
            self.entities[entity.fingerprint()] = entity

    def _recompute_correlations(self) -> None:
        """Calcula las correlaciones entre TODAS las entidades del caso (también entre datos semilla)."""
        buckets: Dict[str, List[Entity]] = defaultdict(list)
        for entity in self.entities.values():
            buckets[entity.entity_type].append(entity)
        self.correlations = []
        for types in self.CORRELATED_TYPES:
            if len(types) == 1:
                pairs = combinations(buckets[types[0]], 2)
            else:
                pairs = product(buckets[types[0]], buckets[types[1]])
            for a, b in pairs:
                correlation = self._check_correlation(a, b)
                if correlation:
                    self.correlations.append(correlation)

    def add_entity(self, entity: Entity) -> bool:
        """Agrega entidad y busca correlaciones"""
        fp = entity.fingerprint()
        if fp in self.entities:
            # Ya existe, aumentar confianza si viene de otra fuente
            existing = self.entities[fp]
            if existing.source != entity.source:
                existing.confidence = min(100, existing.confidence + 10)
            return False

        self.entities[fp] = entity

        # Buscar correlaciones con entidades existentes
        self._find_correlations(entity)

        # Persistir en BD
        self._persist_entity(entity)

        return True

    def add_entities(self, entities: List[Entity]) -> int:
        """Agrega múltiples entidades, retorna cantidad de nuevas"""
        added = 0
        for e in entities:
            if self.add_entity(e):
                added += 1
        return added

    def _find_correlations(self, new_entity: Entity):
        """Busca correlaciones entre nueva entidad y existentes"""
        for fp, existing in self.entities.items():
            if fp == new_entity.fingerprint():
                continue

            correlation = self._check_correlation(new_entity, existing)
            if correlation:
                self.correlations.append(correlation)

    def _check_correlation(self, a: Entity, b: Entity) -> Optional[Correlation]:
        """Verifica si dos entidades están correlacionadas, sin importar el orden en que se pasen."""
        return self._check_ordered(a, b) or self._check_ordered(b, a)

    def _check_ordered(self, a: Entity, b: Entity) -> Optional[Correlation]:

        # Mismo tipo, mismo valor normalizado -> misma entidad
        if a.entity_type == b.entity_type:
            if a.normalized() == b.normalized():
                return Correlation(
                    entity_a=a,
                    entity_b=b,
                    relation_type="same_entity",
                    confidence=95,
                    evidence=f"Valor idéntico: {a.value}"
                )

        # Email usa un dominio (exacto o subdominio; los proveedores gratuitos no cuentan)
        if a.entity_type == "email" and b.entity_type == "domain":
            email_domain = a.normalized().rsplit("@", 1)[-1]
            target = b.normalized()
            if email_domain not in FREEMAIL_DOMAINS and (email_domain == target or email_domain.endswith("." + target)):
                return Correlation(
                    entity_a=a,
                    entity_b=b,
                    relation_type="owns",
                    confidence=85,
                    evidence=f"Email usa dominio: {a.value} -> {b.value}"
                )

        # Username igual (o casi) a la parte local del correo. Se ignoran los buzones de rol
        # (admin, info…) y los usuarios cortos, que coinciden por casualidad.
        if a.entity_type == "email" and b.entity_type == "username":
            email_prefix = a.normalized().split("@")[0].split("+")[0]
            username = b.normalized()
            if email_prefix not in ROLE_ACCOUNTS and username not in ROLE_ACCOUNTS and len(username) >= 3:
                if email_prefix == username:
                    confidence = 75
                elif len(username) >= 5 and username in email_prefix and len(username) / len(email_prefix) >= 0.5:
                    confidence = 55
                else:
                    confidence = 0
                if confidence:
                    return Correlation(
                        entity_a=a,
                        entity_b=b,
                        relation_type="same_person",
                        confidence=confidence,
                        evidence=f"Username coincide con email: {username} ~ {email_prefix}"
                    )

        # Dominio y subdominio
        if a.entity_type == "domain" and b.entity_type == "domain":
            if a.normalized().endswith("." + b.normalized()):
                return Correlation(
                    entity_a=a,
                    entity_b=b,
                    relation_type="subdomain_of",
                    confidence=90,
                    evidence=f"Subdominio: {a.value} de {b.value}"
                )

        return self._check_identity(a, b)

    def _check_identity(self, a: Entity, b: Entity) -> Optional[Correlation]:
        """Relaciones entre perfiles sociales, nombres, usuarios y correos de una persona."""
        pair = (a.entity_type, b.entity_type)

        if pair == ("profile", "profile"):
            pa, pb = parse_profile_url(a.value), parse_profile_url(b.value)
            if pa and pb and pa[1] == pb[1] and pa[0] != pb[0] and len(pa[1]) >= 4:
                return Correlation(a, b, "same_handle", 70 if len(pa[1]) >= 6 else 45,
                                   f"Mismo usuario «{pa[1]}» en {pa[0]} y {pb[0]}")

        elif pair == ("profile", "username"):
            parsed = parse_profile_url(a.value)
            user = b.normalized()
            if parsed and len(user) >= 3 and parsed[1] == user:
                return Correlation(a, b, "profile_of", 90, f"El perfil de {parsed[0]} usa el usuario {b.value}")

        elif pair == ("profile", "email"):
            parsed = parse_profile_url(a.value)
            local = b.normalized().split("@")[0].split("+")[0]
            if parsed and len(local) >= 5 and local not in ROLE_ACCOUNTS and parsed[1] == local:
                return Correlation(a, b, "same_person", 60, f"El usuario de {parsed[0]} coincide con el correo {b.value}")

        elif pair == ("profile", "name"):
            origin = b.source.split(" @ ", 1)[1] if " @ " in b.source else ""
            if origin and profile_key(origin) == a.normalized():
                return Correlation(a, b, "named_in", 85, f"El nombre «{b.value}» aparece en ese perfil")

        elif pair == ("name", "name"):
            if a.normalized() != b.normalized():
                short, long_ = sorted((a, b), key=lambda e: len(e.normalized()))
                points, kind = name_match(short.value, long_.value)
                if kind == "name":
                    return Correlation(a, b, "same_name", 60, f"«{short.value}» está contenido en «{long_.value}»")

        elif pair == ("name", "email"):
            local = b.normalized().split("@")[0]
            if local not in ROLE_ACCOUNTS and handle_matches_name(local, a.value):
                return Correlation(a, b, "name_in_handle", 65, f"El correo {b.value} sigue el patrón del nombre {a.value}")

        elif pair == ("name", "username"):
            if handle_matches_name(b.normalized(), a.value):
                return Correlation(a, b, "name_in_handle", 55, f"El usuario {b.value} sigue el patrón del nombre {a.value}")

        return None

    def _persist_entity(self, entity: Entity):
        """Guarda entidad en la BD como TargetData"""
        td = TargetData(
            case_id=self.case_id,
            field_type=f"found_{entity.entity_type}" if entity.entity_type in self.IDENTITY_TYPES else entity.entity_type,
            value=entity.value,
            source=entity.source,
            confidence=entity.confidence
        )
        db.add_target_data(td)

    def process_tool_results(self, tool_name: str, raw_json: str) -> int:
        """Procesa resultados de una herramienta y extrae entidades"""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            # Tratar como texto plano
            entities = EntityExtractor.extract(raw_json, tool_name)
            return self.add_entities(entities)

        if isinstance(data, list):
            all_entities = []
            for item in data:
                if isinstance(item, dict):
                    # La URL del resultado dice DÓNDE se encontró (tiktok.com, wikipedia.org…), no es un dato de la
                    # persona: se usa solo para reconocer el perfil (extract_identity). Antes cada plataforma salía
                    # como "dominio" del objetivo (27 en un caso real) y disparaba sugerencias como Subfinder.
                    if not self._mentions_target(tool_name, item):
                        continue
                    found = EntityExtractor.extract_from_json(_without_location_noise(item), tool_name)
                    found = [e for e in found if not (e.entity_type == "domain" and self._is_foreign_platform(e.value))]
                    found += EntityExtractor.extract_identity(item, tool_name)
                    if is_dns_txt_record(item.get("title")):     # token de verificación, no un hash
                        found = [e for e in found if not e.entity_type.startswith("hash_")]
                    all_entities.extend(found)
                elif isinstance(item, str):
                    all_entities.extend(EntityExtractor.extract(item, tool_name))
            return self.add_entities(all_entities)
        elif isinstance(data, dict):
            entities = EntityExtractor.extract_from_json(data, tool_name)
            return self.add_entities(entities)

        return 0

    # Herramientas que devuelven MENCIONES (cualquier página que coincida con la búsqueda), no datos de la persona
    MENTION_TOOLS = ("WebSearch", "Google Dorks")

    def _mentions_target(self, tool_name: str, item: Dict) -> bool:
        """En resultados de búsqueda, exige que el texto nombre al objetivo (nombre de pila + un apellido).

        Caso real: '"Jefferson Pérez Quezada" site:github.com' devolvía cuentas de otros "Jefferson" y la
        correlación las atribuía al objetivo como perfiles suyos.
        """
        if not self.target_names or tool_name.split(":")[0] not in self.MENTION_TOOLS:
            return True
        text = f"{item.get('title', '')} {item.get('snippet', '')}"
        return max(name_match(n, text)[0] for n in self.target_names) >= 25

    def _is_foreign_platform(self, domain: str) -> bool:
        """Una plataforma (youtube.com, github.com…) no es dominio del objetivo, salvo que el caso la investigue."""
        if not is_platform_domain(domain):
            return False
        seeds = {e.value.lower() for e in self.entities.values() if e.entity_type == "domain" and e.source == "seed"}
        d = domain.lower()
        return not any(d == s or d.endswith("." + s) for s in seeds)

    def get_profile_summary(self) -> Dict:
        """Genera resumen del perfil correlacionado"""
        by_type = defaultdict(list)
        for entity in self.entities.values():
            by_type[entity.entity_type].append({
                "value": entity.value,
                "source": entity.source,
                "confidence": entity.confidence
            })

        return {
            "case_id": self.case_id,
            "total_entities": len(self.entities),
            "total_correlations": len(self.correlations),
            "correlations": self._correlations_as_dicts(),
            "entities_by_type": dict(by_type),
            "top_correlations": self._correlations_as_dicts()[:10],
        }

    def _correlations_as_dicts(self) -> List[Dict]:
        ordered = sorted(self.correlations, key=lambda x: x.confidence, reverse=True)
        return [
            {"a": c.entity_a.value, "b": c.entity_b.value, "type": c.relation_type,
             "confidence": c.confidence, "evidence": c.evidence}
            for c in ordered
        ]

    def suggest_tools(self) -> List[Tuple[str, str]]:
        """Sugiere herramientas a ejecutar según los datos disponibles"""
        suggestions = []
        types_present = set(e.entity_type for e in self.entities.values())

        if "email" in types_present:
            suggestions.append(("Holehe", "Verificar email en servicios"))
            suggestions.append(("Hunter.io", "Buscar emails relacionados"))

        if "username" in types_present:
            suggestions.append(("Sherlock", "Buscar username en +300 sitios"))
            suggestions.append(("Maigret", "Búsqueda profunda de username"))

        if "domain" in types_present:
            suggestions.append(("Subfinder", "Enumerar subdominios"))
            suggestions.append(("TheHarvester", "Recolectar emails y hosts"))
            suggestions.append(("Wayback", "Histórico del dominio"))

        if "ip" in types_present:
            suggestions.append(("IPWhois", "Información de IP/ASN"))
            suggestions.append(("Censys", "Certificados y servicios"))

        if not types_present:
            suggestions.append(("Google Dorks", "Búsqueda inicial"))

        return suggestions

    def correlate_with_cti(self, store=None, tech_terms: List[str] = None) -> Dict:
        """Cruza las entidades del caso con la inteligencia de amenazas (CTI).

        Si no se pasa `store`, lo carga del almacén CTI por defecto. Devuelve
        las coincidencias por CVE y por tecnología (ver cti_link) y, en "targets", las del propio objetivo: víctima
        de ransomware, menciones en noticias e IP como indicador (ver cti_match).
        """
        from .cti_link import CtiStore, correlate_entities_with_cti
        from .cti_match import correlate_targets_with_cti, target_identifiers
        if store is None:
            store = CtiStore.load()
        result = correlate_entities_with_cti(self.entities.values(), store, tech_terms)
        ids = target_identifiers(db.get_target_data(self.case_id))
        result["targets"] = correlate_targets_with_cti(ids, store.items)
        return result

    def auto_enrich(self, max_tools: int = 3) -> List[str]:
        """
        Ejecuta herramientas automáticamente para enriquecer el perfil.
        Retorna lista de herramientas ejecutadas.
        """
        # Esta función sería llamada por el framework para auto-ejecutar
        # Por ahora retorna las sugerencias
        suggestions = self.suggest_tools()
        return [tool for tool, _ in suggestions[:max_tools]]


class CrossCaseCorrelator:
    """Busca correlaciones entre diferentes casos"""

    def __init__(self):
        self.case_engines: Dict[int, CorrelationEngine] = {}

    def load_case(self, case_id: int):
        """Carga un caso en el correlador"""
        if case_id not in self.case_engines:
            self.case_engines[case_id] = CorrelationEngine(case_id)

    # Datos que comparten muchísimas personas: que dos casos digan "Ecuador" o "futbolista" no los relaciona.
    # Prueba de usuario real (2026-10-13): "country: Ecuador" unía a Jefferson Pérez con casos de otras personas.
    NON_IDENTIFYING_TYPES = {"country", "context", "location", "city", "note", "university"}

    def find_cross_correlations(self, focus_case: Optional[int] = None) -> List[Dict]:
        """Busca entidades que identifican a alguien (correo, usuario, teléfono, dominio…) compartidas entre casos.

        Con `focus_case`, solo las que comparte ese caso con otros (el caso activo).
        """
        # Índice invertido: fingerprint -> [(case_id, entity), ...]
        index = defaultdict(list)

        for case_id, engine in self.case_engines.items():
            for fp, entity in engine.entities.items():
                if entity.entity_type.lower() in self.NON_IDENTIFYING_TYPES:
                    continue
                index[fp].append((case_id, entity))

        # Buscar fingerprints que aparecen en múltiples casos
        shared = []
        for fp, occurrences in index.items():
            if focus_case is not None and focus_case not in {case_id for case_id, _ in occurrences}:
                continue
            if len({case_id for case_id, _ in occurrences}) > 1:
                shared.append({
                    "fingerprint": fp,
                    "entity_type": occurrences[0][1].entity_type,
                    "value": occurrences[0][1].value,
                    "cases": [case_id for case_id, _ in occurrences],
                    "sources": list(set(e.source for _, e in occurrences))
                })

        return sorted(shared, key=lambda x: len(x["cases"]), reverse=True)
