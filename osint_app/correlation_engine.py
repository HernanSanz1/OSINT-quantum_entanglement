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
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .db.feedback_db import db
from .core.models import TargetData, DataType


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
            return v.replace("www.", "")
        elif self.entity_type == "phone":
            return re.sub(r'[^\d+]', '', v)
        elif self.entity_type == "username":
            return v.lstrip("@")
        return v

    def fingerprint(self) -> str:
        """Hash único para deduplicación"""
        return hashlib.md5(f"{self.entity_type}:{self.normalized()}".encode()).hexdigest()[:12]


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
        "domain": r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
        "ip": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "phone": r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}',
        "username": r'@[a-zA-Z0-9_]{3,30}',
        "hash_md5": r'\b[a-fA-F0-9]{32}\b',
        "hash_sha256": r'\b[a-fA-F0-9]{64}\b',
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
                if entity_type == "domain":
                    # Ignorar extensiones de archivo
                    if value.endswith(('.png', '.jpg', '.gif', '.css', '.js', '.html')):
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

        return entities

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

    def __init__(self, case_id: int):
        self.case_id = case_id
        self.entities: Dict[str, Entity] = {}  # fingerprint -> Entity
        self.correlations: List[Correlation] = []
        self._load_existing()

    def _load_existing(self):
        """Carga entidades de datos existentes del caso"""
        target_data = db.get_target_data(self.case_id)
        for td in target_data:
            entity = Entity(
                entity_type=td.field_type,
                value=td.value,
                source=td.source,
                confidence=td.confidence
            )
            self.entities[entity.fingerprint()] = entity

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
        """Verifica si dos entidades están correlacionadas"""

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

        # Email contiene domain
        if a.entity_type == "email" and b.entity_type == "domain":
            if b.normalized() in a.normalized():
                return Correlation(
                    entity_a=a,
                    entity_b=b,
                    relation_type="owns",
                    confidence=85,
                    evidence=f"Email usa dominio: {a.value} -> {b.value}"
                )

        # Username similar a parte de email
        if a.entity_type == "email" and b.entity_type == "username":
            email_prefix = a.normalized().split("@")[0]
            username = b.normalized()
            if email_prefix == username or username in email_prefix:
                return Correlation(
                    entity_a=a,
                    entity_b=b,
                    relation_type="same_person",
                    confidence=75,
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

        return None

    def _persist_entity(self, entity: Entity):
        """Guarda entidad en la BD como TargetData"""
        td = TargetData(
            case_id=self.case_id,
            field_type=entity.entity_type,
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
                    all_entities.extend(EntityExtractor.extract_from_json(item, tool_name))
                elif isinstance(item, str):
                    all_entities.extend(EntityExtractor.extract(item, tool_name))
            return self.add_entities(all_entities)
        elif isinstance(data, dict):
            entities = EntityExtractor.extract_from_json(data, tool_name)
            return self.add_entities(entities)

        return 0

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
            "entities_by_type": dict(by_type),
            "top_correlations": [
                {
                    "a": c.entity_a.value,
                    "b": c.entity_b.value,
                    "type": c.relation_type,
                    "confidence": c.confidence,
                    "evidence": c.evidence
                }
                for c in sorted(self.correlations, key=lambda x: x.confidence, reverse=True)[:10]
            ]
        }

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

    def find_cross_correlations(self) -> List[Dict]:
        """Busca entidades compartidas entre casos"""
        # Índice invertido: fingerprint -> [(case_id, entity), ...]
        index = defaultdict(list)

        for case_id, engine in self.case_engines.items():
            for fp, entity in engine.entities.items():
                index[fp].append((case_id, entity))

        # Buscar fingerprints que aparecen en múltiples casos
        shared = []
        for fp, occurrences in index.items():
            if len(occurrences) > 1:
                shared.append({
                    "fingerprint": fp,
                    "entity_type": occurrences[0][1].entity_type,
                    "value": occurrences[0][1].value,
                    "cases": [case_id for case_id, _ in occurrences],
                    "sources": list(set(e.source for _, e in occurrences))
                })

        return sorted(shared, key=lambda x: len(x["cases"]), reverse=True)
