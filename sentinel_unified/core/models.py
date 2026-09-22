"""
Sentinel Unified - Data Models
Personas, Infraestructura, IOCs y Correlaciones
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
from datetime import datetime


class CaseType(Enum):
    PROFILE = "profile"      # Perfilamiento de persona
    RECON = "recon"          # Reconocimiento de infra
    CTI = "cti"              # Threat Intelligence
    MIXED = "mixed"          # Combinado


class CaseStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class TargetFieldType(Enum):
    NAME = "name"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    PHOTO = "photo"
    LOCATION = "location"
    COMPANY = "company"
    SOCIAL = "social"
    NOTE = "note"


class AssetType(Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    URL = "url"
    PORT = "port"
    TECH = "technology"


class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    CVE = "cve"
    EMAIL = "email"


class RelationType(Enum):
    OWNS = "owns"                    # persona owns email/domain
    WORKS_AT = "works_at"            # persona works_at company
    USES = "uses"                    # persona uses username
    RESOLVES_TO = "resolves_to"      # domain resolves_to IP
    CONTAINS = "contains"            # domain contains subdomain
    HOSTS = "hosts"                  # IP hosts domain
    LINKED_TO = "linked_to"          # generic relation
    EXPOSED_BY = "exposed_by"        # asset exposed_by CVE
    ATTRIBUTED_TO = "attributed_to"  # IOC attributed_to actor


@dataclass
class Case:
    name: str
    description: str = ""
    case_type: CaseType = CaseType.MIXED
    status: CaseStatus = CaseStatus.OPEN
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "case_type": self.case_type.value,
            "status": self.status.value,
            "created_at": self.created_at,
        }


@dataclass
class Target:
    """Persona objetivo de investigacion"""
    case_id: int
    name: str
    email: str = ""
    phone: str = ""
    username: str = ""
    photo_url: str = ""
    location: str = ""
    company: str = ""
    social_profiles: str = ""  # JSON string
    notes: str = ""
    confidence: int = 50
    source: str = "manual"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "username": self.username,
            "photo_url": self.photo_url,
            "location": self.location,
            "company": self.company,
            "social_profiles": self.social_profiles,
            "notes": self.notes,
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass
class Asset:
    """Activo de infraestructura"""
    case_id: int
    asset_type: str  # AssetType value
    value: str
    source_tool: str = "manual"
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = ""
    metadata: str = ""  # JSON string for extra data
    confidence: int = 50
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "asset_type": self.asset_type,
            "value": self.value,
            "source_tool": self.source_tool,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "metadata": self.metadata,
            "confidence": self.confidence,
        }


@dataclass
class IOC:
    """Indicador de Compromiso"""
    case_id: int
    ioc_type: str  # IOCType value
    value: str
    source: str = "manual"
    confidence: int = 50
    tags: str = ""  # comma-separated
    description: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = ""
    is_malicious: bool = False
    severity: int = 0  # 0-10
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "tags": self.tags,
            "description": self.description,
            "is_malicious": self.is_malicious,
            "severity": self.severity,
        }


@dataclass
class Correlation:
    """Relacion entre entidades (para el grafo)"""
    source_type: str  # 'target', 'asset', 'ioc'
    source_id: int
    target_type: str
    target_id: int
    relation_type: str  # RelationType value
    confidence: int = 50
    case_id: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "relation_type": self.relation_type,
            "confidence": self.confidence,
        }


@dataclass
class ToolReport:
    """Resultado de ejecucion de herramienta"""
    case_id: int
    module: str  # 'profile', 'recon', 'cti'
    tool_name: str
    raw_json: str = "[]"
    summary: str = ""
    status: str = "ok"  # ok, error, partial
    execution_time: float = 0.0
    results_count: int = 0
    run_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "module": self.module,
            "tool_name": self.tool_name,
            "summary": self.summary,
            "status": self.status,
            "execution_time": self.execution_time,
            "results_count": self.results_count,
            "run_at": self.run_at,
        }
