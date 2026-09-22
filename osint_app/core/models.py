"""
OSINT App v2 — Core Data Models
All entities: Case, TargetData, ToolReport, ToolRequirements, CompatibilityResult
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
from datetime import datetime


# ── Enums ────────────────────────────────────────────────────────────────────

class CompatibilityStatus(Enum):
    GREEN  = "GREEN"    # All mandatory fields present
    YELLOW = "YELLOW"   # Mandatory present, some optional missing
    RED    = "RED"      # Missing mandatory fields — cannot run


class CaseStatus(Enum):
    OPEN   = "open"
    CLOSED = "closed"


class DataType(Enum):
    """All supported target data field types."""
    NAME      = "name"
    EMAIL     = "email"
    PHONE     = "phone"
    DOMAIN    = "domain"
    IP        = "ip"
    USERNAME  = "username"
    URL       = "url"
    COMPANY   = "company"
    HASH      = "hash"
    LOCATION  = "location"
    NOTE      = "note"
    OBSERVABLE = "observable"   # Generic for threat intel tools


# ── Case ─────────────────────────────────────────────────────────────────────

@dataclass
class Case:
    name: str
    description: str = ""
    status: CaseStatus = CaseStatus.OPEN
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "created_at": self.created_at,
        }


# ── TargetData ────────────────────────────────────────────────────────────────

@dataclass
class TargetData:
    """A single piece of data about the OSINT target."""
    case_id: int
    field_type: str          # DataType value
    value: str
    source: str = "manual"   # manual | tool:<tool_name>
    confidence: int = 50     # 0-100
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "case_id": self.case_id,
            "field_type": self.field_type, "value": self.value,
            "source": self.source, "confidence": self.confidence,
            "created_at": self.created_at,
        }


# ── ToolReport ────────────────────────────────────────────────────────────────

@dataclass
class ToolReport:
    """Result of a single tool execution within a case."""
    case_id: int
    tool_name: str
    raw_json: str   # JSON-serialized list of SearchResult
    summary: str = ""
    status: str = "ok"    # ok | error | partial
    execution_time: float = 0.0
    results_count: int = 0
    run_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "case_id": self.case_id,
            "tool_name": self.tool_name, "summary": self.summary,
            "status": self.status, "execution_time": self.execution_time,
            "results_count": self.results_count, "run_at": self.run_at,
        }


# ── SearchResult ──────────────────────────────────────────────────────────────

@dataclass
class SearchResult:
    """Standardized result from any OSINT tool."""
    title: str
    url: str
    snippet: str
    source_tool: str
    relevance_score: int = 0
    category: str = "General"
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "title": self.title, "url": self.url, "snippet": self.snippet,
            "source_tool": self.source_tool, "relevance_score": self.relevance_score,
            "category": self.category,
        }


# ── QueryParameters ───────────────────────────────────────────────────────────

@dataclass
class QueryParameters:
    """Auto-built from Case TargetData by DataCompatibilityEngine."""
    target_name: str = ""
    email: str = ""
    domain: str = ""
    company: str = ""
    role: str = ""
    location: str = ""
    phone: str = ""
    username: str = ""
    ip: str = ""
    url: str = ""
    hash_value: str = ""
    observable: str = ""
    university: str = ""
    keywords: List[str] = field(default_factory=list)
    extra_args: str = ""

    @classmethod
    def from_target_data(cls, data: List[TargetData], extra_args: str = "") -> "QueryParameters":
        """Build query params from the most confident value per field type."""
        by_type: Dict[str, List[TargetData]] = {}
        for d in data:
            ft = d.field_type.lower()
            by_type.setdefault(ft, []).append(d)
        def best(ft: str) -> str:
            items = by_type.get(ft, [])
            if not items: return ""
            
            def heuristic_score(td: TargetData) -> int:
                score = td.confidence * 100
                v = td.value.lower()
                # Prioritize valid usernames (no spaces)
                if ft == "username" and " " not in v: score += 50
                # Prioritize personal emails over generic info@ domains
                if ft == "email" and ("gmail" in v or "hotmail" in v or "yahoo" in v): score += 50
                # Longer text is usually richer for notes
                if ft == "note": score += len(v)
                return score
                
            return max(items, key=heuristic_score).value
            
        def all_vals(ft: str) -> List[str]:
            return [d.value for d in by_type.get(ft, [])]
        return cls(
            target_name=best("name"),
            email=best("email"),
            domain=best("domain"),
            company=best("company"),
            role=best("note"),
            location=best("location"),
            phone=best("phone"),
            username=best("username"),
            ip=best("ip"),
            url=best("url"),
            hash_value=best("hash"),
            observable=best("observable"),
            university=best("university"),
            keywords=all_vals("note"),
            extra_args=extra_args
        )

    def to_dict(self) -> Dict:
        return {
            "target_name": self.target_name, "email": self.email,
            "domain": self.domain, "company": self.company, "role": self.role,
            "location": self.location, "phone": self.phone, "username": self.username,
            "ip": self.ip, "url": self.url, "hash_value": self.hash_value,
            "observable": self.observable, "university": self.university, "keywords": self.keywords,
        }


# ── ToolRequirements ──────────────────────────────────────────────────────────

@dataclass
class ToolRequirements:
    mandatory: List[str]      # QueryParameters field names required to run
    optional: List[str]       # Fields that expand scope if present
    produces: List[str]       # DataType values this tool generates
    hint: str = ""            # User-facing message explaining what's needed

    def how_to_get(self) -> Dict[str, str]:
        """Suggested sources for each mandatory field."""
        SOURCES = {
            "domain":      "Ingresa el dominio manualmente o corre TheHarvester/GoogleDorks",
            "email":       "Ingresa el email manualmente o extráelo de Google Dorks",
            "username":    "Ingresa el username o extráelo de Google Dorks/Sherlock",
            "ip":          "Ingresa la IP o extráela de CENSYS/Subfinder/dnspython",
            "target_name": "Ingresa el nombre completo del objetivo manualmente",
            "url":         "Ingresa la URL o extráela de Google Dorks",
            "phone":       "Ingresa el teléfono manualmente",
            "hash_value":  "Ingresa el hash manualmente o extráelo de un análisis de malware",
            "observable":  "Cualquier dato disponible: IP, dominio, nombre o hash",
        }
        return {f: SOURCES.get(f, "Ingresa manualmente") for f in self.mandatory}


# ── CompatibilityResult ───────────────────────────────────────────────────────

@dataclass
class CompatibilityResult:
    status: CompatibilityStatus
    available: List[str]                    # fields that are present
    missing_mandatory: List[str]            # blocks execution
    missing_optional: List[str]             # reduces scope
    auto_params: QueryParameters = field(default_factory=QueryParameters)
    hint: str = ""
    missing_hints: Dict[str, str] = field(default_factory=dict)

    @property
    def can_run(self) -> bool:
        return self.status != CompatibilityStatus.RED

    def user_message(self) -> str:
        if self.status == CompatibilityStatus.GREEN:
            return f"✅ Listo para ejecutar con: {', '.join(self.available)}"
        if self.status == CompatibilityStatus.YELLOW:
            msgs = [f"⚠️  Scope reducido — faltan (opcionales): {', '.join(self.missing_optional)}"]
            for f, h in self.missing_hints.items():
                if f in self.missing_optional:
                    msgs.append(f"   • {f}: {h}")
            return "\n".join(msgs)
        # RED
        msgs = [f"⛔ No se puede ejecutar — faltan datos obligatorios: {', '.join(self.missing_mandatory)}"]
        for f, h in self.missing_hints.items():
            msgs.append(f"   • {f}: {h}")
        return "\n".join(msgs)


# ── AICorrelation ─────────────────────────────────────────────────────────────

@dataclass
class AICorrelation:
    case_id: int
    report_ids: List[int]
    prompt: str
    response: str
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    id: Optional[int] = None
