"""
Sentinel Unified - SQLite Database
Schema unificado para Profile, Recon y CTI
"""
import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

from .models import (
    Case, Target, Asset, IOC, Correlation, ToolReport,
    CaseType, CaseStatus
)

logger = logging.getLogger(__name__)
DB_PATH = Path(__file__).parent.parent / "store" / "sentinel.db"


class Database:
    """Base de datos unificada para Sentinel"""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = str(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self):
        with sqlite3.connect(self.db_path) as c:
            c.executescript("""
                -- Casos
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    case_type TEXT DEFAULT 'mixed',
                    status TEXT DEFAULT 'open',
                    created_at TEXT
                );

                -- Targets (Personas)
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    email TEXT DEFAULT '',
                    phone TEXT DEFAULT '',
                    username TEXT DEFAULT '',
                    photo_url TEXT DEFAULT '',
                    location TEXT DEFAULT '',
                    company TEXT DEFAULT '',
                    social_profiles TEXT DEFAULT '{}',
                    notes TEXT DEFAULT '',
                    confidence INTEGER DEFAULT 50,
                    source TEXT DEFAULT 'manual',
                    created_at TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                -- Assets (Infraestructura)
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    asset_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source_tool TEXT DEFAULT 'manual',
                    first_seen TEXT,
                    last_seen TEXT DEFAULT '',
                    metadata TEXT DEFAULT '{}',
                    confidence INTEGER DEFAULT 50,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                -- IOCs (Indicadores de Compromiso)
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT DEFAULT 'manual',
                    confidence INTEGER DEFAULT 50,
                    tags TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    first_seen TEXT,
                    last_seen TEXT DEFAULT '',
                    is_malicious INTEGER DEFAULT 0,
                    severity INTEGER DEFAULT 0,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                -- Correlations (Grafo)
                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    source_id INTEGER NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id INTEGER NOT NULL,
                    relation_type TEXT NOT NULL,
                    confidence INTEGER DEFAULT 50,
                    created_at TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                -- Tool Reports
                CREATE TABLE IF NOT EXISTS tool_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    module TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    raw_json TEXT DEFAULT '[]',
                    summary TEXT DEFAULT '',
                    status TEXT DEFAULT 'ok',
                    execution_time REAL DEFAULT 0,
                    results_count INTEGER DEFAULT 0,
                    run_at TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                -- CTI Items (feeds raw)
                CREATE TABLE IF NOT EXISTS cti_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    title TEXT NOT NULL,
                    link TEXT DEFAULT '',
                    published TEXT,
                    summary TEXT DEFAULT '',
                    tags TEXT DEFAULT '',
                    cves TEXT DEFAULT '',
                    raw_json TEXT DEFAULT '{}',
                    harvested_at TEXT
                );

                -- CTI Dossiers
                CREATE TABLE IF NOT EXISTS cti_dossiers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    period_type TEXT DEFAULT 'daily',
                    period_start TEXT,
                    period_end TEXT,
                    client TEXT DEFAULT '',
                    items_json TEXT DEFAULT '[]',
                    html_path TEXT DEFAULT '',
                    status TEXT DEFAULT 'draft',
                    created_at TEXT
                );

                -- Indices
                CREATE INDEX IF NOT EXISTS idx_targets_case ON targets(case_id);
                CREATE INDEX IF NOT EXISTS idx_assets_case ON assets(case_id);
                CREATE INDEX IF NOT EXISTS idx_iocs_case ON iocs(case_id);
                CREATE INDEX IF NOT EXISTS idx_correlations_case ON correlations(case_id);
                CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);
                CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
            """)

    # ══════════════════════════════════════════════════════════════════════════
    # CASES
    # ══════════════════════════════════════════════════════════════════════════

    def create_case(self, case: Case) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                "INSERT INTO cases (name, description, case_type, status, created_at) VALUES (?,?,?,?,?)",
                (case.name, case.description, case.case_type.value, case.status.value, case.created_at)
            )
            return cur.lastrowid

    def get_cases(self) -> List[Case]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        return [Case(
            id=r["id"], name=r["name"], description=r["description"],
            case_type=CaseType(r["case_type"]), status=CaseStatus(r["status"]),
            created_at=r["created_at"]
        ) for r in rows]

    def get_case(self, case_id: int) -> Optional[Case]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            r = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not r:
            return None
        return Case(
            id=r["id"], name=r["name"], description=r["description"],
            case_type=CaseType(r["case_type"]), status=CaseStatus(r["status"]),
            created_at=r["created_at"]
        )

    def update_case(self, case_id: int, name: str, description: str, status: str):
        with sqlite3.connect(self.db_path) as c:
            c.execute("UPDATE cases SET name=?, description=?, status=? WHERE id=?",
                      (name, description, status, case_id))

    def delete_case(self, case_id: int):
        with sqlite3.connect(self.db_path) as c:
            c.execute("DELETE FROM cases WHERE id=?", (case_id,))
            c.execute("DELETE FROM targets WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM assets WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM iocs WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM correlations WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM tool_reports WHERE case_id=?", (case_id,))

    # ══════════════════════════════════════════════════════════════════════════
    # TARGETS (Personas)
    # ══════════════════════════════════════════════════════════════════════════

    def add_target(self, target: Target) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                """INSERT INTO targets
                   (case_id, name, email, phone, username, photo_url, location,
                    company, social_profiles, notes, confidence, source, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (target.case_id, target.name, target.email, target.phone,
                 target.username, target.photo_url, target.location, target.company,
                 target.social_profiles, target.notes, target.confidence,
                 target.source, target.created_at)
            )
            return cur.lastrowid

    def get_targets(self, case_id: int) -> List[Target]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM targets WHERE case_id=? ORDER BY confidence DESC",
                (case_id,)
            ).fetchall()
        return [Target(
            id=r["id"], case_id=r["case_id"], name=r["name"], email=r["email"],
            phone=r["phone"], username=r["username"], photo_url=r["photo_url"],
            location=r["location"], company=r["company"],
            social_profiles=r["social_profiles"], notes=r["notes"],
            confidence=r["confidence"], source=r["source"], created_at=r["created_at"]
        ) for r in rows]

    def update_target(self, target_id: int, **kwargs):
        allowed = ['name', 'email', 'phone', 'username', 'photo_url', 'location',
                   'company', 'social_profiles', 'notes', 'confidence']
        updates = [(k, v) for k, v in kwargs.items() if k in allowed]
        if not updates:
            return
        set_clause = ", ".join(f"{k}=?" for k, _ in updates)
        values = [v for _, v in updates] + [target_id]
        with sqlite3.connect(self.db_path) as c:
            c.execute(f"UPDATE targets SET {set_clause} WHERE id=?", values)

    def delete_target(self, target_id: int):
        with sqlite3.connect(self.db_path) as c:
            c.execute("DELETE FROM targets WHERE id=?", (target_id,))

    # ══════════════════════════════════════════════════════════════════════════
    # ASSETS (Infraestructura)
    # ══════════════════════════════════════════════════════════════════════════

    def add_asset(self, asset: Asset) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                """INSERT INTO assets
                   (case_id, asset_type, value, source_tool, first_seen, last_seen, metadata, confidence)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (asset.case_id, asset.asset_type, asset.value, asset.source_tool,
                 asset.first_seen, asset.last_seen, asset.metadata, asset.confidence)
            )
            return cur.lastrowid

    def get_assets(self, case_id: int, asset_type: str = None) -> List[Asset]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            if asset_type:
                rows = c.execute(
                    "SELECT * FROM assets WHERE case_id=? AND asset_type=? ORDER BY first_seen DESC",
                    (case_id, asset_type)
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM assets WHERE case_id=? ORDER BY first_seen DESC",
                    (case_id,)
                ).fetchall()
        return [Asset(
            id=r["id"], case_id=r["case_id"], asset_type=r["asset_type"],
            value=r["value"], source_tool=r["source_tool"], first_seen=r["first_seen"],
            last_seen=r["last_seen"], metadata=r["metadata"], confidence=r["confidence"]
        ) for r in rows]

    def find_asset(self, case_id: int, value: str) -> Optional[Asset]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            r = c.execute(
                "SELECT * FROM assets WHERE case_id=? AND value=?",
                (case_id, value)
            ).fetchone()
        if not r:
            return None
        return Asset(
            id=r["id"], case_id=r["case_id"], asset_type=r["asset_type"],
            value=r["value"], source_tool=r["source_tool"], first_seen=r["first_seen"],
            last_seen=r["last_seen"], metadata=r["metadata"], confidence=r["confidence"]
        )

    def delete_asset(self, asset_id: int):
        with sqlite3.connect(self.db_path) as c:
            c.execute("DELETE FROM assets WHERE id=?", (asset_id,))

    # ══════════════════════════════════════════════════════════════════════════
    # IOCs
    # ══════════════════════════════════════════════════════════════════════════

    def add_ioc(self, ioc: IOC) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                """INSERT INTO iocs
                   (case_id, ioc_type, value, source, confidence, tags, description,
                    first_seen, last_seen, is_malicious, severity)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (ioc.case_id, ioc.ioc_type, ioc.value, ioc.source, ioc.confidence,
                 ioc.tags, ioc.description, ioc.first_seen, ioc.last_seen,
                 1 if ioc.is_malicious else 0, ioc.severity)
            )
            return cur.lastrowid

    def get_iocs(self, case_id: int, ioc_type: str = None) -> List[IOC]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            if ioc_type:
                rows = c.execute(
                    "SELECT * FROM iocs WHERE case_id=? AND ioc_type=? ORDER BY severity DESC",
                    (case_id, ioc_type)
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM iocs WHERE case_id=? ORDER BY severity DESC",
                    (case_id,)
                ).fetchall()
        return [IOC(
            id=r["id"], case_id=r["case_id"], ioc_type=r["ioc_type"],
            value=r["value"], source=r["source"], confidence=r["confidence"],
            tags=r["tags"], description=r["description"], first_seen=r["first_seen"],
            last_seen=r["last_seen"], is_malicious=bool(r["is_malicious"]),
            severity=r["severity"]
        ) for r in rows]

    def find_ioc(self, value: str) -> List[IOC]:
        """Buscar IOC por valor en todos los casos"""
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM iocs WHERE value=?", (value,)
            ).fetchall()
        return [IOC(
            id=r["id"], case_id=r["case_id"], ioc_type=r["ioc_type"],
            value=r["value"], source=r["source"], confidence=r["confidence"],
            tags=r["tags"], description=r["description"], first_seen=r["first_seen"],
            last_seen=r["last_seen"], is_malicious=bool(r["is_malicious"]),
            severity=r["severity"]
        ) for r in rows]

    def delete_ioc(self, ioc_id: int):
        with sqlite3.connect(self.db_path) as c:
            c.execute("DELETE FROM iocs WHERE id=?", (ioc_id,))

    # ══════════════════════════════════════════════════════════════════════════
    # CORRELATIONS (Grafo)
    # ══════════════════════════════════════════════════════════════════════════

    def add_correlation(self, corr: Correlation) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                """INSERT INTO correlations
                   (case_id, source_type, source_id, target_type, target_id,
                    relation_type, confidence, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (corr.case_id, corr.source_type, corr.source_id,
                 corr.target_type, corr.target_id, corr.relation_type,
                 corr.confidence, corr.created_at)
            )
            return cur.lastrowid

    def get_correlations(self, case_id: int) -> List[Correlation]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM correlations WHERE case_id=?", (case_id,)
            ).fetchall()
        return [Correlation(
            id=r["id"], case_id=r["case_id"], source_type=r["source_type"],
            source_id=r["source_id"], target_type=r["target_type"],
            target_id=r["target_id"], relation_type=r["relation_type"],
            confidence=r["confidence"], created_at=r["created_at"]
        ) for r in rows]

    def get_related(self, entity_type: str, entity_id: int) -> List[Correlation]:
        """Obtener todas las correlaciones donde participa una entidad"""
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                """SELECT * FROM correlations
                   WHERE (source_type=? AND source_id=?)
                      OR (target_type=? AND target_id=?)""",
                (entity_type, entity_id, entity_type, entity_id)
            ).fetchall()
        return [Correlation(
            id=r["id"], case_id=r["case_id"], source_type=r["source_type"],
            source_id=r["source_id"], target_type=r["target_type"],
            target_id=r["target_id"], relation_type=r["relation_type"],
            confidence=r["confidence"], created_at=r["created_at"]
        ) for r in rows]

    # ══════════════════════════════════════════════════════════════════════════
    # TOOL REPORTS
    # ══════════════════════════════════════════════════════════════════════════

    def save_report(self, report: ToolReport) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                """INSERT INTO tool_reports
                   (case_id, module, tool_name, raw_json, summary, status,
                    execution_time, results_count, run_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (report.case_id, report.module, report.tool_name, report.raw_json,
                 report.summary, report.status, report.execution_time,
                 report.results_count, report.run_at)
            )
            return cur.lastrowid

    def get_reports(self, case_id: int, module: str = None) -> List[ToolReport]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            if module:
                rows = c.execute(
                    "SELECT * FROM tool_reports WHERE case_id=? AND module=? ORDER BY run_at DESC",
                    (case_id, module)
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM tool_reports WHERE case_id=? ORDER BY run_at DESC",
                    (case_id,)
                ).fetchall()
        return [ToolReport(
            id=r["id"], case_id=r["case_id"], module=r["module"],
            tool_name=r["tool_name"], raw_json=r["raw_json"], summary=r["summary"],
            status=r["status"], execution_time=r["execution_time"],
            results_count=r["results_count"], run_at=r["run_at"]
        ) for r in rows]

    # ══════════════════════════════════════════════════════════════════════════
    # CTI ITEMS
    # ══════════════════════════════════════════════════════════════════════════

    def add_cti_item(self, source: str, title: str, link: str, published: str,
                     summary: str, tags: str, cves: str, raw_json: str) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                """INSERT INTO cti_items
                   (source, title, link, published, summary, tags, cves, raw_json, harvested_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (source, title, link, published, summary, tags, cves, raw_json,
                 datetime.now().isoformat())
            )
            return cur.lastrowid

    def get_cti_items(self, since: str = None, source: str = None) -> List[Dict]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            query = "SELECT * FROM cti_items"
            params = []
            conditions = []
            if since:
                conditions.append("harvested_at >= ?")
                params.append(since)
            if source:
                conditions.append("source = ?")
                params.append(source)
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY published DESC"
            rows = c.execute(query, params).fetchall()
        return [dict(r) for r in rows]


# Global singleton
db = Database()
