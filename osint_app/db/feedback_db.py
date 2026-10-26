"""
v2 SQLite schema — Cases, TargetData, ToolReports, DataExtracts.
"""
import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

from ..core.models import Case, TargetData, ToolReport, CaseStatus
from ..utils.data_paths import resolve_db_path

logger = logging.getLogger(__name__)
# Fuera de la carpeta del proyecto (que puede estar en OneDrive); ver utils/data_paths.py
DB_PATH = resolve_db_path()


class Database:
    """Single SQLite database for the full OSINT v2 data model."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = str(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ── Schema ────────────────────────────────────────────────────────────────

    def _init_schema(self):
        with sqlite3.connect(self.db_path) as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    status TEXT DEFAULT 'open',
                    created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS target_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    field_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT DEFAULT 'manual',
                    confidence INTEGER DEFAULT 50,
                    created_at TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
                CREATE TABLE IF NOT EXISTS tool_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    tool_name TEXT NOT NULL,
                    raw_json TEXT DEFAULT '[]',
                    summary TEXT DEFAULT '',
                    status TEXT DEFAULT 'ok',
                    execution_time REAL DEFAULT 0,
                    results_count INTEGER DEFAULT 0,
                    run_at TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
                CREATE TABLE IF NOT EXISTS data_extracts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER,
                    case_id INTEGER,
                    field_type TEXT,
                    value TEXT,
                    auto_added INTEGER DEFAULT 0,
                    FOREIGN KEY (report_id) REFERENCES tool_reports(id),
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
                -- Cada perfilamiento guardado en un caso: la semilla exacta (con alias y usuarios extra) y los avisos de
                -- búsqueda incompleta, para rehacer la ficha más tarde desde el caso
                CREATE TABLE IF NOT EXISTS profile_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    seed_json TEXT NOT NULL,
                    warnings_json TEXT DEFAULT '{}',
                    run_at TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
                -- Lo que el analista confirmó o descartó de cada candidato (antes los descartes no se guardaban)
                CREATE TABLE IF NOT EXISTS candidate_verdicts (
                    case_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    decided_at TEXT,
                    PRIMARY KEY (case_id, url),
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
                -- Tabla heredada de la antigua función de IA: ya no se usa, se conserva para no tocar bases existentes
                CREATE TABLE IF NOT EXISTS ai_correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    report_ids TEXT DEFAULT '[]',
                    prompt TEXT,
                    response TEXT,
                    created_at TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
            """)

    # ── Cases ─────────────────────────────────────────────────────────────────

    def create_case(self, case: Case) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                "INSERT INTO cases (name, description, status, created_at) VALUES (?,?,?,?)",
                (case.name, case.description, case.status.value, case.created_at)
            )
            return cur.lastrowid  # type: ignore

    def get_cases(self) -> List[Case]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        return [Case(
            id=r["id"], name=r["name"], description=r["description"],
            status=CaseStatus(r["status"]), created_at=r["created_at"]
        ) for r in rows]

    def get_case(self, case_id: int) -> Optional[Case]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            r = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not r:
            return None
        return Case(id=r["id"], name=r["name"], description=r["description"],
                    status=CaseStatus(r["status"]), created_at=r["created_at"])

    def update_case(self, case_id: int, name: str, description: str):
        with sqlite3.connect(self.db_path) as c:
            c.execute("UPDATE cases SET name=?, description=? WHERE id=?", (name, description, case_id))

    def delete_case(self, case_id: int):
        with sqlite3.connect(self.db_path) as c:
            c.execute("DELETE FROM cases WHERE id=?", (case_id,))
            c.execute("DELETE FROM target_data WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM tool_reports WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM data_extracts WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM ai_correlations WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM profile_runs WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM candidate_verdicts WHERE case_id=?", (case_id,))

    # ── TargetData ────────────────────────────────────────────────────────────

    def add_target_data(self, td: TargetData) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                "INSERT INTO target_data (case_id, field_type, value, source, confidence, created_at) VALUES (?,?,?,?,?,?)",
                (td.case_id, td.field_type, td.value, td.source, td.confidence, td.created_at)
            )
            return cur.lastrowid  # type: ignore

    def get_target_data(self, case_id: int) -> List[TargetData]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM target_data WHERE case_id=? ORDER BY confidence DESC",
                (case_id,)
            ).fetchall()
        return [TargetData(
            id=r["id"], case_id=r["case_id"], field_type=r["field_type"],
            value=r["value"], source=r["source"],
            confidence=r["confidence"], created_at=r["created_at"]
        ) for r in rows]

    def update_target_data(self, data_id: int, field_type: str, value: str, confidence: int):
        with sqlite3.connect(self.db_path) as c:
            c.execute("UPDATE target_data SET field_type=?, value=?, confidence=? WHERE id=?", (field_type, value, confidence, data_id))

    def delete_target_data(self, data_id: int):
        with sqlite3.connect(self.db_path) as c:
            c.execute("DELETE FROM target_data WHERE id=?", (data_id,))

    # ── ToolReports ───────────────────────────────────────────────────────────

    def save_report(self, report: ToolReport) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                "INSERT INTO tool_reports (case_id, tool_name, raw_json, summary, status, execution_time, results_count, run_at) VALUES (?,?,?,?,?,?,?,?)",
                (report.case_id, report.tool_name, report.raw_json, report.summary,
                 report.status, report.execution_time, report.results_count, report.run_at)
            )
            return cur.lastrowid  # type: ignore

    def get_reports(self, case_id: int) -> List[ToolReport]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM tool_reports WHERE case_id=? ORDER BY run_at DESC",
                (case_id,)
            ).fetchall()
        return [ToolReport(
            id=r["id"], case_id=r["case_id"], tool_name=r["tool_name"],
            raw_json=r["raw_json"], summary=r["summary"], status=r["status"],
            execution_time=r["execution_time"], results_count=r["results_count"],
            run_at=r["run_at"]
        ) for r in rows]

    def update_report_json(self, report_id: int, raw_json: str):
        with sqlite3.connect(self.db_path) as c:
            c.execute("UPDATE tool_reports SET raw_json=? WHERE id=?", (raw_json, report_id))

    def delete_report(self, report_id: int):
        with sqlite3.connect(self.db_path) as c:
            c.execute("DELETE FROM tool_reports WHERE id=?", (report_id,))
            c.execute("DELETE FROM data_extracts WHERE report_id=?", (report_id,))

    # ── Perfilamientos y decisiones del analista ──────────────────────────────

    def save_profile_run(self, case_id: int, seed: Dict, warnings: Optional[Dict] = None) -> int:
        with sqlite3.connect(self.db_path) as c:
            cur = c.execute(
                "INSERT INTO profile_runs (case_id, seed_json, warnings_json, run_at) VALUES (?,?,?,?)",
                (case_id, json.dumps(seed, ensure_ascii=False), json.dumps(warnings or {}, ensure_ascii=False),
                 datetime.now().isoformat()))
            return cur.lastrowid  # type: ignore

    def get_profile_runs(self, case_id: int) -> List[Dict]:
        """Perfilamientos del caso, el más reciente primero: {"seed": {...}, "warnings": {...}, "run_at": "..."}."""
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute("SELECT * FROM profile_runs WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()
        return [{"seed": json.loads(r["seed_json"] or "{}"), "warnings": json.loads(r["warnings_json"] or "{}"),
                 "run_at": r["run_at"]} for r in rows]

    def set_verdict(self, case_id: int, url: str, verdict: str) -> None:
        """verdict: "confirmado" o "descartado"; "" borra la decisión."""
        with sqlite3.connect(self.db_path) as c:
            if verdict:
                c.execute("INSERT OR REPLACE INTO candidate_verdicts (case_id, url, verdict, decided_at) VALUES (?,?,?,?)",
                          (case_id, url, verdict, datetime.now().isoformat()))
            else:
                c.execute("DELETE FROM candidate_verdicts WHERE case_id=? AND url=?", (case_id, url))

    def get_verdicts(self, case_id: int) -> Dict[str, str]:
        with sqlite3.connect(self.db_path) as c:
            rows = c.execute("SELECT url, verdict FROM candidate_verdicts WHERE case_id=?", (case_id,)).fetchall()
        return {url: verdict for url, verdict in rows}

    # ── DataExtracts ──────────────────────────────────────────────────────────

    def save_extracts(self, report_id: int, case_id: int,
                      entities: Dict[str, List[str]]) -> None:
        with sqlite3.connect(self.db_path) as c:
            for field_type, values in entities.items():
                for val in values:
                    c.execute(
                        "INSERT INTO data_extracts (report_id, case_id, field_type, value) VALUES (?,?,?,?)",
                        (report_id, case_id, field_type, val)
                    )

    def get_extracts(self, report_id: int) -> Dict[str, List[str]]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT field_type, value FROM data_extracts WHERE report_id=?",
                (report_id,)
            ).fetchall()
        result: Dict[str, List[str]] = {}
        for r in rows:
            result.setdefault(r["field_type"], []).append(r["value"])
        return result


# Global singleton
db = Database()
