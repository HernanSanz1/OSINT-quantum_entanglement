"""Case manager — CRUD for OSINT cases."""
from typing import List, Optional
from .core.models import Case, CaseStatus
from .db.feedback_db import db


class CaseManager:
    def create(self, name: str, description: str = "") -> Case:
        case = Case(name=name, description=description)
        case.id = db.create_case(case)
        return case

    def list_all(self) -> List[Case]:
        return db.get_cases()

    def get(self, case_id: int) -> Optional[Case]:
        return db.get_case(case_id)

    def update(self, case_id: int, name: str, description: str) -> None:
        db.update_case(case_id, name, description)

    def delete(self, case_id: int) -> None:
        db.delete_case(case_id)

    def close(self, case_id: int) -> None:
        case = db.get_case(case_id)
        if case:
            case.status = CaseStatus.CLOSED
            with __import__("sqlite3").connect(db.db_path) as c:
                c.execute("UPDATE cases SET status='closed' WHERE id=?", (case_id,))
