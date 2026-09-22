"""DB package — v2 singleton."""
from .feedback_db import Database

# Global singleton instance
db = Database()

__all__ = ["Database", "db"]
