"""
SecretVault — API key storage outside the project directory.

Priority order:
  1. Environment variables (OSINT_OPENAI_KEY, OSINT_VENICE_KEY, …)
  2. ~/.osint_v2_keys  (a JSON file in the user's home dir, NOT in the repo)
  3. In-memory only (keys set at runtime and never persisted)

This file NEVER stores keys in the project directory.
Keys are NEVER logged and NEVER appear in __repr__ / __str__ of any object.
"""
import json
import logging
import os
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# File stored in HOME directory — always outside the project/repo
_VAULT_PATH = Path.home() / ".osint_v2_keys"

# Environment variable names
_ENV_MAP: Dict[str, str] = {
    "ChatGPT":   "OSINT_OPENAI_KEY",
    "Venice":    "OSINT_VENICE_KEY",
    "Hunter.io": "OSINT_HUNTER_KEY",
    "CENSYS":    "OSINT_CENSYS_KEY",
    "IntelOwl":  "OSINT_INTELOWL_KEY",
    "OpenCTI":   "OSINT_OPENCTI_KEY",
    "MISP":      "OSINT_MISP_KEY",
    "Cortex":    "OSINT_CORTEX_KEY",
    "IntelMQ":   "OSINT_INTELMQ_KEY",
}


class SecretVault:
    """
    Secure, repo-safe key store.
    Use get(name) / set(name, key) / delete(name).
    """

    def __init__(self, vault_path: Path = _VAULT_PATH):
        self._vault_path = vault_path
        self._memory: Dict[str, str] = {}   # session-only cache

    # ── Public API ────────────────────────────────────────────────────────────

    def get(self, name: str) -> str:
        """Return key for `name`. Checks env vars → vault file → memory."""
        # 1. Environment variable takes highest priority
        env_name = _ENV_MAP.get(name, f"OSINT_{name.upper().replace(' ', '_')}_KEY")
        env_val = os.environ.get(env_name, "")
        if env_val:
            return env_val

        # 2. Memory cache (runtime-set)
        if name in self._memory:
            return self._memory[name]

        # 3. Vault file
        return self._read_vault().get(name, "")

    def set(self, name: str, key: str, persist: bool = True) -> None:
        """Store key. If persist=True writes to vault file; otherwise session-only."""
        if not key:
            return
        self._memory[name] = key
        if persist:
            data = self._read_vault()
            data[name] = key
            self._write_vault(data)

    def delete(self, name: str) -> None:
        self._memory.pop(name, None)
        data = self._read_vault()
        data.pop(name, None)
        self._write_vault(data)

    def all_names(self) -> list:
        """Return list of known key names from vault (values are NOT returned)."""
        return list(self._read_vault().keys())

    def has(self, name: str) -> bool:
        return bool(self.get(name))

    def status_report(self) -> Dict[str, str]:
        """Return {name: 'set via env' / 'set via vault' / 'not configured'} — no key values."""
        report = {}
        for name in _ENV_MAP.keys():
            env_name = _ENV_MAP[name]
            if os.environ.get(env_name):
                report[name] = "✅ set via env var"
            elif self._read_vault().get(name):
                report[name] = "✅ set via vault"
            else:
                report[name] = "⬜ not configured"
        return report

    # ── File I/O ──────────────────────────────────────────────────────────────

    def _read_vault(self) -> Dict[str, str]:
        if not self._vault_path.exists():
            return {}
        try:
            text = self._vault_path.read_text(encoding="utf-8")
            data = json.loads(text)
            # Ensure only string values — never log content
            return {k: str(v) for k, v in data.items() if isinstance(v, str)}
        except Exception as e:
            logger.debug(f"SecretVault read error: {type(e).__name__}")
            return {}

    def _write_vault(self, data: Dict[str, str]) -> None:
        try:
            self._vault_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            # Restrict file permissions: owner read/write only (600)
            self._vault_path.chmod(0o600)
        except Exception as e:
            logger.error(f"SecretVault write error: {type(e).__name__}")

    def __repr__(self):
        # Never expose keys in repr
        return f"<SecretVault keys={self.all_names()} path={self._vault_path}>"


# Global singleton
vault = SecretVault()
