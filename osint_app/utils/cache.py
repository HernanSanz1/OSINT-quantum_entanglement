"""LRU-style cache manager for OSINT search results."""
import time
import hashlib
import json
from typing import Any, Optional


class CacheManager:
    """In-memory cache with TTL expiration and LRU eviction."""

    def __init__(self, max_size: int = 200, ttl: float = 3600.0):
        self.max_size = max_size
        self.ttl = ttl  # seconds
        self._cache: dict = {}  # key -> {value, ts}

    def _make_key(self, params: dict) -> str:
        return hashlib.md5(json.dumps(params, sort_keys=True).encode()).hexdigest()

    def get(self, params: dict) -> Optional[Any]:
        key = self._make_key(params)
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.time() - entry["ts"] > self.ttl:
            del self._cache[key]
            return None
        entry["ts"] = time.time()  # refresh on access
        return entry["value"]

    def set(self, params: dict, value: Any) -> None:
        if len(self._cache) >= self.max_size:
            # Evict the oldest entry
            oldest = min(self._cache, key=lambda k: self._cache[k]["ts"])
            del self._cache[oldest]
        key = self._make_key(params)
        self._cache[key] = {"value": value, "ts": time.time()}

    def clear(self) -> None:
        self._cache.clear()
