"""
In-memory LRU cache for LLM responses.

Cache key: SHA-256 hash of (model + messages JSON).
Each entry stores the full response, token counts, and latency for replaying.
"""

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CacheEntry:
    response: Any          # raw response dict from OpenAI
    input_tokens: int
    output_tokens: int
    latency_ms: float      # original call latency (for reporting)
    created_at: float = field(default_factory=time.time)


class LLMCache:
    def __init__(self, max_size: int = 256, ttl_seconds: float | None = None):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl_seconds
        self.hits = 0
        self.misses = 0

    def _make_key(self, model: str, messages: list[dict]) -> str:
        payload = json.dumps({"model": model, "messages": messages}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def get(self, model: str, messages: list[dict]) -> CacheEntry | None:
        key = self._make_key(model, messages)
        entry = self._cache.get(key)
        if entry is None:
            self.misses += 1
            return None
        if self.ttl and (time.time() - entry.created_at) > self.ttl:
            del self._cache[key]
            self.misses += 1
            return None
        # Move to end (most-recently-used)
        self._cache.move_to_end(key)
        self.hits += 1
        return entry

    def set(self, model: str, messages: list[dict], entry: CacheEntry) -> None:
        key = self._make_key(model, messages)
        self._cache[key] = entry
        self._cache.move_to_end(key)
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)  # evict LRU

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def clear(self) -> None:
        self._cache.clear()
        self.hits = 0
        self.misses = 0


# Module-level singleton so all agents share one cache by default
_default_cache = LLMCache()


def get_default_cache() -> LLMCache:
    return _default_cache
