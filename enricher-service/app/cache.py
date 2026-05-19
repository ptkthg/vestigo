import time
from typing import Any

_TTL = 3600  # 1 hora

_store: dict[str, tuple[Any, float]] = {}


def get(key: str) -> Any | None:
    entry = _store.get(key)
    if entry is None:
        return None
    value, expires_at = entry
    if time.monotonic() > expires_at:
        del _store[key]
        return None
    return value


def set(key: str, value: Any, ttl: int = _TTL) -> None:
    _store[key] = (value, time.monotonic() + ttl)
