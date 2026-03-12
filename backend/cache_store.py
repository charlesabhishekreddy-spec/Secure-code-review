from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any


class JsonCacheStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def _read_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def get(self, key: str) -> Any | None:
        with self._lock:
            return self._read_unlocked().get(key)

    def get_many(self, keys: list[str]) -> dict[str, Any]:
        with self._lock:
            cache = self._read_unlocked()
            return {key: cache[key] for key in keys if key in cache}

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            cache = self._read_unlocked()
            cache[key] = value
            self._write_unlocked(cache)

    def set_many(self, values: dict[str, Any]) -> None:
        if not values:
            return
        with self._lock:
            cache = self._read_unlocked()
            cache.update(values)
            self._write_unlocked(cache)

    def _write_unlocked(self, payload: dict[str, Any]) -> None:
        temp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temp_path.replace(self.path)

