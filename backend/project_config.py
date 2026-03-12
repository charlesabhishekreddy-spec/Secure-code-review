from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG = {
    "suppressions": {
        "paths": [],
        "rule_ids": [],
        "types": [],
    },
    "ai": {
        "min_severity": "HIGH",
    },
    "scanner": {
        "max_findings_per_file": 100,
        "prefer_python_ast": True,
    },
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


@dataclass(frozen=True)
class ProjectConfig:
    suppress_paths: tuple[str, ...] = field(default_factory=tuple)
    suppress_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    suppress_types: tuple[str, ...] = field(default_factory=tuple)
    ai_min_severity: str = "HIGH"
    max_findings_per_file: int = 100
    prefer_python_ast: bool = True
    config_path: str | None = None

    def severity_allows_ai(self, severity: str) -> bool:
        normalized = str(severity).upper()
        threshold = str(self.ai_min_severity).upper()
        return SEVERITY_ORDER.get(normalized, 99) <= SEVERITY_ORDER.get(threshold, 99)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def find_project_config(start_path: Path | None = None) -> Path | None:
    current = (start_path or Path.cwd()).resolve()
    candidates = [current, *current.parents]
    for directory in candidates:
        candidate = directory / ".codesentinel.yml"
        if candidate.exists():
            return candidate
    return None


@lru_cache(maxsize=1)
def load_project_config() -> ProjectConfig:
    config_path = find_project_config()
    merged_config = dict(DEFAULT_CONFIG)
    if config_path:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            merged_config = _deep_merge(DEFAULT_CONFIG, loaded)

    suppressions = merged_config.get("suppressions", {})
    scanner = merged_config.get("scanner", {})
    ai = merged_config.get("ai", {})

    return ProjectConfig(
        suppress_paths=tuple(str(item) for item in suppressions.get("paths", []) if str(item).strip()),
        suppress_rule_ids=tuple(str(item) for item in suppressions.get("rule_ids", []) if str(item).strip()),
        suppress_types=tuple(str(item) for item in suppressions.get("types", []) if str(item).strip()),
        ai_min_severity=str(ai.get("min_severity", "HIGH")).upper(),
        max_findings_per_file=max(1, int(scanner.get("max_findings_per_file", 100))),
        prefer_python_ast=bool(scanner.get("prefer_python_ast", True)),
        config_path=str(config_path) if config_path else None,
    )

