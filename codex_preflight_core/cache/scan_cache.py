from pathlib import Path
from typing import Any

from codex_preflight_core.cache.atomic_json import read_json, write_json_atomic


class ScanCache:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _load(self) -> list[dict[str, Any]]:
        return list(read_json(self.path, []))

    def get(self, key: dict[str, str | None]) -> dict[str, Any] | None:
        for entry in self._load():
            if all(entry.get(name) == value for name, value in key.items()):
                report = entry.get("report")
                if isinstance(report, dict) and report.get("decision") in {"ALLOW", "WARN"}:
                    return report
        return None

    def store(self, key: dict[str, str | None], report: dict[str, Any]) -> None:
        if report.get("decision") not in {"ALLOW", "WARN"}:
            return
        entries = [
            entry
            for entry in self._load()
            if not all(entry.get(name) == value for name, value in key.items())
        ]
        entries.append({**key, "report": report})
        write_json_atomic(self.path, entries)

    def clear(self) -> None:
        write_json_atomic(self.path, [])
