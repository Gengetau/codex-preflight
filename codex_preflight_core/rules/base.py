from pathlib import Path
from typing import Protocol

from codex_preflight_core.scanner.finding import Finding


class Rule(Protocol):
    rule_ids: tuple[str, ...]

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        ...


def line_number(text: str, needle: str) -> int:
    index = text.lower().find(needle.lower())
    if index < 0:
        return 1
    return text[:index].count("\n") + 1
