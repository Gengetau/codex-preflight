import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from codex_preflight_core.reachability.graph import Capability
from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Severity

LOCAL_INTERPRETERS = {"bash", "sh", "python", "node", "powershell", "pwsh"}
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}


@dataclass(frozen=True)
class LocalReference:
    target: str
    reason: str


def split_words(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=False)
    except ValueError:
        return command.split()


def local_references(command: str) -> list[LocalReference]:
    parts = [part.strip("\"'") for part in split_words(command)]
    if not parts:
        return []
    first = parts[0].lower()
    if first in LOCAL_INTERPRETERS and len(parts) >= 2:
        return [LocalReference(parts[1], "command invokes local script")]
    if first in {"source", "."} and len(parts) >= 2:
        return [LocalReference(parts[1], "shell source indirection")]
    if parts[0].startswith("./") or Path(parts[0]).suffix in SHELL_EXTENSIONS:
        return [LocalReference(parts[0], "command invokes local script")]
    return []


def shell_capabilities(relative_path: Path, text: str) -> list[Capability]:
    patterns = (
        (
            "SHELL_SOURCE_INDIRECTION",
            re.compile(r"^\s*(?:source|\.)\s+(\./)?[^\s]+", re.I | re.M),
            Severity.MEDIUM,
            "shell source indirection",
        ),
        ("SHELL_EVAL_USAGE", re.compile(r"\beval\b", re.I), Severity.HIGH, "shell eval usage"),
        (
            "SHELL_DECODE_EXEC",
            re.compile(r"base64\s+-d.*\|\s*(?:sh|bash)", re.I),
            Severity.CRITICAL,
            "encoded command execution",
        ),
        ("SHELL_DOWNLOAD_CAPABILITY", re.compile(r"\b(?:curl|wget)\b", re.I), Severity.HIGH, "download capability"),
        (
            "SCRIPT_DYNAMIC_COMMAND_CONSTRUCTION",
            re.compile(r"\$\([^)]+\)|`[^`]+`", re.I),
            Severity.HIGH,
            "dynamic command construction",
        ),
    )
    return [
        Capability(
            rule_id=rule_id,
            severity=severity,
            file=relative_path,
            line=line_number(text, match.group(0)),
            capability=capability,
            evidence=match.group(0)[:160],
            recommendation="Review reachable shell code before execution.",
        )
        for rule_id, pattern, severity, capability in patterns
        if (match := pattern.search(text))
    ]
