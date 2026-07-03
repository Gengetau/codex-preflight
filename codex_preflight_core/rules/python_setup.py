import re
from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity

REMOTE_FETCH_PATTERNS = (
    re.compile(r"urllib\.request\.urlopen\s*\(", re.I),
    re.compile(r"requests\.get\s*\(", re.I),
    re.compile(r"curl\b.*\|\s*(?:bash|sh)", re.I),
)


class PythonSetupRule:
    rule_ids = ("PYTHON_SETUP_REMOTE_FETCH",)

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        _ = root
        if relative_path.name != "setup.py":
            return []
        for pattern in REMOTE_FETCH_PATTERNS:
            match = pattern.search(text)
            if match:
                return [
                    Finding(
                        rule_id="PYTHON_SETUP_REMOTE_FETCH",
                        severity=Severity.HIGH,
                        title="Python setup remote fetch detected",
                        file=relative_path.as_posix(),
                        line=line_number(text, match.group(0)),
                        evidence=match.group(0)[:160],
                        why_it_matters="Python setup files can execute during package installation.",
                        recommendation="Inspect setup.py before running installation commands.",
                    )
                ]
        return []
