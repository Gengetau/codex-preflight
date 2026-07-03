import re
from pathlib import Path

from codex_preflight_core.reachability.graph import Capability
from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Severity


def python_capabilities(relative_path: Path, text: str) -> list[Capability]:
    patterns = (
        (
            "PYTHON_SUBPROCESS_EXEC",
            re.compile(r"\bsubprocess\.(?:run|Popen)\s*\(|\bos\.system\s*\(", re.I),
            Severity.HIGH,
            "Python subprocess execution",
        ),
        ("PYTHON_DYNAMIC_EXEC", re.compile(r"\b(?:eval|exec)\s*\(", re.I), Severity.HIGH, "Python dynamic execution"),
        (
            "PYTHON_NETWORK_ACCESS",
            re.compile(r"\burllib\.request\.urlopen\s*\(|\brequests\.(?:get|post)\s*\(", re.I),
            Severity.HIGH,
            "Python network access",
        ),
        ("PYTHON_ENV_ACCESS", re.compile(r"\bos\.environ\b", re.I), Severity.MEDIUM, "Python environment access"),
    )
    return [
        Capability(
            rule_id=rule_id,
            severity=severity,
            file=relative_path,
            line=line_number(text, match.group(0)),
            capability=capability,
            evidence=match.group(0)[:160],
            recommendation="Review reachable Python code before execution.",
        )
        for rule_id, pattern, severity, capability in patterns
        if (match := pattern.search(text))
    ]
