import re
from pathlib import Path

from codex_preflight_core.reachability.graph import Capability
from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Severity


def node_capabilities(relative_path: Path, text: str) -> list[Capability]:
    patterns = (
        (
            "JS_CHILD_PROCESS_EXEC",
            re.compile(r"child_process\.(?:exec|spawn)|\b\w+\.(?:exec|spawn)\s*\(|\b(?:execSync|spawnSync)\s*\(", re.I),
            Severity.HIGH,
            "Node child process execution",
        ),
        ("JS_DYNAMIC_EVAL", re.compile(r"\b(?:eval|Function)\s*\(", re.I), Severity.HIGH, "Node dynamic evaluation"),
        (
            "JS_NETWORK_ACCESS",
            re.compile(r"\b(?:https|http)\.request\s*\(|\bfetch\s*\(", re.I),
            Severity.HIGH,
            "Node network access",
        ),
        ("JS_ENV_ACCESS", re.compile(r"\bprocess\.env\b", re.I), Severity.MEDIUM, "Node environment access"),
        (
            "SCRIPT_DYNAMIC_COMMAND_CONSTRUCTION",
            re.compile(r"`[^`]*\$\{[^}]+}", re.I),
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
            recommendation="Review reachable Node.js code before execution.",
        )
        for rule_id, pattern, severity, capability in patterns
        if (match := pattern.search(text))
    ]
