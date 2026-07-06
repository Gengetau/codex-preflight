import re
from dataclasses import dataclass
from pathlib import Path

from codex_preflight_core.reachability.graph import Capability
from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Severity

NODE_MODULE_EXTENSIONS = (".js", ".mjs", ".cjs", ".ts", ".tsx")

_STATIC_REQUIRE = re.compile(r"\brequire\s*\(\s*([\"'])(\.{1,2}/[^\"']+)\1\s*\)", re.I)
_STATIC_DYNAMIC_IMPORT = re.compile(r"\bimport\s*\(\s*([\"'])(\.{1,2}/[^\"']+)\1\s*\)", re.I)
_STATIC_SIDE_EFFECT_IMPORT = re.compile(r"\bimport\s+([\"'])(\.{1,2}/[^\"']+)\1", re.I)
_STATIC_FROM_IMPORT = re.compile(r"\bimport\s+[\s\S]*?\s+from\s+([\"'])(\.{1,2}/[^\"']+)\1", re.I)
_DYNAMIC_REQUIRE = re.compile(r"\brequire\s*\(\s*(?:[\"']\.{1,2}/[^\"']*[\"']\s*\+|[^\"'][^)]+)", re.I)
_DYNAMIC_IMPORT = re.compile(r"\bimport\s*\(\s*(?:[\"']\.{1,2}/[^\"']*[\"']\s*\+|[^\"'][^)]+)", re.I)


@dataclass(frozen=True)
class NodeModuleReference:
    target: str
    reason: str


def node_capabilities(relative_path: Path, text: str) -> list[Capability]:
    patterns = (
        (
            "JS_CHILD_PROCESS_EXEC",
            re.compile(
                r"child_process\.(?:exec|spawn)"
                r"|require\s*\(\s*[\"'](?:node:)?child_process[\"']\s*\)\s*\.\s*(?:exec|spawn)\s*\("
                r"|\b\w+\.(?:exec|spawn)\s*\("
                r"|\b(?:exec|spawn|execSync|spawnSync)\s*\(",
                re.I,
            ),
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


def local_module_references(text: str) -> list[NodeModuleReference]:
    references: list[NodeModuleReference] = []
    seen: set[str] = set()
    for pattern, reason in (
        (_STATIC_REQUIRE, "Node require reaches local module"),
        (_STATIC_DYNAMIC_IMPORT, "Node dynamic import reaches local module"),
        (_STATIC_SIDE_EFFECT_IMPORT, "Node import reaches local module"),
        (_STATIC_FROM_IMPORT, "Node import reaches local module"),
    ):
        for match in pattern.finditer(text):
            target = match.group(2)
            if target in seen:
                continue
            seen.add(target)
            references.append(NodeModuleReference(target=target, reason=reason))
    return references


def has_dynamic_module_reference(text: str) -> bool:
    return bool(_DYNAMIC_REQUIRE.search(text) or _DYNAMIC_IMPORT.search(text))
