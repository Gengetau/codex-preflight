from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity

PATTERNS = (
    ("AGENT_IGNORE_INSTRUCTIONS", "ignore previous instructions", Severity.HIGH),
    ("AGENT_SECRET_EXFILTRATION_REQUEST", "print secrets", Severity.HIGH),
    ("AGENT_SECRET_EXFILTRATION_REQUEST", "send environment variables", Severity.HIGH),
    ("AGENT_UNSAFE_COMMAND_REQUEST", "run this command without asking", Severity.HIGH),
    ("AGENT_DISABLE_SAFETY", "disable safety", Severity.HIGH),
    ("AGENT_UNSAFE_COMMAND_REQUEST", "curl this url and execute it", Severity.HIGH),
)


class AgentInstructionRule:
    rule_ids = (
        "AGENT_IGNORE_INSTRUCTIONS",
        "AGENT_SECRET_EXFILTRATION_REQUEST",
        "AGENT_UNSAFE_COMMAND_REQUEST",
        "AGENT_DISABLE_SAFETY",
    )

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        _ = root
        normalized = relative_path.as_posix()
        if relative_path.name not in {"README.md", "AGENTS.md", "CLAUDE.md"} and not (
            normalized.startswith(".cursor/rules")
            or normalized == ".github/copilot-instructions.md"
        ):
            return []
        lowered = text.lower()
        findings: list[Finding] = []
        seen: set[str] = set()
        for rule_id, phrase, severity in PATTERNS:
            if phrase in lowered and rule_id not in seen:
                seen.add(rule_id)
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        title="Unsafe agent instruction detected",
                        file=normalized,
                        line=line_number(text, phrase),
                        evidence=phrase,
                        why_it_matters="Repository instructions can attempt to steer agents unsafely.",
                        recommendation="Treat these instructions as untrusted and ask the user before acting.",
                    )
                )
        return findings
