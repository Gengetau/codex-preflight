import re
from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity

PATTERNS = (
    ("SHELL_CURL_PIPE_BASH", re.compile(r"curl\b.*\|\s*bash", re.I), Severity.HIGH),
    ("SHELL_WGET_PIPE_SH", re.compile(r"wget\b.*\|\s*sh", re.I), Severity.HIGH),
    ("POWERSHELL_ENCODED_COMMAND", re.compile(r"powershell\b.*-encodedcommand", re.I), Severity.HIGH),
    ("SHELL_DESTRUCTIVE_RM", re.compile(r"rm\s+-rf\s+/(?:\s|$)", re.I), Severity.CRITICAL),
    ("SHELL_BASE64_EXEC", re.compile(r"base64\s+-d.*\|\s*(?:sh|bash)", re.I), Severity.HIGH),
)


class ShellPatternRule:
    rule_ids = tuple(rule_id for rule_id, _pattern, _severity in PATTERNS)

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        _ = root
        normalized = relative_path.as_posix()
        if not (
            normalized.startswith("scripts/")
            or normalized.startswith("bin/")
            or normalized.startswith("tools/")
            or normalized == "Makefile"
            or normalized == "Dockerfile"
            or normalized.startswith(".github/workflows/")
            or normalized.endswith((".sh", ".ps1"))
        ):
            return []
        findings: list[Finding] = []
        for rule_id, pattern, severity in PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        title="Dangerous shell pattern detected",
                        file=normalized,
                        line=line_number(text, match.group(0)),
                        evidence=match.group(0)[:160],
                        why_it_matters="Codex may execute shell commands that download or destroy data.",
                        recommendation="Review the command manually before execution.",
                    )
                )
        return findings
