import re
from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity


class GitHubActionsRule:
    rule_ids = (
        "GHA_PULL_REQUEST_TARGET",
        "GHA_WRITE_ALL_PERMISSIONS",
        "GHA_SELF_HOSTED_RUNNER",
        "GHA_UNPINNED_ACTION",
        "GHA_REMOTE_SCRIPT_EXEC",
    )

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        _ = root
        normalized = relative_path.as_posix()
        if not normalized.startswith(".github/workflows/"):
            return []
        checks = [
            ("GHA_PULL_REQUEST_TARGET", "pull_request_target", Severity.HIGH),
            ("GHA_WRITE_ALL_PERMISSIONS", "permissions: write-all", Severity.HIGH),
            ("GHA_SELF_HOSTED_RUNNER", "self-hosted", Severity.MEDIUM),
            ("GHA_REMOTE_SCRIPT_EXEC", "| bash", Severity.HIGH),
        ]
        findings: list[Finding] = []
        lowered = text.lower()
        for rule_id, needle, severity in checks:
            if needle in lowered:
                findings.append(self._finding(rule_id, severity, normalized, text, needle))
        if re.search(r"uses:\s+[^@\n]+(?:\n|$)", text, re.I):
            findings.append(self._finding("GHA_UNPINNED_ACTION", Severity.MEDIUM, normalized, text, "uses:"))
        return findings

    @staticmethod
    def _finding(rule_id: str, severity: Severity, file: str, text: str, needle: str) -> Finding:
        return Finding(
            rule_id=rule_id,
            severity=severity,
            title="Risky GitHub Actions configuration detected",
            file=file,
            line=line_number(text, needle),
            evidence=needle,
            why_it_matters="Workflow configuration can execute code with repository or secret access.",
            recommendation="Review workflow permissions, triggers, and remote execution.",
        )
