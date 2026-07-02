import re
from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity

PLACEHOLDERS = ("your-api-key", "changeme", "example", "dummy", "password123")
SECRET_PATTERNS = (
    ("SECRET_PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), Severity.CRITICAL),
    ("SECRET_GITHUB_TOKEN", re.compile(r"ghp_[A-Za-z0-9_]{20,}"), Severity.CRITICAL),
    ("SECRET_OPENAI_KEY", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{30,}"), Severity.CRITICAL),
    ("SECRET_AWS_KEY", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("SECRET_ENV_FILE", re.compile(r"(?:DATABASE_URL|AWS_SECRET_ACCESS_KEY)=\S+", re.I), Severity.HIGH),
)


class SecretRule:
    rule_ids = tuple(rule_id for rule_id, _pattern, _severity in SECRET_PATTERNS)

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        _ = root
        findings: list[Finding] = []
        lowered = text.lower()
        if any(placeholder in lowered for placeholder in PLACEHOLDERS):
            return []
        for rule_id, pattern, severity in SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        title="Secret-like value detected",
                        file=relative_path.as_posix(),
                        line=line_number(text, match.group(0)),
                        evidence=match.group(0)[:16] + "...",
                        why_it_matters="Committed secrets can be exposed to tools or logs.",
                        recommendation="Remove the secret and rotate it if it is real.",
                    )
                )
        return findings
