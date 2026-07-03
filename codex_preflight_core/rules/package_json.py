import json
from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity

LIFECYCLE = {"preinstall", "install", "postinstall", "prepare", "prepack", "postpack"}
HIGH_RISK = (
    "curl",
    "wget",
    "bash",
    " sh",
    "powershell",
    "invoke-expression",
    "node -e",
    "python -c",
    "base64",
    "chmod",
    "sudo",
    "rm -rf",
)


class PackageJsonRule:
    rule_ids = (
        "NODE_LIFECYCLE_SCRIPT",
        "NODE_LIFECYCLE_REMOTE_EXEC",
        "NODE_POSTINSTALL_SCRIPT",
        "NODE_PREINSTALL_SCRIPT",
        "NODE_PREPARE_SCRIPT",
    )

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        _ = root
        if relative_path.name != "package.json":
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            return []
        findings: list[Finding] = []
        for name, value in scripts.items():
            if name not in LIFECYCLE or not isinstance(value, str):
                continue
            lowered = value.lower()
            rule_id = "NODE_LIFECYCLE_SCRIPT"
            severity = Severity.HIGH if any(pattern in lowered for pattern in HIGH_RISK) else Severity.MEDIUM
            if "curl" in lowered and "| bash" in lowered or "wget" in lowered and "| sh" in lowered:
                rule_id = "NODE_LIFECYCLE_REMOTE_EXEC"
                severity = Severity.CRITICAL
            elif name == "postinstall":
                rule_id = "NODE_POSTINSTALL_SCRIPT"
            elif name == "preinstall":
                rule_id = "NODE_PREINSTALL_SCRIPT"
            elif name == "prepare":
                rule_id = "NODE_PREPARE_SCRIPT"
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title="Package install lifecycle script detected",
                    file=relative_path.as_posix(),
                    line=line_number(text, name),
                    evidence=f"{name}: {value}",
                    why_it_matters="Dependency installation may execute this script automatically.",
                    recommendation="Inspect lifecycle scripts before running dependency installation.",
                )
            )
        return findings
