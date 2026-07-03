from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity


class DockerRule:
    rule_ids = (
        "DOCKER_PRIVILEGED_CONTAINER",
        "DOCKER_SOCKET_MOUNT",
        "DOCKER_BROAD_HOST_MOUNT",
        "DOCKER_REMOTE_SCRIPT_EXEC",
    )

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        _ = root
        normalized = relative_path.as_posix()
        if relative_path.name not in {"Dockerfile", "docker-compose.yml", "compose.yaml", "compose.yml"}:
            return []
        lowered = text.lower()
        findings: list[Finding] = []
        checks = [
            ("DOCKER_PRIVILEGED_CONTAINER", "privileged: true", Severity.HIGH),
            ("DOCKER_SOCKET_MOUNT", "/var/run/docker.sock", Severity.HIGH),
            ("DOCKER_BROAD_HOST_MOUNT", '"/:/', Severity.HIGH),
            ("DOCKER_BROAD_HOST_MOUNT", "- /:/", Severity.HIGH),
            ("DOCKER_REMOTE_SCRIPT_EXEC", "| bash", Severity.HIGH),
        ]
        seen: set[str] = set()
        for rule_id, needle, severity in checks:
            if needle in lowered and rule_id not in seen:
                seen.add(rule_id)
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        title="Risky Docker configuration detected",
                        file=normalized,
                        line=line_number(text, needle),
                        evidence=needle,
                        why_it_matters="Docker commands can expose host resources or run remote code.",
                        recommendation="Review Docker configuration before starting containers.",
                    )
                )
        return findings
