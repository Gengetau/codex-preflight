import re
from pathlib import Path

import yaml

from codex_preflight_core.reachability.graph import Capability
from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Severity

COMPOSE_NAMES = {"docker-compose.yml", "compose.yml", "compose.yaml"}


def docker_capabilities(relative_path: Path, text: str) -> list[Capability]:
    checks = (
        (
            "DOCKER_REACHABLE_RUN_REMOTE_EXEC",
            re.compile(r"RUN\s+(?:curl\b.*\|\s*bash|wget\b.*\|\s*sh)", re.I),
            Severity.CRITICAL,
            "Dockerfile remote shell execution",
        ),
        (
            "DOCKER_REACHABLE_ENTRYPOINT_SCRIPT",
            re.compile(r"^(?:ENTRYPOINT|CMD)\s+.*\.(?:sh|bash|ps1)", re.I | re.M),
            Severity.HIGH,
            "Docker entrypoint script",
        ),
        ("DOCKER_SOCKET_MOUNT", re.compile(r"/var/run/docker\.sock", re.I), Severity.HIGH, "Docker socket mount"),
        ("DOCKER_PRIVILEGED_CONTAINER", re.compile(r"privileged:\s*true", re.I), Severity.HIGH, "privileged container"),
        ("DOCKER_PRIVILEGED_CONTAINER", re.compile(r"network_mode:\s*host", re.I), Severity.HIGH, "host network mode"),
    )
    return [
        Capability(
            rule_id=rule_id,
            severity=severity,
            file=relative_path,
            line=line_number(text, match.group(0)),
            capability=capability,
            evidence=match.group(0)[:160],
            recommendation="Review reachable Docker configuration before execution.",
        )
        for rule_id, pattern, severity, capability in checks
        if (match := pattern.search(text))
    ]


def referenced_dockerfiles(compose_text: str) -> list[str]:
    try:
        data = yaml.safe_load(compose_text)
    except yaml.YAMLError:
        return []
    services = data.get("services", {}) if isinstance(data, dict) else {}
    if not isinstance(services, dict):
        return []
    references: list[str] = []
    for service in services.values():
        if not isinstance(service, dict):
            continue
        build = service.get("build")
        if isinstance(build, str):
            references.append(str(Path(build) / "Dockerfile"))
        elif isinstance(build, dict):
            context = build.get("context", ".")
            dockerfile = build.get("dockerfile", "Dockerfile")
            references.append(str(Path(str(context)) / str(dockerfile)))
    return references
