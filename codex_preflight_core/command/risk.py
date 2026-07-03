import re
import shlex
from pathlib import Path

from codex_preflight_core.command.classifier import split_shell_segments
from codex_preflight_core.scanner.finding import Finding, Severity

COMMAND_FILE = "<command>"

_REMOTE_SHELL_PIPE = re.compile(
    r"\b(?:curl|wget)\b[^|]{0,800}\|\s*(?:sudo\s+)?(?:bash|sh)\b",
    re.IGNORECASE,
)
_POWERSHELL = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.IGNORECASE)
_POWERSHELL_ENCODED = re.compile(r"\s-(?:encodedcommand|enc|e)\b", re.IGNORECASE)
_REMOTE_DOWNLOADER = re.compile(
    r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)\b",
    re.IGNORECASE,
)
_POWERSHELL_EXECUTOR = re.compile(r"\b(?:iex|invoke-expression)\b", re.IGNORECASE)
_INLINE_INTERPRETER = re.compile(
    r"^\s*(?:python|python3|node|ruby|perl)\b.*\s(?:-c|-e|--eval)\b",
    re.IGNORECASE,
)
_DOCKER_PRIVILEGED = re.compile(r"^\s*docker\s+run\b.*(?:^|\s)--privileged(?:\s|$)", re.IGNORECASE)
_DOCKER_SOCKET = re.compile(
    r"(?:/var/run/docker\.sock|type=bind,[^\s]*source=/var/run/docker\.sock)",
    re.IGNORECASE,
)
_DOCKER_HOST_ROOT = re.compile(
    r"(?:^|\s)(?:-v|--volume)(?:\s+|=)/:(?:[^\s]*)(?:\s|$)"
    r"|--mount\s+type=bind,[^\s]*source=/,[^\s]*target=",
    re.IGNORECASE,
)
_BROAD_ROOT_FLAG = re.compile(r"(?:--root|--workspace|--allow-fs)(?:=|\s+)/(?=\s|$)", re.IGNORECASE)


def analyze_command_risk(command: str, *, cwd: Path | None = None) -> list[Finding]:
    """Return static risk findings for the planned command string itself."""
    del cwd
    findings: list[Finding] = []
    for segment in split_shell_segments(command):
        findings.extend(_analyze_segment(segment.strip(), evidence_command=command))
    return _dedupe(findings)


def _analyze_segment(segment: str, *, evidence_command: str) -> list[Finding]:
    findings: list[Finding] = []

    if _REMOTE_SHELL_PIPE.search(segment):
        findings.append(
            _finding(
                "COMMAND_REMOTE_SHELL_PIPE",
                Severity.CRITICAL,
                "Planned command pipes a remote download into a shell",
                evidence_command,
                "Remote shell pipelines execute network content without local review.",
                "Do not run this command automatically. Inspect and pin the downloaded script first.",
            )
        )

    if _POWERSHELL.search(segment) and _POWERSHELL_ENCODED.search(segment):
        findings.append(
            _finding(
                "COMMAND_POWERSHELL_ENCODED",
                Severity.CRITICAL,
                "Planned command uses encoded PowerShell",
                evidence_command,
                "Encoded PowerShell hides the command body from straightforward review.",
                "Decode and review the command before running it.",
            )
        )

    if (
        _POWERSHELL.search(segment)
        and _REMOTE_DOWNLOADER.search(segment)
        and _POWERSHELL_EXECUTOR.search(segment)
    ):
        findings.append(
            _finding(
                "COMMAND_POWERSHELL_REMOTE_EXEC",
                Severity.CRITICAL,
                "Planned command downloads and executes PowerShell content",
                evidence_command,
                "PowerShell download-and-execute patterns can run remote code immediately.",
                "Do not run this command automatically. Review the downloaded script first.",
            )
        )

    if _DOCKER_PRIVILEGED.search(segment):
        findings.append(
            _finding(
                "COMMAND_DOCKER_PRIVILEGED",
                Severity.HIGH,
                "Planned Docker command enables privileged mode",
                evidence_command,
                "Privileged containers can escape normal container isolation boundaries.",
                "Ask the user before running privileged containers.",
            )
        )

    if _is_docker_run(segment) and _DOCKER_HOST_ROOT.search(segment):
        findings.append(
            _finding(
                "COMMAND_DOCKER_HOST_ROOT_MOUNT",
                Severity.HIGH,
                "Planned Docker command mounts the host root filesystem",
                evidence_command,
                "Mounting the host root gives the container broad access to local files.",
                "Ask the user before running containers with host root mounts.",
            )
        )

    if _is_docker_run(segment) and _DOCKER_SOCKET.search(segment):
        findings.append(
            _finding(
                "COMMAND_DOCKER_SOCKET_MOUNT",
                Severity.HIGH,
                "Planned Docker command mounts the Docker socket",
                evidence_command,
                "Docker socket access can let a container control the host Docker daemon.",
                "Ask the user before running containers with Docker socket access.",
            )
        )

    if _INLINE_INTERPRETER.search(segment):
        findings.append(
            _finding(
                "COMMAND_INLINE_INTERPRETER_EXEC",
                Severity.MEDIUM,
                "Planned command runs inline interpreter code",
                evidence_command,
                "Inline interpreter code can hide non-obvious filesystem, process, or network actions.",
                "Review the inline code and ask the user before running it.",
            )
        )

    if _is_broad_mcp_startup(segment):
        findings.append(
            _finding(
                "COMMAND_MCP_BROAD_STARTUP",
                Severity.MEDIUM,
                "Planned command starts a broad-access server-like process",
                evidence_command,
                "Broad filesystem or workspace grants can expose more local context than intended.",
                "Ask the user before starting broad-access MCP or server processes.",
            )
        )

    return findings


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    evidence: str,
    why_it_matters: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        file=COMMAND_FILE,
        line=0,
        evidence=evidence,
        why_it_matters=why_it_matters,
        recommendation=recommendation,
    )


def _is_docker_run(segment: str) -> bool:
    return bool(re.match(r"^\s*docker\s+run\b", segment, flags=re.IGNORECASE))


def _is_broad_mcp_startup(segment: str) -> bool:
    if not _BROAD_ROOT_FLAG.search(segment):
        return False
    tokens = _split(segment)
    if not tokens:
        return False
    first = tokens[0].lower()
    second = tokens[1].lower() if len(tokens) > 1 else ""
    if first == "npx" and "mcp" in segment.lower():
        return True
    return first in {"node", "python", "python3"} and "server" in second


def _split(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
