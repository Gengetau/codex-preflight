from pathlib import Path

from codex_preflight_core.reachability.graph import Uncertainty
from codex_preflight_core.scanner.finding import Severity


def missing_target(target: str, file: Path | None = None) -> Uncertainty:
    return Uncertainty(
        rule_id="SCRIPT_TARGET_MISSING",
        severity=Severity.MEDIUM,
        file=file,
        reason=f"Referenced local script target was not found: {target}",
        recommendation="Inspect the command chain manually before execution.",
    )


def outside_repo(target: str, file: Path | None = None) -> Uncertainty:
    return Uncertainty(
        rule_id="SCRIPT_TARGET_OUTSIDE_REPO",
        severity=Severity.MEDIUM,
        file=file,
        reason=f"Referenced script target is outside the repository: {target}",
        recommendation="Do not follow outside-repository paths automatically.",
    )


def unknown_interpreter(command: str, file: Path | None = None) -> Uncertainty:
    return Uncertainty(
        rule_id="SCRIPT_UNKNOWN_INTERPRETER",
        severity=Severity.MEDIUM,
        file=file,
        reason=f"Could not identify a static interpreter for command: {command}",
        recommendation="Review the command manually before execution.",
    )


def parse_uncertain(reason: str, file: Path | None = None) -> Uncertainty:
    return Uncertainty(
        rule_id="SCRIPT_PARSE_UNCERTAIN",
        severity=Severity.MEDIUM,
        file=file,
        reason=reason,
        recommendation="Static parsing was incomplete; review this execution path manually.",
    )


def chain_depth_exceeded(file: Path | None = None) -> Uncertainty:
    return Uncertainty(
        rule_id="SCRIPT_CHAIN_DEPTH_EXCEEDED",
        severity=Severity.HIGH,
        file=file,
        reason="Static script reachability exceeded the maximum chain depth.",
        recommendation="Manually inspect the remaining script chain before execution.",
    )


def dynamic_command(command: str, file: Path | None = None) -> Uncertainty:
    return Uncertainty(
        rule_id="SCRIPT_DYNAMIC_COMMAND_CONSTRUCTION",
        severity=Severity.HIGH,
        file=file,
        reason=f"Dynamic command construction may hide execution targets: {command}",
        recommendation="Review dynamic command construction before execution.",
    )
