import json
from pathlib import Path
from typing import Any

from codex_preflight_core.command.classifier import CommandClassification
from codex_preflight_core.policy.decision import PolicyResult
from codex_preflight_core.repo.identity import RepoIdentity
from codex_preflight_core.scanner.finding import Finding, Severity


def render_json_report(
    *,
    command: str,
    classification: CommandClassification,
    repo_path: Path,
    repo_identity: RepoIdentity | None,
    fingerprint: str,
    findings: list[Finding],
    policy: PolicyResult,
    cache_status: dict[str, Any],
) -> str:
    report = build_report(
        command=command,
        classification=classification,
        repo_path=repo_path,
        repo_identity=repo_identity,
        fingerprint=fingerprint,
        findings=findings,
        policy=policy,
        cache_status=cache_status,
    )
    return json.dumps(report, indent=2, sort_keys=False)


def build_report(
    *,
    command: str,
    classification: CommandClassification,
    repo_path: Path,
    repo_identity: RepoIdentity | None,
    fingerprint: str,
    findings: list[Finding],
    policy: PolicyResult,
    cache_status: dict[str, Any],
) -> dict[str, Any]:
    summary = {severity.value.lower(): 0 for severity in Severity}
    for finding in findings:
        summary[finding.severity.value.lower()] += 1
    identity = repo_identity
    return {
        "schemaVersion": "1.0",
        "decision": policy.decision.value,
        "riskScore": policy.risk_score,
        "command": command,
        "commandScope": classification.scope.value,
        "repo": {
            "path": str(repo_path),
            "remoteUrl": identity.remote_url if identity else None,
            "headCommit": identity.head_commit if identity else None,
            "criticalFingerprint": fingerprint,
        },
        "summary": summary,
        "reason": policy.reason,
        "agentInstruction": policy.agent_instruction,
        "findings": [finding.to_report() for finding in findings],
        "cache": cache_status,
    }
