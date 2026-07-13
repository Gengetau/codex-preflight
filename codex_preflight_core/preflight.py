from pathlib import Path
from typing import Any

from codex_preflight_core.cache.paths import scan_cache_path, trust_cache_path
from codex_preflight_core.cache.scan_cache import ScanCache
from codex_preflight_core.cache.trust_cache import TrustCache
from codex_preflight_core.command.classifier import classify_command
from codex_preflight_core.command.risk import analyze_command_risk
from codex_preflight_core.policy.decision import Decision, PolicyResult
from codex_preflight_core.policy.engine import evaluate_policy
from codex_preflight_core.policy.explanation import build_policy_explanation
from codex_preflight_core.reachability.resolver import build_execution_graph
from codex_preflight_core.repo.fingerprint import compute_critical_fingerprint
from codex_preflight_core.repo.identity import RepoIdentity, resolve_repo_identity
from codex_preflight_core.report.json_renderer import build_report
from codex_preflight_core.scanner.engine import scan_repository

POLICY_VERSION = "default-v1"
RULESET_VERSION = "2026.07.13"
REPORT_FORMAT_VERSION = "policy-explanation-v1"


def run_preflight(
    cwd: Path,
    command: str,
    use_cache: bool = True,
    allow_trust: bool = True,
    source_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scan_path = cwd.resolve()
    identity = resolve_repo_identity(cwd)
    classification = classify_command(command)
    fingerprint = compute_critical_fingerprint(scan_path, command=command)
    cache_key = _cache_key(identity, fingerprint, classification.scope.value)
    cache_status = {"usedScanCache": False, "usedTrustCache": False, "cacheReason": None}

    scan_cache = ScanCache(scan_cache_path())
    if use_cache:
        try:
            cached = scan_cache.get(cache_key)
        except OSError:
            cached = None
        if cached:
            cached["cache"] = {
                "usedScanCache": True,
                "usedTrustCache": False,
                "cacheReason": "matching repository identity and critical fingerprint",
            }
            return cached

    if allow_trust:
        try:
            trust = TrustCache(trust_cache_path()).match(
                repo_id=identity.repo_id,
                head_commit=identity.head_commit,
                critical_fingerprint=fingerprint,
                command_scope=classification.scope.value,
                policy_version=POLICY_VERSION,
                ruleset_version=RULESET_VERSION,
            )
        except OSError:
            trust = None
    else:
        trust = None
    if trust:
        cache_status = {
            "usedScanCache": False,
            "usedTrustCache": True,
            "cacheReason": "matching scoped user approval",
        }

    graph = build_execution_graph(scan_path, command, classification)
    findings = analyze_command_risk(command, cwd=scan_path)
    findings.extend(scan_repository(scan_path, command=command))
    findings.extend(graph.to_findings())
    findings = _dedupe_findings(findings)
    policy = evaluate_policy(findings, classification)
    if trust:
        policy = PolicyResult(
            decision=Decision.ALLOW,
            risk_score=policy.risk_score,
            reason="Command allowed by matching scoped user approval.",
            agent_instruction="Proceed normally. A matching scoped user approval was found.",
        )
    report = build_report(
        command=command,
        classification=classification,
        repo_path=scan_path,
        repo_identity=identity,
        fingerprint=fingerprint,
        findings=findings,
        policy=policy,
        cache_status=cache_status,
        source_metadata=source_metadata,
        execution_graph=graph.to_report(),
        policy_explanation=build_policy_explanation(findings, classification, policy, trusted=bool(trust)),
    )
    if use_cache and not trust:
        try:
            scan_cache.store(cache_key, report)
        except OSError:
            report["cache"]["cacheReason"] = "cache unavailable"
    return report


def _cache_key(identity: RepoIdentity, fingerprint: str, command_scope: str) -> dict[str, str | None]:
    return {
        "repoId": identity.repo_id,
        "headCommit": identity.head_commit,
        "criticalFingerprint": fingerprint,
        "commandScope": command_scope,
        "policyVersion": POLICY_VERSION,
        "rulesetVersion": RULESET_VERSION,
        "reportFormatVersion": REPORT_FORMAT_VERSION,
    }


def _dedupe_findings(findings: list) -> list:
    direct_shell_downloads = {
        finding.file
        for finding in findings
        if finding.rule_id in {"SHELL_CURL_PIPE_BASH", "SHELL_WGET_PIPE_SH"}
    }
    seen: set[tuple[str, str]] = set()
    deduped = []
    for finding in findings:
        if finding.rule_id == "SHELL_DOWNLOAD_CAPABILITY" and finding.file in direct_shell_downloads:
            continue
        key = (finding.rule_id, finding.file)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
