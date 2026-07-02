from pathlib import Path
from typing import Any

from codex_preflight_core.cache.paths import scan_cache_path, trust_cache_path
from codex_preflight_core.cache.scan_cache import ScanCache
from codex_preflight_core.cache.trust_cache import TrustCache
from codex_preflight_core.command.classifier import classify_command
from codex_preflight_core.policy.engine import evaluate_policy
from codex_preflight_core.repo.fingerprint import compute_critical_fingerprint
from codex_preflight_core.repo.identity import RepoIdentity, resolve_repo_identity
from codex_preflight_core.report.json_renderer import build_report
from codex_preflight_core.scanner.engine import scan_repository

POLICY_VERSION = "default-v1"
RULESET_VERSION = "2026.07.02"


def run_preflight(cwd: Path, command: str, use_cache: bool = True) -> dict[str, Any]:
    scan_path = cwd.resolve()
    identity = resolve_repo_identity(cwd)
    classification = classify_command(command)
    fingerprint = compute_critical_fingerprint(scan_path)
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

    try:
        trust = TrustCache(trust_cache_path()).match(
            repo_id=identity.repo_id,
            head_commit=identity.head_commit,
            critical_fingerprint=fingerprint,
            command_scope=classification.scope.value,
        )
    except OSError:
        trust = None
    if trust:
        cache_status = {
            "usedScanCache": False,
            "usedTrustCache": True,
            "cacheReason": "matching scoped user approval",
        }

    findings = scan_repository(scan_path)
    policy = evaluate_policy(findings, classification)
    report = build_report(
        command=command,
        classification=classification,
        repo_path=scan_path,
        repo_identity=identity,
        fingerprint=fingerprint,
        findings=findings,
        policy=policy,
        cache_status=cache_status,
    )
    if use_cache:
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
    }
