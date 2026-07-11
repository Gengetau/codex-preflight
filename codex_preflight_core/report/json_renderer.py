import json
from pathlib import Path
from typing import Any

from codex_preflight_core.command.classifier import CommandClassification
from codex_preflight_core.policy.decision import PolicyResult
from codex_preflight_core.policy.explanation import build_policy_explanation
from codex_preflight_core.repo.identity import RepoIdentity
from codex_preflight_core.report.schema import SCHEMA_VERSION
from codex_preflight_core.scanner.finding import Finding, Severity, evidence_metadata

REPORT_MAX_FINDINGS = 100
REPORT_MAX_GRAPH_NODES = 100
REPORT_MAX_GRAPH_EDGES = 150
REPORT_MAX_GRAPH_CAPABILITIES = 100
REPORT_MAX_GRAPH_UNCERTAINTIES = 100

_SEVERITY_RANK = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


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
    source_metadata: dict[str, Any] | None = None,
    execution_graph: dict[str, Any] | None = None,
    policy_explanation: dict[str, Any] | None = None,
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
        source_metadata=source_metadata,
        execution_graph=execution_graph,
        policy_explanation=policy_explanation,
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
    source_metadata: dict[str, Any] | None = None,
    execution_graph: dict[str, Any] | None = None,
    policy_explanation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary = {severity.value.lower(): 0 for severity in Severity}
    for finding in findings:
        summary[finding.severity.value.lower()] += 1
    identity = repo_identity
    source = source_metadata or {"sourceType": "local"}
    capped_findings, finding_limit = _cap_findings(findings)
    graph, graph_limits = _cap_execution_graph(
        execution_graph
        or {
            "entryCommand": command,
            "nodes": [],
            "edges": [],
            "capabilities": [],
            "uncertainties": [],
        }
    )
    if finding_limit["omitted"] and not _has_report_size_uncertainty(graph):
        graph["uncertainties"].append(_report_size_uncertainty())
    return {
        "schemaVersion": SCHEMA_VERSION,
        "decision": policy.decision.value,
        "riskScore": policy.risk_score,
        "command": command,
        "commandScope": classification.scope.value,
        "repo": {
            "path": str(repo_path),
            "sourceType": source.get("sourceType", "local"),
            "cloneUrl": source.get("cloneUrl"),
            "requestedRef": source.get("requestedRef"),
            "resolvedCommit": source.get("resolvedCommit"),
            "remoteUrl": identity.remote_url if identity else None,
            "headCommit": identity.head_commit if identity else None,
            "criticalFingerprint": fingerprint,
        },
        "summary": summary,
        "reason": policy.reason,
        "agentInstruction": policy.agent_instruction,
        "policyExplanation": policy_explanation
        or build_policy_explanation(findings, classification, policy),
        "findings": capped_findings,
        "executionGraph": graph,
        "reportLimits": {
            "findings": finding_limit,
            "executionGraph": graph_limits,
        },
        "cache": cache_status,
    }


def _cap_findings(findings: list[Finding]) -> tuple[list[dict[str, object]], dict[str, int]]:
    if len(findings) <= REPORT_MAX_FINDINGS:
        included = [finding.to_report() for finding in findings]
        return included, _limit(REPORT_MAX_FINDINGS, len(findings), len(included))
    ordered = sorted(enumerate(findings), key=lambda item: (_SEVERITY_RANK[item[1].severity.value], item[0]))
    included = [finding.to_report() for _, finding in ordered[:REPORT_MAX_FINDINGS]]
    return included, _limit(REPORT_MAX_FINDINGS, len(findings), len(included))


def _cap_execution_graph(graph: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, int]]]:
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    capabilities = list(graph.get("capabilities", []))
    uncertainties = list(graph.get("uncertainties", []))
    capped = {
        "entryCommand": graph.get("entryCommand"),
        "nodes": nodes[:REPORT_MAX_GRAPH_NODES],
        "edges": edges[:REPORT_MAX_GRAPH_EDGES],
        "capabilities": capabilities[:REPORT_MAX_GRAPH_CAPABILITIES],
        "uncertainties": uncertainties[:REPORT_MAX_GRAPH_UNCERTAINTIES],
    }
    limits = {
        "nodes": _limit(REPORT_MAX_GRAPH_NODES, len(nodes), len(capped["nodes"])),
        "edges": _limit(REPORT_MAX_GRAPH_EDGES, len(edges), len(capped["edges"])),
        "capabilities": _limit(REPORT_MAX_GRAPH_CAPABILITIES, len(capabilities), len(capped["capabilities"])),
        "uncertainties": _limit(REPORT_MAX_GRAPH_UNCERTAINTIES, len(uncertainties), len(capped["uncertainties"])),
    }
    if any(limit["omitted"] for limit in limits.values()):
        capped["uncertainties"].append(_report_size_uncertainty())
    return capped, limits


def _limit(maximum: int, original: int, included: int) -> dict[str, int]:
    return {"max": maximum, "included": included, "omitted": max(0, original - included)}


def _report_size_uncertainty() -> dict[str, object]:
    return {
        "ruleId": "REPORT_SIZE_BUDGET_EXCEEDED",
        "severity": Severity.MEDIUM.value,
        "file": None,
        "reason": (
            "Repository analysis exceeded the static reporting budget. "
            "Some reachable nodes, findings, or uncertainties were omitted from the detailed report."
        ),
        "recommendation": "Treat the report as summarized and review omitted areas manually when risk matters.",
    } | evidence_metadata(
        "REPORT_SIZE_BUDGET_EXCEEDED",
        None,
        "Reachability uncertainty detected",
    )


def _has_report_size_uncertainty(graph: dict[str, Any]) -> bool:
    return any(
        item.get("ruleId") == "REPORT_SIZE_BUDGET_EXCEEDED"
        for item in graph.get("uncertainties", [])
        if isinstance(item, dict)
    )
