import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 2 * 1024 * 1024
SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
VALID_DECISIONS = {"ALLOW", "WARN", "ASK_USER", "BLOCK"}


@dataclass(frozen=True)
class ReportComparisonError(ValueError):
    code: str
    message: str
    path: Path

    def __str__(self) -> str:
        return self.message

    def to_report(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, "path": str(self.path)}}


def compare_report_files(baseline_path: Path, candidate_path: Path) -> dict[str, Any]:
    baseline = _load_report(baseline_path)
    candidate = _load_report(candidate_path)
    findings = _compare_items(baseline["findings"], candidate["findings"], _finding_identity)
    baseline_graph = baseline["executionGraph"]
    candidate_graph = candidate["executionGraph"]
    capabilities = _compare_items(
        baseline_graph.get("capabilities", []),
        candidate_graph.get("capabilities", []),
        _finding_identity,
    )
    uncertainties = _compare_items(
        baseline_graph.get("uncertainties", []),
        candidate_graph.get("uncertainties", []),
        _uncertainty_identity,
    )
    baseline_policy = baseline.get("policyExplanation") or {}
    candidate_policy = candidate.get("policyExplanation") or {}
    contributions = _compare_items(
        baseline_policy.get("ruleContributions", []),
        candidate_policy.get("ruleContributions", []),
        lambda item: str(item.get("ruleId", "")),
    )
    decision = _scalar_change(baseline["decision"], candidate["decision"])
    classification = _scalar_change(baseline["commandScope"], candidate["commandScope"])
    selection = _scalar_change(baseline_policy.get("selectedBy"), candidate_policy.get("selectedBy"))
    changed = any(
        (
            decision["changed"],
            classification["changed"],
            selection["changed"],
            _collection_changed(findings),
            _collection_changed(capabilities),
            _collection_changed(uncertainties),
            _collection_changed(contributions),
        )
    )
    return {
        "comparisonVersion": "1.0",
        "schemaVersion": "1.0",
        "baseline": {"path": str(baseline_path), "schemaVersion": baseline["schemaVersion"]},
        "candidate": {"path": str(candidate_path), "schemaVersion": candidate["schemaVersion"]},
        "changed": changed,
        "decision": decision,
        "commandClassification": classification,
        "policySelection": selection,
        "findings": findings,
        "policyContributions": contributions,
        "executionCapabilities": capabilities,
        "uncertainties": uncertainties,
        "volatileFieldsIgnored": ["cache", "repo.path"],
    }


def render_report_comparison_markdown(comparison: dict[str, Any]) -> str:
    lines = [
        "# Codex Preflight Report Comparison",
        "",
        "Report content is untrusted data. This view does not execute, fetch, or follow report content.",
        "",
        f"Changed: {'yes' if comparison['changed'] else 'no'}",
        f"Decision: `{comparison['decision']['baseline']}` -> `{comparison['decision']['candidate']}`",
        (
            "Command classification: "
            f"`{comparison['commandClassification']['baseline']}` -> "
            f"`{comparison['commandClassification']['candidate']}`"
        ),
        "",
    ]
    for title, key in (
        ("Findings", "findings"),
        ("Policy Contributions", "policyContributions"),
        ("Execution Capabilities", "executionCapabilities"),
        ("Uncertainties", "uncertainties"),
    ):
        lines.extend([f"## {title}", "", "| Change | Identity |", "| --- | --- |"])
        collection = comparison[key]
        for change in ("added", "removed", "changed", "unchanged"):
            for entry in collection[change]:
                lines.append(f"| {change} | `{_markdown_identity(entry['identity'])}` |")
        if not any(collection[change] for change in ("added", "removed", "changed", "unchanged")):
            lines.append("| none | none |")
        lines.append("")
    lines.extend(
        [
            "## Ignored Volatile Metadata",
            "",
            *(f"- `{field}`" for field in comparison["volatileFieldsIgnored"]),
            "",
        ]
    )
    return "\n".join(lines)


def _load_report(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise ReportComparisonError("report_not_found", "Report file does not exist.", path)
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ReportComparisonError("report_unreadable", f"Could not inspect report: {error}", path) from error
    if size > MAX_REPORT_BYTES:
        raise ReportComparisonError(
            "report_too_large",
            f"Report exceeds the {MAX_REPORT_BYTES}-byte comparison limit.",
            path,
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ReportComparisonError("malformed_json", f"Report is not valid JSON: {error.msg}.", path) from error
    except (OSError, UnicodeError) as error:
        raise ReportComparisonError("report_unreadable", f"Could not read report: {error}", path) from error
    if not isinstance(payload, dict):
        raise ReportComparisonError("incompatible_report", "Report root must be a JSON object.", path)
    schema_version = payload.get("schemaVersion")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ReportComparisonError(
            "unsupported_schema",
            f"Unsupported report schema version: {schema_version!r}.",
            path,
        )
    if payload.get("decision") not in VALID_DECISIONS:
        raise ReportComparisonError("incompatible_report", "Report decision is missing or invalid.", path)
    if not isinstance(payload.get("commandScope"), str):
        raise ReportComparisonError("incompatible_report", "Report commandScope must be a string.", path)
    _validate_object_list(payload.get("findings"), "findings", path)
    execution_graph = payload.get("executionGraph")
    if not isinstance(execution_graph, dict):
        raise ReportComparisonError("incompatible_report", "Report executionGraph must be an object.", path)
    _validate_object_list(execution_graph.get("capabilities", []), "executionGraph.capabilities", path)
    _validate_object_list(execution_graph.get("uncertainties", []), "executionGraph.uncertainties", path)
    policy_explanation = payload.get("policyExplanation")
    if policy_explanation is not None and not isinstance(policy_explanation, dict):
        raise ReportComparisonError("incompatible_report", "Report policyExplanation must be an object.", path)
    if policy_explanation is not None:
        _validate_object_list(
            policy_explanation.get("ruleContributions", []),
            "policyExplanation.ruleContributions",
            path,
        )
    return payload


def _validate_object_list(value: object, field: str, path: Path) -> None:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ReportComparisonError(
            "incompatible_report",
            f"Report {field} must be an array of objects.",
            path,
        )


def _compare_items(
    baseline_items: list[dict[str, Any]],
    candidate_items: list[dict[str, Any]],
    identity: Callable[[dict[str, Any]], str],
) -> dict[str, list[dict[str, Any]]]:
    baseline = _index_items(baseline_items, identity)
    candidate = _index_items(candidate_items, identity)
    added = [
        {"identity": key, "item": candidate[key]}
        for key in sorted(candidate.keys() - baseline.keys())
    ]
    removed = [
        {"identity": key, "item": baseline[key]}
        for key in sorted(baseline.keys() - candidate.keys())
    ]
    changed = [
        {"identity": key, "baseline": baseline[key], "candidate": candidate[key]}
        for key in sorted(baseline.keys() & candidate.keys())
        if baseline[key] != candidate[key]
    ]
    unchanged = [
        {"identity": key, "item": baseline[key]}
        for key in sorted(baseline.keys() & candidate.keys())
        if baseline[key] == candidate[key]
    ]
    return {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged}


def _index_items(
    items: list[dict[str, Any]],
    identity: Callable[[dict[str, Any]], str],
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = identity(item)
        if key:
            indexed[key] = item
    return indexed


def _finding_identity(item: dict[str, Any]) -> str:
    return f"{item.get('ruleId', '')}|{item.get('file', '')}|{item.get('line', '')}"


def _uncertainty_identity(item: dict[str, Any]) -> str:
    return f"{item.get('ruleId', '')}|{item.get('file', '')}"


def _scalar_change(baseline: Any, candidate: Any) -> dict[str, Any]:
    return {"baseline": baseline, "candidate": candidate, "changed": baseline != candidate}


def _collection_changed(collection: dict[str, list[dict[str, Any]]]) -> bool:
    return bool(collection["added"] or collection["removed"] or collection["changed"])


def _markdown_identity(value: object) -> str:
    return str(value).replace("`", "'").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
