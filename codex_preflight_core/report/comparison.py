import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 2 * 1024 * 1024
SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
VALID_DECISIONS = {"ALLOW", "WARN", "ASK_USER", "BLOCK"}
VALID_POLICY_SELECTORS = {
    "trust_approval",
    "hard_block_rule",
    "command_scope",
    "scope_adjustment",
    "policy_matrix",
    "risk_score",
    "no_gate",
}
_RULE_ID = re.compile(r"^[A-Z][A-Z0-9_]*$")
_WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
_SCHEME_PATH = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:/")
_SCP_LIKE_PATH = re.compile(r"^(?:[^@\s/\\]+@)?[^:\s/\\]+:.+")
_NORMALIZED_SCP_PATH = re.compile(r"^[^@\s/]+@[^/\s]+/.+")
_CLONE_HELPER = re.compile(r"^(?:git\s+clone|gh\s+repo\s+clone|hg\s+clone|svn\s+checkout)\b", re.I)


@dataclass(frozen=True)
class ReportComparisonError(ValueError):
    code: str
    message: str
    path: str | Path

    def __str__(self) -> str:
        return self.message

    def to_report(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, "path": str(self.path)}}


def compare_report_files(baseline_path: str | Path, candidate_path: str | Path) -> dict[str, Any]:
    baseline_path = validate_local_report_path(baseline_path, "baseline")
    candidate_path = validate_local_report_path(candidate_path, "candidate")
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
    command_contribution = _scalar_change(
        baseline_policy.get("commandContribution"),
        candidate_policy.get("commandContribution"),
    )
    changed = any(
        (
            decision["changed"],
            classification["changed"],
            selection["changed"],
            command_contribution["changed"],
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
        "commandContribution": command_contribution,
        "findings": findings,
        "policyContributions": contributions,
        "executionCapabilities": capabilities,
        "uncertainties": uncertainties,
        "volatileFieldsIgnored": ["cache", "repo.path"],
    }


def validate_local_report_path(value: str | Path, field: str) -> Path:
    raw = str(value).strip()
    normalized = raw.replace("\\", "/")
    is_windows_drive = bool(_WINDOWS_DRIVE_PATH.match(raw))
    if not raw:
        raise ReportComparisonError("invalid_report_path", f"{field} path must not be empty.", raw)
    if (
        normalized.startswith("//")
        or (not is_windows_drive and _SCHEME_PATH.match(normalized))
        or (not is_windows_drive and _SCP_LIKE_PATH.match(raw))
        or (isinstance(value, Path) and _NORMALIZED_SCP_PATH.match(normalized))
        or _CLONE_HELPER.match(raw)
    ):
        raise ReportComparisonError(
            "remote_path_not_allowed",
            f"{field} must be a local filesystem path; remote and clone-like forms are not allowed.",
            raw,
        )
    return Path(raw).expanduser()


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
        (
            "Policy selection: "
            f"`{_format_policy_selection(comparison['policySelection']['baseline'])}` -> "
            f"`{_format_policy_selection(comparison['policySelection']['candidate'])}`"
        ),
        (
            "Command contribution: "
            f"`{_format_command_contribution(comparison['commandContribution']['baseline'])}` -> "
            f"`{_format_command_contribution(comparison['commandContribution']['candidate'])}`"
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
    if not isinstance(schema_version, str):
        raise ReportComparisonError("incompatible_report", "Report schemaVersion must be a string.", path)
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ReportComparisonError(
            "unsupported_schema",
            f"Unsupported report schema version: {schema_version!r}.",
            path,
        )
    decision = payload.get("decision")
    if not isinstance(decision, str) or decision not in VALID_DECISIONS:
        raise ReportComparisonError("incompatible_report", "Report decision is missing or invalid.", path)
    if not isinstance(payload.get("commandScope"), str):
        raise ReportComparisonError("incompatible_report", "Report commandScope must be a string.", path)
    findings = _validate_object_list(payload.get("findings"), "findings", path)
    _validate_finding_identities(findings, "findings", path)
    execution_graph = payload.get("executionGraph")
    if not isinstance(execution_graph, dict):
        raise ReportComparisonError("incompatible_report", "Report executionGraph must be an object.", path)
    capabilities = _validate_object_list(
        execution_graph.get("capabilities", []),
        "executionGraph.capabilities",
        path,
    )
    uncertainties = _validate_object_list(
        execution_graph.get("uncertainties", []),
        "executionGraph.uncertainties",
        path,
    )
    _validate_finding_identities(capabilities, "executionGraph.capabilities", path)
    _validate_uncertainty_identities(uncertainties, path)
    policy_explanation = payload.get("policyExplanation")
    if policy_explanation is not None and not isinstance(policy_explanation, dict):
        raise ReportComparisonError("incompatible_report", "Report policyExplanation must be an object.", path)
    if policy_explanation is not None:
        contributions = _validate_object_list(
            policy_explanation.get("ruleContributions", []),
            "policyExplanation.ruleContributions",
            path,
        )
        _validate_rule_identities(contributions, "policyExplanation.ruleContributions", path)
        if "selectedBy" in policy_explanation:
            _validate_policy_selection(policy_explanation["selectedBy"], path)
        if "commandContribution" in policy_explanation:
            _validate_command_contribution(policy_explanation["commandContribution"], path)
    return payload


def _validate_object_list(value: object, field: str, path: Path) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ReportComparisonError(
            "incompatible_report",
            f"Report {field} must be an array of objects.",
            path,
        )
    return value


def _validate_finding_identities(items: list[dict[str, Any]], field: str, path: Path) -> None:
    _validate_rule_identities(items, field, path)
    for item in items:
        line = item.get("line")
        if not isinstance(item.get("file"), str) or isinstance(line, bool) or not isinstance(line, int):
            raise ReportComparisonError(
                "incompatible_report",
                f"Report {field} items require string file and integer line identity fields.",
                path,
            )


def _validate_uncertainty_identities(items: list[dict[str, Any]], path: Path) -> None:
    field = "executionGraph.uncertainties"
    _validate_rule_identities(items, field, path)
    for item in items:
        if "file" not in item or not isinstance(item["file"], (str, type(None))):
            raise ReportComparisonError(
                "incompatible_report",
                f"Report {field} items require a string or null file identity field.",
                path,
            )


def _validate_rule_identities(items: list[dict[str, Any]], field: str, path: Path) -> None:
    if any(not isinstance(item.get("ruleId"), str) or not _RULE_ID.fullmatch(item["ruleId"]) for item in items):
        raise ReportComparisonError(
            "incompatible_report",
            f"Report {field} items require a valid ruleId identity field.",
            path,
        )


def _validate_policy_selection(value: object, path: Path) -> None:
    if not isinstance(value, dict):
        raise ReportComparisonError("incompatible_report", "Report selectedBy must be an object.", path)
    selector = value.get("type")
    decision = value.get("decision")
    rule_id = value.get("ruleId")
    if (
        not isinstance(selector, str)
        or selector not in VALID_POLICY_SELECTORS
        or not isinstance(decision, str)
        or decision not in VALID_DECISIONS
        or (rule_id is not None and (not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id)))
    ):
        raise ReportComparisonError("incompatible_report", "Report selectedBy is missing valid fields.", path)


def _validate_command_contribution(value: object, path: Path) -> None:
    if not isinstance(value, dict):
        raise ReportComparisonError(
            "incompatible_report",
            "Report commandContribution must be an object.",
            path,
        )
    risk_score = value.get("riskScore")
    minimum = value.get("minimumDecision")
    affected = value.get("affectedFinalGate")
    if (
        isinstance(risk_score, bool)
        or not isinstance(risk_score, int)
        or risk_score < 0
        or not isinstance(minimum, str)
        or minimum not in VALID_DECISIONS
        or not isinstance(affected, bool)
    ):
        raise ReportComparisonError(
            "incompatible_report",
            "Report commandContribution is missing valid fields.",
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
    baseline = _normalize_value(baseline)
    candidate = _normalize_value(candidate)
    return {"baseline": baseline, "candidate": candidate, "changed": baseline != candidate}


def _collection_changed(collection: dict[str, list[dict[str, Any]]]) -> bool:
    return bool(collection["added"] or collection["removed"] or collection["changed"])


def _markdown_identity(value: object) -> str:
    return str(value).replace("`", "'").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    return value


def _format_policy_selection(value: object) -> str:
    if not isinstance(value, dict):
        return "none"
    return _markdown_identity(
        f"{value.get('type', 'none')} / {value.get('decision', 'none')} / {value.get('ruleId') or 'none'}"
    )


def _format_command_contribution(value: object) -> str:
    if not isinstance(value, dict):
        return "none"
    effect = "gate" if value.get("affectedFinalGate") else "report-only"
    return _markdown_identity(
        f"{value.get('riskScore', 'none')} / {value.get('minimumDecision', 'none')} / {effect}"
    )
