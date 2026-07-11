from collections import defaultdict
from typing import Any

from codex_preflight_core.command.classifier import CommandClassification
from codex_preflight_core.command.scope import CommandScope
from codex_preflight_core.policy.decision import Decision, PolicyResult
from codex_preflight_core.policy.matrix import DECISION_RANK, POLICY_MATRIX, max_decision
from codex_preflight_core.policy.scoring import SEVERITY_SCORES
from codex_preflight_core.scanner.finding import Finding


def build_policy_explanation(
    findings: list[Finding],
    classification: CommandClassification,
    policy: PolicyResult,
    *,
    trusted: bool = False,
) -> dict[str, Any]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.rule_id].append(finding)

    threshold = _threshold_decision(policy.risk_score)
    matrix_minimum = Decision.ALLOW
    minimums: dict[str, Decision | None] = {}
    for rule_id in sorted(grouped):
        entry = POLICY_MATRIX.get(rule_id)
        minimum = None if entry is None else entry.scope_minimums.get(classification.scope, entry.default_minimum)
        minimums[rule_id] = minimum
        if minimum is not None:
            matrix_minimum = max_decision(matrix_minimum, minimum)

    selected = _selection(
        grouped=grouped,
        minimums=minimums,
        classification=classification,
        policy=policy,
        threshold=threshold,
        matrix_minimum=matrix_minimum,
        trusted=trusted,
    )
    contributions = [
        _rule_contribution(
            rule_id,
            grouped[rule_id],
            minimums[rule_id],
            classification,
            policy,
            selected,
        )
        for rule_id in sorted(grouped)
    ]
    command_affected = selected["type"] in {"command_scope", "risk_score", "scope_adjustment"}
    return {
        "finalDecision": policy.decision.value,
        "commandScope": classification.scope.value,
        "selectedBy": selected,
        "commandContribution": {
            "riskScore": policy.risk_score,
            "minimumDecision": threshold.value,
            "affectedFinalGate": command_affected,
        },
        "ruleContributions": contributions,
    }


def _selection(
    *,
    grouped: dict[str, list[Finding]],
    minimums: dict[str, Decision | None],
    classification: CommandClassification,
    policy: PolicyResult,
    threshold: Decision,
    matrix_minimum: Decision,
    trusted: bool,
) -> dict[str, str | None]:
    if trusted:
        return {"type": "trust_approval", "decision": policy.decision.value, "ruleId": None}
    hard_rules = sorted(
        rule_id
        for rule_id in grouped
        if POLICY_MATRIX.get(rule_id) and POLICY_MATRIX[rule_id].hard_block
    )
    if hard_rules:
        return {"type": "hard_block_rule", "decision": Decision.BLOCK.value, "ruleId": hard_rules[0]}
    if not grouped and classification.scope == CommandScope.UNKNOWN_SHELL:
        return {"type": "command_scope", "decision": policy.decision.value, "ruleId": None}
    preliminary = max_decision(threshold, matrix_minimum)
    if classification.scope == CommandScope.SAFE_READONLY and preliminary == Decision.ASK_USER:
        return {"type": "scope_adjustment", "decision": policy.decision.value, "ruleId": None}
    if matrix_minimum != Decision.ALLOW and policy.decision == matrix_minimum:
        selected_rules = sorted(rule_id for rule_id, minimum in minimums.items() if minimum == matrix_minimum)
        return {"type": "policy_matrix", "decision": policy.decision.value, "ruleId": selected_rules[0]}
    if threshold != Decision.ALLOW and policy.decision == threshold:
        return {"type": "risk_score", "decision": policy.decision.value, "ruleId": None}
    return {"type": "no_gate", "decision": policy.decision.value, "ruleId": None}


def _rule_contribution(
    rule_id: str,
    findings: list[Finding],
    minimum: Decision | None,
    classification: CommandClassification,
    policy: PolicyResult,
    selected: dict[str, str | None],
) -> dict[str, Any]:
    entry = POLICY_MATRIX.get(rule_id)
    score = sum(SEVERITY_SCORES[finding.severity] for finding in findings)
    selected_type = selected["type"]
    if selected_type == "hard_block_rule":
        affected = bool(entry and entry.hard_block)
    elif selected_type == "policy_matrix":
        affected = minimum is not None and minimum == policy.decision
    elif selected_type == "risk_score":
        affected = score > 0
    elif selected_type == "scope_adjustment":
        affected = score > 0 or (minimum is not None and DECISION_RANK[minimum] >= DECISION_RANK[Decision.WARN])
    else:
        affected = False
    return {
        "ruleId": rule_id,
        "findingCount": len(findings),
        "riskScore": score,
        "matrixMatched": entry is not None,
        "minimumDecision": minimum.value if minimum is not None else None,
        "hardBlock": bool(entry and entry.hard_block),
        "rationale": entry.rationale if entry is not None else None,
        "affectedFinalGate": affected,
        "reportOnly": not affected,
    }


def _threshold_decision(score: int) -> Decision:
    if score <= 9:
        return Decision.ALLOW
    if score <= 24:
        return Decision.WARN
    if score <= 74:
        return Decision.ASK_USER
    return Decision.BLOCK
