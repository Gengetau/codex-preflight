from codex_preflight_core.command.classifier import CommandClassification
from codex_preflight_core.command.scope import CommandScope
from codex_preflight_core.policy.decision import Decision, PolicyResult
from codex_preflight_core.policy.matrix import is_hard_block, max_decision, minimum_decision_for
from codex_preflight_core.policy.scoring import SEVERITY_SCORES
from codex_preflight_core.scanner.finding import Finding


def evaluate_policy(
    findings: list[Finding],
    classification: CommandClassification,
) -> PolicyResult:
    risk_score = sum(SEVERITY_SCORES[finding.severity] for finding in findings)
    rule_ids = {finding.rule_id for finding in findings}

    if any(is_hard_block(rule_id) for rule_id in rule_ids):
        return _result(Decision.BLOCK, risk_score, "A hard-blocking finding was detected.")

    threshold_decision = _threshold_decision(risk_score)
    decision = threshold_decision
    matrix_minimum = Decision.ALLOW

    for rule_id in rule_ids:
        minimum = minimum_decision_for(rule_id, classification.scope)
        if minimum is not None:
            matrix_minimum = max_decision(matrix_minimum, minimum)
            decision = max_decision(decision, minimum)

    safe_readonly_downgraded = False
    if classification.scope == CommandScope.SAFE_READONLY and decision == Decision.ASK_USER:
        decision = Decision.WARN
        safe_readonly_downgraded = True

    if not findings and classification.scope == CommandScope.UNKNOWN_SHELL:
        decision = Decision.WARN
        risk_score = max(risk_score, 10)
        return _result(decision, risk_score, "Unknown shell command without static findings requires caution.")

    reason = _reason(
        decision,
        threshold_decision=threshold_decision,
        matrix_minimum=matrix_minimum,
        safe_readonly_downgraded=safe_readonly_downgraded,
    )
    return _result(decision, risk_score, reason)


def _threshold_decision(score: int) -> Decision:
    if score <= 9:
        return Decision.ALLOW
    if score <= 24:
        return Decision.WARN
    if score <= 74:
        return Decision.ASK_USER
    return Decision.BLOCK


def _reason(
    decision: Decision,
    *,
    threshold_decision: Decision,
    matrix_minimum: Decision,
    safe_readonly_downgraded: bool,
) -> str:
    if safe_readonly_downgraded:
        return "Safe read-only command scope downgraded contextual user-review findings to warning."
    if decision == matrix_minimum and matrix_minimum != Decision.ALLOW:
        return "A policy matrix minimum applies to one or more findings for this command scope."
    if decision == threshold_decision and threshold_decision != Decision.ALLOW:
        return "Risk score threshold determines the policy decision."
    return {
        Decision.ALLOW: "No relevant static risk findings were detected.",
        Decision.WARN: "Low or contextual risks were detected.",
        Decision.ASK_USER: "The command should not run automatically without user review.",
        Decision.BLOCK: "A critical finding blocks automatic execution.",
    }[decision]


def _result(decision: Decision, score: int, reason: str) -> PolicyResult:
    instruction = {
        Decision.ALLOW: "Proceed normally.",
        Decision.WARN: "Summarize the warning briefly before proceeding.",
        Decision.ASK_USER: "Do not execute the command yet. Summarize findings and ask the user.",
        Decision.BLOCK: "Do not execute the command. Explain the blocking finding.",
    }[decision]
    return PolicyResult(decision=decision, risk_score=score, reason=reason, agent_instruction=instruction)
