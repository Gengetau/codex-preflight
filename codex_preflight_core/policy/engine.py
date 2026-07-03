from codex_preflight_core.command.classifier import CommandClassification
from codex_preflight_core.command.scope import CommandScope
from codex_preflight_core.policy.decision import Decision, PolicyResult
from codex_preflight_core.policy.scoring import SEVERITY_SCORES
from codex_preflight_core.scanner.finding import Finding

BLOCK_OVERRIDES = {
    "SECRET_PRIVATE_KEY",
    "SECRET_GITHUB_TOKEN",
    "SECRET_OPENAI_KEY",
    "NODE_LIFECYCLE_REMOTE_EXEC",
    "POWERSHELL_ENCODED_COMMAND",
    "MCP_SECRET_ENV_EXPOSURE",
    "SHELL_DECODE_EXEC",
    "DOCKER_REACHABLE_RUN_REMOTE_EXEC",
    "COMMAND_REMOTE_SHELL_PIPE",
    "COMMAND_POWERSHELL_ENCODED",
    "COMMAND_POWERSHELL_REMOTE_EXEC",
}
ASK_USER_MINIMUM = {
    "NODE_LIFECYCLE_SCRIPT",
    "NODE_POSTINSTALL_SCRIPT",
    "NODE_PREINSTALL_SCRIPT",
    "NODE_PREPARE_SCRIPT",
    "AGENT_SECRET_EXFILTRATION_REQUEST",
    "AGENT_UNSAFE_COMMAND_REQUEST",
    "DOCKER_SOCKET_MOUNT",
    "SCRIPT_INDIRECT_EXECUTION",
    "SCRIPT_TARGET_MISSING",
    "SCRIPT_TARGET_OUTSIDE_REPO",
    "SCRIPT_CHAIN_DEPTH_EXCEEDED",
    "SCRIPT_NODE_BUDGET_EXCEEDED",
    "SCRIPT_UNKNOWN_INTERPRETER",
    "SCRIPT_PARSE_UNCERTAIN",
    "SCRIPT_DYNAMIC_COMMAND_CONSTRUCTION",
    "JS_CHILD_PROCESS_EXEC",
    "JS_DYNAMIC_EVAL",
    "JS_NETWORK_ACCESS",
    "JS_ENV_ACCESS",
    "PYTHON_SUBPROCESS_EXEC",
    "PYTHON_DYNAMIC_EXEC",
    "PYTHON_NETWORK_ACCESS",
    "PYTHON_ENV_ACCESS",
    "SHELL_SOURCE_INDIRECTION",
    "SHELL_EVAL_USAGE",
    "SHELL_DOWNLOAD_CAPABILITY",
    "DOCKER_REACHABLE_ENTRYPOINT_SCRIPT",
    "COMMAND_DOCKER_PRIVILEGED",
    "COMMAND_DOCKER_HOST_ROOT_MOUNT",
    "COMMAND_DOCKER_SOCKET_MOUNT",
    "COMMAND_INLINE_INTERPRETER_EXEC",
    "COMMAND_MCP_BROAD_STARTUP",
}


def evaluate_policy(
    findings: list[Finding],
    classification: CommandClassification,
) -> PolicyResult:
    risk_score = sum(SEVERITY_SCORES[finding.severity] for finding in findings)
    rule_ids = {finding.rule_id for finding in findings}

    if rule_ids & BLOCK_OVERRIDES:
        return _result(Decision.BLOCK, risk_score, "A hard-blocking finding was detected.")

    decision = _threshold_decision(risk_score)

    if rule_ids & ASK_USER_MINIMUM:
        if classification.scope == CommandScope.SAFE_READONLY and decision == Decision.ASK_USER:
            decision = Decision.WARN
        elif decision in {Decision.ALLOW, Decision.WARN} and classification.scope != CommandScope.SAFE_READONLY:
            decision = Decision.ASK_USER

    if classification.scope == CommandScope.SAFE_READONLY and decision == Decision.ASK_USER:
        decision = Decision.WARN

    if not findings and classification.scope == CommandScope.UNKNOWN_SHELL:
        decision = Decision.WARN
        risk_score = max(risk_score, 10)

    reason = {
        Decision.ALLOW: "No relevant static risk findings were detected.",
        Decision.WARN: "Low or contextual risks were detected.",
        Decision.ASK_USER: "The command should not run automatically without user review.",
        Decision.BLOCK: "A critical finding blocks automatic execution.",
    }[decision]
    return _result(decision, risk_score, reason)


def _threshold_decision(score: int) -> Decision:
    if score <= 9:
        return Decision.ALLOW
    if score <= 24:
        return Decision.WARN
    if score <= 74:
        return Decision.ASK_USER
    return Decision.BLOCK


def _result(decision: Decision, score: int, reason: str) -> PolicyResult:
    instruction = {
        Decision.ALLOW: "Proceed normally.",
        Decision.WARN: "Summarize the warning briefly before proceeding.",
        Decision.ASK_USER: "Do not execute the command yet. Summarize findings and ask the user.",
        Decision.BLOCK: "Do not execute the command. Explain the blocking finding.",
    }[decision]
    return PolicyResult(decision=decision, risk_score=score, reason=reason, agent_instruction=instruction)
