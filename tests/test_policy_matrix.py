import pytest

from codex_preflight_core.command.classifier import CommandClassification
from codex_preflight_core.command.scope import CommandScope
from codex_preflight_core.policy.decision import Decision
from codex_preflight_core.policy.engine import evaluate_policy
from codex_preflight_core.policy.matrix import (
    is_hard_block,
    matrix_rule_ids,
    max_decision,
    minimum_decision_for,
)
from codex_preflight_core.scanner.engine import list_rule_ids
from codex_preflight_core.scanner.finding import Finding, Severity

HARD_BLOCK_RULE_IDS = {
    "COMMAND_POWERSHELL_ENCODED",
    "COMMAND_POWERSHELL_REMOTE_EXEC",
    "COMMAND_REMOTE_SHELL_PIPE",
    "DOCKER_REACHABLE_RUN_REMOTE_EXEC",
    "MCP_SECRET_ENV_EXPOSURE",
    "NODE_LIFECYCLE_REMOTE_EXEC",
    "POWERSHELL_ENCODED_COMMAND",
    "SECRET_GITHUB_TOKEN",
    "SECRET_OPENAI_KEY",
    "SECRET_PRIVATE_KEY",
    "SHELL_DECODE_EXEC",
}

ASK_USER_RULE_IDS = {
    "AGENT_SECRET_EXFILTRATION_REQUEST",
    "AGENT_UNSAFE_COMMAND_REQUEST",
    "COMMAND_DOCKER_HOST_ROOT_MOUNT",
    "COMMAND_DOCKER_PRIVILEGED",
    "COMMAND_DOCKER_SOCKET_MOUNT",
    "COMMAND_INLINE_INTERPRETER_EXEC",
    "COMMAND_MCP_BROAD_STARTUP",
    "DOCKER_BROAD_HOST_MOUNT",
    "DOCKER_PRIVILEGED_CONTAINER",
    "DOCKER_REACHABLE_ENTRYPOINT_SCRIPT",
    "DOCKER_REMOTE_SCRIPT_EXEC",
    "DOCKER_SOCKET_MOUNT",
    "JS_CHILD_PROCESS_EXEC",
    "JS_DYNAMIC_EVAL",
    "JS_ENV_ACCESS",
    "JS_NETWORK_ACCESS",
    "MCP_BROAD_FILESYSTEM_ACCESS",
    "MCP_REMOTE_EXEC_ARGUMENTS",
    "MCP_SHELL_COMMAND",
    "NODE_LIFECYCLE_SCRIPT",
    "NODE_POSTINSTALL_SCRIPT",
    "NODE_PREINSTALL_SCRIPT",
    "NODE_PREPARE_SCRIPT",
    "PYTHON_DYNAMIC_EXEC",
    "PYTHON_ENV_ACCESS",
    "PYTHON_NETWORK_ACCESS",
    "PYTHON_SETUP_REMOTE_FETCH",
    "PYTHON_SUBPROCESS_EXEC",
    "SCRIPT_CHAIN_DEPTH_EXCEEDED",
    "SCRIPT_DYNAMIC_COMMAND_CONSTRUCTION",
    "SCRIPT_DYNAMIC_MODULE_REFERENCE",
    "SCRIPT_EXTERNAL_PACKAGE_EXECUTION",
    "SCRIPT_INDIRECT_EXECUTION",
    "SCRIPT_NODE_BUDGET_EXCEEDED",
    "SCRIPT_PARSE_UNCERTAIN",
    "SCRIPT_TARGET_MISSING",
    "SCRIPT_TARGET_OUTSIDE_REPO",
    "SCRIPT_TASK_RUNNER_UNRESOLVED",
    "SCRIPT_UNKNOWN_INTERPRETER",
    "SECRET_AWS_KEY",
    "SECRET_ENV_FILE",
    "SHELL_BASE64_EXEC",
    "SHELL_CURL_PIPE_BASH",
    "SHELL_DESTRUCTIVE_RM",
    "SHELL_DOWNLOAD_CAPABILITY",
    "SHELL_EVAL_USAGE",
    "SHELL_SOURCE_INDIRECTION",
    "SHELL_WGET_PIPE_SH",
}

WARN_CONTEXTUAL_RULE_IDS = {
    "AGENT_DISABLE_SAFETY",
    "AGENT_IGNORE_INSTRUCTIONS",
    "GHA_PULL_REQUEST_TARGET",
    "GHA_REMOTE_SCRIPT_EXEC",
    "GHA_SELF_HOSTED_RUNNER",
    "GHA_UNPINNED_ACTION",
    "GHA_WRITE_ALL_PERMISSIONS",
    "REPORT_SIZE_BUDGET_EXCEEDED",
}

KNOWN_RULE_IDS = HARD_BLOCK_RULE_IDS | ASK_USER_RULE_IDS | WARN_CONTEXTUAL_RULE_IDS


def test_policy_matrix_covers_known_rule_ids() -> None:
    assert matrix_rule_ids() == KNOWN_RULE_IDS


def test_static_scanner_rule_ids_have_matrix_entries() -> None:
    assert set(list_rule_ids()) <= matrix_rule_ids()


def test_policy_matrix_entries_have_rationales() -> None:
    from codex_preflight_core.policy.matrix import POLICY_MATRIX

    assert all(entry.rationale for entry in POLICY_MATRIX.values())


@pytest.mark.parametrize("rule_id", sorted(HARD_BLOCK_RULE_IDS))
def test_hard_block_rules_always_block(rule_id: str) -> None:
    assert is_hard_block(rule_id)
    assert minimum_decision_for(rule_id, CommandScope.SAFE_READONLY) == Decision.BLOCK

    policy = evaluate_policy([_finding(rule_id, Severity.LOW)], _classification(CommandScope.SAFE_READONLY))

    assert policy.decision == Decision.BLOCK


@pytest.mark.parametrize(
    "rule_id",
    [
        "SCRIPT_TARGET_MISSING",
        "SCRIPT_TARGET_OUTSIDE_REPO",
        "SCRIPT_PARSE_UNCERTAIN",
        "SCRIPT_EXTERNAL_PACKAGE_EXECUTION",
        "SCRIPT_TASK_RUNNER_UNRESOLVED",
        "SCRIPT_DYNAMIC_COMMAND_CONSTRUCTION",
        "SCRIPT_DYNAMIC_MODULE_REFERENCE",
    ],
)
def test_uncertainty_rules_are_not_safe_for_execution_scopes(rule_id: str) -> None:
    assert minimum_decision_for(rule_id, CommandScope.SCRIPT_EXECUTION) == Decision.ASK_USER

    policy = evaluate_policy([_finding(rule_id, Severity.MEDIUM)], _classification(CommandScope.SCRIPT_EXECUTION))

    assert policy.decision == Decision.ASK_USER


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("COMMAND_REMOTE_SHELL_PIPE", Decision.BLOCK),
        ("COMMAND_POWERSHELL_ENCODED", Decision.BLOCK),
        ("COMMAND_POWERSHELL_REMOTE_EXEC", Decision.BLOCK),
        ("COMMAND_DOCKER_PRIVILEGED", Decision.ASK_USER),
        ("COMMAND_DOCKER_SOCKET_MOUNT", Decision.ASK_USER),
        ("COMMAND_INLINE_INTERPRETER_EXEC", Decision.ASK_USER),
    ],
)
def test_command_self_risk_policy_minimums(rule_id: str, expected: Decision) -> None:
    assert minimum_decision_for(rule_id, CommandScope.SCRIPT_EXECUTION) == expected


def test_safe_readonly_contextual_findings_warn_but_hard_blocks_still_block() -> None:
    contextual = evaluate_policy(
        [_finding("AGENT_IGNORE_INSTRUCTIONS", Severity.HIGH)],
        _classification(CommandScope.SAFE_READONLY),
    )
    hard_block = evaluate_policy(
        [_finding("SECRET_PRIVATE_KEY", Severity.CRITICAL)],
        _classification(CommandScope.SAFE_READONLY),
    )

    assert contextual.decision == Decision.WARN
    assert hard_block.decision == Decision.BLOCK


def test_critical_severity_behavior_is_explicit() -> None:
    threshold_only = evaluate_policy(
        [_finding("UNKNOWN_CRITICAL_RULE", Severity.CRITICAL)],
        _classification(CommandScope.SCRIPT_EXECUTION),
    )
    matrix_minimum = evaluate_policy(
        [_finding("COMMAND_INLINE_INTERPRETER_EXEC", Severity.CRITICAL)],
        _classification(CommandScope.SCRIPT_EXECUTION),
    )
    hard_block = evaluate_policy(
        [_finding("SECRET_OPENAI_KEY", Severity.CRITICAL)],
        _classification(CommandScope.SCRIPT_EXECUTION),
    )

    assert threshold_only.decision == Decision.ASK_USER
    assert matrix_minimum.decision == Decision.ASK_USER
    assert hard_block.decision == Decision.BLOCK


def test_max_decision_uses_execution_gate_ordering() -> None:
    assert max_decision(Decision.ALLOW, Decision.WARN, Decision.ASK_USER) == Decision.ASK_USER
    assert max_decision(Decision.ASK_USER, Decision.BLOCK) == Decision.BLOCK


def _classification(scope: CommandScope) -> CommandClassification:
    return CommandClassification(raw="test command", scope=scope, reason="test")


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=rule_id,
        file="test.txt",
        line=1,
        evidence=rule_id,
        why_it_matters="policy test",
        recommendation="review",
    )
