from dataclasses import dataclass, field

from codex_preflight_core.command.scope import CommandScope
from codex_preflight_core.policy.decision import Decision

DECISION_RANK = {
    Decision.ALLOW: 0,
    Decision.WARN: 1,
    Decision.ASK_USER: 2,
    Decision.BLOCK: 3,
}


@dataclass(frozen=True)
class PolicyMatrixEntry:
    rule_id: str
    default_minimum: Decision
    scope_minimums: dict[CommandScope, Decision] = field(default_factory=dict)
    hard_block: bool = False
    rationale: str = ""


def minimum_decision_for(rule_id: str, scope: CommandScope) -> Decision | None:
    entry = POLICY_MATRIX.get(rule_id)
    if entry is None:
        return None
    return entry.scope_minimums.get(scope, entry.default_minimum)


def is_hard_block(rule_id: str) -> bool:
    entry = POLICY_MATRIX.get(rule_id)
    return bool(entry and entry.hard_block)


def matrix_rule_ids() -> set[str]:
    return set(POLICY_MATRIX)


def max_decision(*decisions: Decision) -> Decision:
    if not decisions:
        return Decision.ALLOW
    return max(decisions, key=lambda decision: DECISION_RANK[decision])


def _entry(
    rule_id: str,
    minimum: Decision,
    *,
    hard_block: bool = False,
    rationale: str,
    scope_minimums: dict[CommandScope, Decision] | None = None,
) -> PolicyMatrixEntry:
    return PolicyMatrixEntry(
        rule_id=rule_id,
        default_minimum=minimum,
        scope_minimums=scope_minimums or {},
        hard_block=hard_block,
        rationale=rationale,
    )


def _hard(rule_id: str, rationale: str) -> PolicyMatrixEntry:
    return _entry(rule_id, Decision.BLOCK, hard_block=True, rationale=rationale)


def _ask(rule_id: str, rationale: str) -> PolicyMatrixEntry:
    return _entry(rule_id, Decision.ASK_USER, rationale=rationale)


def _warn(rule_id: str, rationale: str) -> PolicyMatrixEntry:
    return _entry(rule_id, Decision.WARN, rationale=rationale)


def _readme_download(rule_id: str, rationale: str) -> PolicyMatrixEntry:
    return _entry(
        rule_id,
        Decision.ASK_USER,
        rationale=rationale,
        scope_minimums={CommandScope.SAFE_READONLY: Decision.WARN},
    )


POLICY_MATRIX: dict[str, PolicyMatrixEntry] = {
    entry.rule_id: entry
    for entry in (
        _hard("COMMAND_POWERSHELL_ENCODED", "Encoded planned PowerShell hides execution content."),
        _hard("COMMAND_POWERSHELL_REMOTE_EXEC", "Planned PowerShell downloads and executes remote content."),
        _hard("COMMAND_REMOTE_SHELL_PIPE", "Planned command pipes remote content into a shell."),
        _hard("DOCKER_REACHABLE_RUN_REMOTE_EXEC", "Reachable Dockerfile runs remote shell content."),
        _hard("MCP_SECRET_ENV_EXPOSURE", "MCP configuration can expose secrets to a server process."),
        _hard("NODE_LIFECYCLE_REMOTE_EXEC", "Package lifecycle script directly executes remote shell content."),
        _hard("POWERSHELL_ENCODED_COMMAND", "Repository script contains encoded PowerShell."),
        _hard("SECRET_GITHUB_TOKEN", "GitHub tokens should block automatic execution."),
        _hard("SECRET_OPENAI_KEY", "OpenAI API keys should block automatic execution."),
        _hard("SECRET_PRIVATE_KEY", "Private keys should block automatic execution."),
        _hard("SHELL_DECODE_EXEC", "Reachable shell decodes and executes command content."),
        _ask("AGENT_SECRET_EXFILTRATION_REQUEST", "Agent instructions request secret disclosure."),
        _ask("AGENT_UNSAFE_COMMAND_REQUEST", "Agent instructions request unsafe command execution."),
        _ask("COMMAND_DOCKER_HOST_ROOT_MOUNT", "Planned Docker command mounts the host root filesystem."),
        _ask("COMMAND_DOCKER_PRIVILEGED", "Planned Docker command enables privileged mode."),
        _ask("COMMAND_DOCKER_SOCKET_MOUNT", "Planned Docker command mounts the Docker socket."),
        _ask("COMMAND_INLINE_INTERPRETER_EXEC", "Planned command runs inline interpreter code."),
        _ask("COMMAND_MCP_BROAD_STARTUP", "Planned command starts a broad-access server process."),
        _ask("DOCKER_BROAD_HOST_MOUNT", "Docker configuration mounts broad host filesystem paths."),
        _ask("DOCKER_PRIVILEGED_CONTAINER", "Docker configuration enables privileged or host-network behavior."),
        _ask("DOCKER_REACHABLE_ENTRYPOINT_SCRIPT", "Reachable Docker entrypoint invokes a local script."),
        _ask("DOCKER_REMOTE_SCRIPT_EXEC", "Docker configuration contains remote script execution."),
        _ask("DOCKER_SOCKET_MOUNT", "Docker configuration mounts the Docker socket."),
        _ask("JS_CHILD_PROCESS_EXEC", "Reachable Node.js code can start child processes."),
        _ask("JS_DYNAMIC_EVAL", "Reachable Node.js code uses dynamic evaluation."),
        _ask("JS_ENV_ACCESS", "Reachable Node.js code reads environment variables."),
        _ask("JS_NETWORK_ACCESS", "Reachable Node.js code can access the network."),
        _ask("MCP_BROAD_FILESYSTEM_ACCESS", "MCP configuration grants broad filesystem access."),
        _ask("MCP_REMOTE_EXEC_ARGUMENTS", "MCP configuration contains remote execution-like arguments."),
        _ask("MCP_SHELL_COMMAND", "MCP configuration starts a shell-backed server command."),
        _ask("NODE_LIFECYCLE_SCRIPT", "Package lifecycle scripts can execute during dependency installation."),
        _ask("NODE_POSTINSTALL_SCRIPT", "postinstall scripts can execute during dependency installation."),
        _ask("NODE_PREINSTALL_SCRIPT", "preinstall scripts can execute during dependency installation."),
        _ask("NODE_PREPARE_SCRIPT", "prepare scripts can execute during dependency installation."),
        _ask("PYTHON_DYNAMIC_EXEC", "Reachable Python code uses dynamic execution."),
        _ask("PYTHON_ENV_ACCESS", "Reachable Python code reads environment variables."),
        _ask("PYTHON_NETWORK_ACCESS", "Reachable Python code can access the network."),
        _ask("PYTHON_SETUP_REMOTE_FETCH", "Python setup code fetches remote content."),
        _ask("PYTHON_SUBPROCESS_EXEC", "Reachable Python code can start subprocesses."),
        _readme_download("README_DEFEAT_SECURITY_WARNING", "README text encourages bypassing security warnings."),
        _readme_download(
            "README_FAKE_RELEASE_LINK",
            "README release/download wording points away from expected releases.",
        ),
        _readme_download(
            "README_INSTALLER_FROM_NON_RELEASE_HOST",
            "README installer/download wording points outside GitHub release assets.",
        ),
        _readme_download("README_RAW_SOURCE_ARCHIVE_DOWNLOAD", "README download wording points to raw source content."),
        _ask("SCRIPT_CHAIN_DEPTH_EXCEEDED", "Reachability exceeded static chain-depth budget."),
        _ask("SCRIPT_DYNAMIC_COMMAND_CONSTRUCTION", "Reachable command construction is dynamic."),
        _ask("SCRIPT_DYNAMIC_MODULE_REFERENCE", "Reachable Node.js module reference is dynamic."),
        _ask("SCRIPT_EXTERNAL_PACKAGE_EXECUTION", "Command reaches external package or tool execution."),
        _ask("SCRIPT_INDIRECT_EXECUTION", "Dependency or script execution reaches another local script."),
        _ask("SCRIPT_NODE_BUDGET_EXCEEDED", "Reachability exceeded static node budget."),
        _ask("SCRIPT_PARSE_UNCERTAIN", "Static parser could not fully resolve an execution path."),
        _ask("SCRIPT_TARGET_MISSING", "Referenced local script target is missing."),
        _ask("SCRIPT_TARGET_OUTSIDE_REPO", "Referenced script target is outside the repository."),
        _ask("SCRIPT_TASK_RUNNER_UNRESOLVED", "Task runner configuration could not be resolved statically."),
        _ask("SCRIPT_UNKNOWN_INTERPRETER", "Static parser could not identify the interpreter."),
        _ask("SECRET_AWS_KEY", "AWS access keys require user review before execution."),
        _ask("SECRET_ENV_FILE", "Environment files can expose sensitive runtime configuration."),
        _ask("SHELL_BASE64_EXEC", "Repository shell content decodes and executes commands."),
        _ask("SHELL_CURL_PIPE_BASH", "Repository shell content pipes curl output to bash."),
        _ask("SHELL_DESTRUCTIVE_RM", "Repository shell content contains destructive root deletion."),
        _ask("SHELL_DOWNLOAD_CAPABILITY", "Reachable shell content can download remote data."),
        _ask("SHELL_EVAL_USAGE", "Reachable shell content uses eval."),
        _ask("SHELL_SOURCE_INDIRECTION", "Reachable shell content sources another script."),
        _ask("SHELL_WGET_PIPE_SH", "Repository shell content pipes wget output to sh."),
        _warn("AGENT_DISABLE_SAFETY", "Agent instruction safety-disable text is contextual repository risk."),
        _warn("AGENT_IGNORE_INSTRUCTIONS", "Agent instruction override text is contextual repository risk."),
        _warn("GHA_PULL_REQUEST_TARGET", "GitHub Actions pull_request_target needs workflow review."),
        _warn("GHA_REMOTE_SCRIPT_EXEC", "GitHub Actions workflow contains remote script execution."),
        _warn("GHA_SELF_HOSTED_RUNNER", "GitHub Actions workflow uses a self-hosted runner."),
        _warn("GHA_UNPINNED_ACTION", "GitHub Actions workflow uses an unpinned action."),
        _warn("GHA_WRITE_ALL_PERMISSIONS", "GitHub Actions workflow grants broad write permissions."),
        _warn("REPORT_SIZE_BUDGET_EXCEEDED", "Report details were capped after policy evaluation."),
    )
}
