import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath


@dataclass(frozen=True)
class CommandTarget:
    target: str
    reason: str


@dataclass(frozen=True)
class CommandUncertainty:
    rule_id: str
    reason: str


@dataclass(frozen=True)
class ParsedCommand:
    executable: str
    args: list[str]
    local_paths: list[CommandTarget] = field(default_factory=list)
    nested_commands: list[str] = field(default_factory=list)
    package_scripts: list[str] = field(default_factory=list)
    python_modules: list[str] = field(default_factory=list)
    uncertainties: list[CommandUncertainty] = field(default_factory=list)
    normalized_display: str = ""


SHELL_EXECUTABLES = {"bash", "sh"}
PYTHON_EXECUTABLES = {"python", "python3"}
NODE_EXECUTABLES = {"node"}
POWERSHELL_EXECUTABLES = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
CMD_EXECUTABLES = {"cmd", "cmd.exe"}
PACKAGE_MANAGERS = {"npm", "pnpm", "yarn"}
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}
SCRIPT_EXTENSIONS = SHELL_EXTENSIONS | {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx"}

PYTHON_NO_VALUE_FLAGS = {
    "-b",
    "-bb",
    "-bB",
    "-e",
    "-E",
    "-i",
    "-I",
    "-O",
    "-OO",
    "-q",
    "-s",
    "-S",
    "-u",
    "-v",
    "-V",
    "--version",
}
PYTHON_VALUE_FLAGS = {"-c", "-W", "-X"}
NODE_VALUE_FLAGS = {"--require", "-r", "--loader", "--import"}
NODE_INLINE_FLAGS = {"-e", "--eval", "-p", "--print", "--check"}


def parse_reachable_command(command: str) -> ParsedCommand:
    tokens = _split(command)
    return _parse_tokens(tokens, normalized_display=" ".join(tokens) if tokens else command.strip())


def unwrap_env_command(tokens: list[str]) -> list[str]:
    if not tokens or tokens[0].lower() != "env":
        return tokens
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token in {"-i", "-", "--ignore-environment", "--null", "-0"}:
            index += 1
            continue
        if token in {"-u", "--unset"}:
            index += 2
            continue
        if token.startswith("-u") and len(token) > 2:
            index += 1
            continue
        if _is_env_assignment(token):
            index += 1
            continue
        break
    return tokens[index:]


def unwrap_shell_c_command(tokens: list[str]) -> str | None:
    if not tokens or tokens[0].lower() not in SHELL_EXECUTABLES:
        return None
    for index, token in enumerate(tokens[1:], start=1):
        if token == "-c":
            return tokens[index + 1] if index + 1 < len(tokens) else None
    return None


def extract_python_targets(tokens: list[str]) -> tuple[list[str], list[str], list[CommandUncertainty]]:
    targets: list[str] = []
    modules: list[str] = []
    uncertainties: list[CommandUncertainty] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "-m":
            if index + 1 < len(tokens):
                modules.append(tokens[index + 1])
            else:
                uncertainties.append(_parse_uncertain("Python -m flag is missing a module name."))
            return targets, modules, uncertainties
        if token in PYTHON_VALUE_FLAGS:
            if index + 1 >= len(tokens):
                uncertainties.append(_parse_uncertain(f"Python flag {token} is missing a value."))
            return targets, modules, uncertainties
        if token in PYTHON_NO_VALUE_FLAGS or _is_python_combined_flag(token):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        targets.append(normalize_repo_path_token(token))
        return targets, modules, uncertainties
    return targets, modules, uncertainties


def extract_node_targets(tokens: list[str]) -> tuple[list[str], list[CommandUncertainty]]:
    targets: list[str] = []
    uncertainties: list[CommandUncertainty] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in NODE_VALUE_FLAGS:
            if index + 1 < len(tokens):
                targets.append(normalize_repo_path_token(tokens[index + 1]))
                index += 2
                continue
            uncertainties.append(_parse_uncertain(f"Node flag {token} is missing a value."))
            return targets, uncertainties
        if token.startswith("--require="):
            targets.append(normalize_repo_path_token(token.split("=", 1)[1]))
            index += 1
            continue
        if token in NODE_INLINE_FLAGS:
            return targets, uncertainties
        if token.startswith("-"):
            index += 1
            continue
        targets.append(normalize_repo_path_token(token))
        return targets, uncertainties
    return targets, uncertainties


def extract_windows_shell_targets(tokens: list[str]) -> tuple[list[str], list[str], list[CommandUncertainty]]:
    targets: list[str] = []
    nested_commands: list[str] = []
    uncertainties: list[CommandUncertainty] = []
    if not tokens:
        return targets, nested_commands, uncertainties
    first = tokens[0].lower()
    if first in POWERSHELL_EXECUTABLES:
        for index, token in enumerate(tokens[1:], start=1):
            lowered = token.lower()
            if lowered in {"-file", "-f"}:
                if index + 1 < len(tokens):
                    targets.append(normalize_repo_path_token(tokens[index + 1]))
                else:
                    uncertainties.append(_parse_uncertain("PowerShell -File flag is missing a target."))
                return targets, nested_commands, uncertainties
            if lowered in {"-command", "-c"}:
                if index + 1 >= len(tokens):
                    uncertainties.append(_parse_uncertain("PowerShell -Command flag is missing a command."))
                    return targets, nested_commands, uncertainties
                command = tokens[index + 1]
                if _is_local_path_token(command):
                    targets.append(normalize_repo_path_token(command))
                else:
                    nested_commands.append(command)
                return targets, nested_commands, uncertainties
    if first in CMD_EXECUTABLES:
        for index, token in enumerate(tokens[1:], start=1):
            if token.lower() in {"/c", "-c"}:
                if index + 1 < len(tokens):
                    nested_commands.append(" ".join(tokens[index + 1 :]))
                else:
                    uncertainties.append(_parse_uncertain("cmd /c is missing a command."))
                return targets, nested_commands, uncertainties
    return targets, nested_commands, uncertainties


def normalize_repo_path_token(token: str) -> str:
    cleaned = token.strip().strip("\"'")
    cleaned = cleaned.replace("\\", "/")
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def _parse_tokens(tokens: list[str], *, normalized_display: str) -> ParsedCommand:
    tokens = [token.strip("\"'") for token in tokens if token.strip("\"'")]
    if not tokens:
        return ParsedCommand("", [], normalized_display=normalized_display)

    env_unwrapped = unwrap_env_command(tokens)
    if env_unwrapped != tokens:
        parsed = _parse_tokens(env_unwrapped, normalized_display=" ".join(env_unwrapped))
        return ParsedCommand(
            executable=parsed.executable,
            args=parsed.args,
            local_paths=parsed.local_paths,
            nested_commands=parsed.nested_commands,
            package_scripts=parsed.package_scripts,
            python_modules=parsed.python_modules,
            uncertainties=parsed.uncertainties,
            normalized_display=parsed.normalized_display,
        )

    executable = tokens[0].lower()
    args = tokens[1:]
    local_paths: list[CommandTarget] = []
    nested_commands: list[str] = []
    package_scripts: list[str] = []
    python_modules: list[str] = []
    uncertainties: list[CommandUncertainty] = []

    if executable in SHELL_EXECUTABLES:
        inner = unwrap_shell_c_command(tokens)
        if inner is not None:
            if inner:
                nested_commands.append(inner)
            else:
                uncertainties.append(_parse_uncertain("Shell -c flag is missing a command string."))
        else:
            target = _first_non_option(args)
            if target:
                local_paths.append(CommandTarget(normalize_repo_path_token(target), "command invokes local script"))
        return ParsedCommand(executable, args, local_paths, nested_commands, uncertainties=uncertainties)

    if executable in PYTHON_EXECUTABLES:
        targets, modules, parsed_uncertainties = extract_python_targets(tokens)
        local_paths.extend(CommandTarget(target, "python command invokes local script") for target in targets)
        python_modules.extend(modules)
        uncertainties.extend(parsed_uncertainties)
        return ParsedCommand(executable, args, local_paths, python_modules=python_modules, uncertainties=uncertainties)

    if executable in NODE_EXECUTABLES:
        targets, parsed_uncertainties = extract_node_targets(tokens)
        local_paths.extend(CommandTarget(target, "node command reaches local script") for target in targets)
        uncertainties.extend(parsed_uncertainties)
        return ParsedCommand(executable, args, local_paths, uncertainties=uncertainties)

    win_targets, win_nested, win_uncertainties = extract_windows_shell_targets(tokens)
    if win_targets or win_nested or win_uncertainties:
        local_paths.extend(
            CommandTarget(target, "windows shell command reaches local script") for target in win_targets
        )
        nested_commands.extend(win_nested)
        uncertainties.extend(win_uncertainties)
        return ParsedCommand(executable, args, local_paths, nested_commands, uncertainties=uncertainties)

    script_name = _package_script_name(tokens)
    if script_name:
        package_scripts.append(script_name)
        return ParsedCommand(executable, args, package_scripts=package_scripts)

    if _is_external_package_execution(tokens):
        tool = (
            tokens[2]
            if executable in {"pnpm", "yarn"} and len(tokens) >= 3
            else tokens[1]
            if len(tokens) >= 2
            else ""
        )
        if _is_local_path_token(tool):
            local_paths.append(CommandTarget(normalize_repo_path_token(tool), "package manager executes local tool"))
        else:
            uncertainties.append(
                CommandUncertainty(
                    "SCRIPT_EXTERNAL_PACKAGE_EXECUTION",
                    f"Package manager may execute external package or tool: {' '.join(tokens)}",
                )
            )
        return ParsedCommand(executable, args, local_paths, uncertainties=uncertainties)

    if executable == "deno" and len(tokens) >= 3 and tokens[1].lower() == "run":
        local_paths.append(CommandTarget(normalize_repo_path_token(tokens[2]), "deno run reaches local script"))
        return ParsedCommand(executable, args, local_paths)

    if executable == "deno" and len(tokens) >= 3 and tokens[1].lower() == "task":
        uncertainties.append(
            CommandUncertainty(
                "SCRIPT_TASK_RUNNER_UNRESOLVED",
                f"Deno task was not statically resolved: {' '.join(tokens)}",
            )
        )
        return ParsedCommand(executable, args, uncertainties=uncertainties)

    if executable == "bun" and len(tokens) >= 2 and _is_local_path_token(tokens[1]):
        local_paths.append(CommandTarget(normalize_repo_path_token(tokens[1]), "bun command reaches local script"))
        return ParsedCommand(executable, args, local_paths)

    if executable in {"just", "task"}:
        uncertainties.append(
            CommandUncertainty(
                "SCRIPT_TASK_RUNNER_UNRESOLVED",
                f"Task runner command was not statically resolved: {' '.join(tokens)}",
            )
        )
        return ParsedCommand(executable, args, uncertainties=uncertainties)

    if executable in {"source", "."} and args:
        local_paths.append(CommandTarget(normalize_repo_path_token(args[0]), "shell source indirection"))
    elif _is_local_path_token(tokens[0]):
        local_paths.append(CommandTarget(normalize_repo_path_token(tokens[0]), "command invokes local script"))

    return ParsedCommand(executable, args, local_paths, uncertainties=uncertainties)


def _split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=False)
    except ValueError:
        return command.split()


def _is_env_assignment(token: str) -> bool:
    if "=" not in token or token.startswith("="):
        return False
    key = token.split("=", 1)[0]
    return key.replace("_", "").isalnum()


def _is_python_combined_flag(token: str) -> bool:
    return token.startswith("-") and set(token[1:]) <= {"B", "E", "I", "O", "S", "b", "i", "q", "s", "u", "v"}


def _first_non_option(args: list[str]) -> str | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return args[index + 1] if index + 1 < len(args) else None
        if token.startswith("-"):
            index += 1
            continue
        return token
    return None


def _package_script_name(tokens: list[str]) -> str | None:
    if len(tokens) >= 3 and tokens[0].lower() in PACKAGE_MANAGERS | {"bun"} and tokens[1].lower() == "run":
        return tokens[2]
    if len(tokens) >= 2 and tokens[0].lower() in PACKAGE_MANAGERS and tokens[1].lower() in {
        "test",
        "start",
        "build",
    }:
        return tokens[1]
    return None


def _is_external_package_execution(tokens: list[str]) -> bool:
    if not tokens:
        return False
    first = tokens[0].lower()
    second = tokens[1].lower() if len(tokens) > 1 else ""
    return first == "npx" or (first == "pnpm" and second == "exec") or (first == "yarn" and second == "dlx")


def _is_local_path_token(token: str) -> bool:
    normalized = normalize_repo_path_token(token)
    if not normalized or "://" in normalized:
        return False
    if normalized.startswith(("/", "~")):
        return False
    if normalized.startswith("../") or normalized.startswith("./"):
        return True
    if "/" in normalized:
        return True
    return PurePosixPath(normalized).suffix.lower() in SCRIPT_EXTENSIONS


def _parse_uncertain(reason: str) -> CommandUncertainty:
    return CommandUncertainty("SCRIPT_PARSE_UNCERTAIN", reason)
