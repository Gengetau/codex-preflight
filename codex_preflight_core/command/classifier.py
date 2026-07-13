import re
import shlex
from dataclasses import dataclass

from codex_preflight_core.command.scope import CommandScope

RISK_ORDER = {
    CommandScope.SAFE_READONLY: 0,
    CommandScope.UNKNOWN_SHELL: 1,
    CommandScope.TEST: 2,
    CommandScope.BUILD: 3,
    CommandScope.MCP_SERVER_START: 4,
    CommandScope.SCRIPT_EXECUTION: 5,
    CommandScope.DOCKER: 6,
    CommandScope.DEPENDENCY_INSTALL: 7,
    CommandScope.NETWORK_SHELL: 8,
}


@dataclass(frozen=True)
class CommandClassification:
    raw: str
    scope: CommandScope
    reason: str

    @property
    def is_risky(self) -> bool:
        return self.scope not in {CommandScope.SAFE_READONLY}


def _split(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=False)
    except ValueError:
        return command.split()


def classify_command(command: str) -> CommandClassification:
    segments = split_shell_segments(command)
    if len(segments) > 1:
        classifications = [_classify_single(segment) for segment in segments]
        riskiest = max(classifications, key=lambda item: RISK_ORDER[item.scope])
        return CommandClassification(
            command,
            riskiest.scope,
            f"Composite command; riskiest segment `{riskiest.raw}`: {riskiest.reason}",
        )
    return _classify_single(command)


def _classify_single(command: str) -> CommandClassification:
    stripped = command.strip()
    lowered = stripped.lower()
    parts = [part.lower() for part in _split(stripped)]
    first = parts[0] if parts else ""
    second = parts[1] if len(parts) > 1 else ""

    if not stripped:
        return CommandClassification(command, CommandScope.UNKNOWN_SHELL, "Empty command.")

    if ("curl " in lowered or "wget " in lowered) and ("| bash" in lowered or "| sh" in lowered):
        return CommandClassification(command, CommandScope.NETWORK_SHELL, "Remote shell pipeline.")

    if ("modelcontextprotocol" in lowered or "mcp" in lowered) and first in {"npx", "node", "python"}:
        return CommandClassification(command, CommandScope.MCP_SERVER_START, "MCP server startup.")

    if first in {"npm", "pnpm", "yarn"} and second in {"install", "ci", "add"}:
        return CommandClassification(command, CommandScope.DEPENDENCY_INSTALL, "Node dependency install.")
    if first == "pip" and second == "install":
        return CommandClassification(command, CommandScope.DEPENDENCY_INSTALL, "Python dependency install.")
    if first == "poetry" and second == "install":
        return CommandClassification(command, CommandScope.DEPENDENCY_INSTALL, "Poetry dependency install.")
    if first == "uv" and second in {"sync", "pip"}:
        return CommandClassification(command, CommandScope.DEPENDENCY_INSTALL, "uv dependency install.")
    if first in {"bundle", "bundler"} and second == "install":
        return CommandClassification(command, CommandScope.DEPENDENCY_INSTALL, "Bundler dependency install.")

    if first == "docker":
        return CommandClassification(command, CommandScope.DOCKER, "Docker command.")

    if first in {"bash", "sh", "powershell", "pwsh", "python", "node"}:
        return CommandClassification(command, CommandScope.SCRIPT_EXECUTION, "Local script execution.")

    java_tool, java_task = _java_build_tool(parts)
    if first in {"pytest"} or java_tool == "maven" and java_task == "test":
        return CommandClassification(command, CommandScope.TEST, "Test command.")
    if java_tool == "gradle" and _gradle_task_is_test(java_task):
        return CommandClassification(command, CommandScope.TEST, "Gradle test task command.")
    if first == "cargo" and second == "test":
        return CommandClassification(command, CommandScope.TEST, "Cargo test command.")
    if first == "go" and second == "test":
        return CommandClassification(command, CommandScope.TEST, "Go test command.")
    ruby_task = _ruby_rake_task(parts)
    if ruby_task and _ruby_task_is_test(ruby_task):
        return CommandClassification(command, CommandScope.TEST, "Rake test task command.")
    if first in {"npm", "pnpm", "yarn"} and second == "test":
        return CommandClassification(command, CommandScope.TEST, "Package test script command.")
    if first == "cargo" and second == "build":
        return CommandClassification(command, CommandScope.BUILD, "Cargo build command.")
    if first == "go" and second in {"build", "generate"}:
        return CommandClassification(command, CommandScope.BUILD, "Go build or generate command.")
    if ruby_task:
        return CommandClassification(command, CommandScope.BUILD, "Rake task command.")
    if first in {"npm", "pnpm", "yarn"} and second in {"start", "build"}:
        return CommandClassification(command, CommandScope.BUILD, "Package script command.")
    if first in {"npm", "pnpm", "yarn"} and second == "run":
        return CommandClassification(command, CommandScope.BUILD, "Package script command.")
    if java_tool:
        return CommandClassification(command, CommandScope.BUILD, "Maven or Gradle build command.")
    if first == "make":
        return CommandClassification(command, CommandScope.BUILD, "Build command.")

    if first in {"ls", "dir", "pwd"}:
        return CommandClassification(command, CommandScope.SAFE_READONLY, "Read-only shell command.")
    if first in {"cat", "type"}:
        return CommandClassification(command, CommandScope.SAFE_READONLY, "Read-only file command.")
    if first == "git" and second in {"status", "diff", "log", "show"}:
        return CommandClassification(command, CommandScope.SAFE_READONLY, "Read-only git command.")

    return CommandClassification(command, CommandScope.UNKNOWN_SHELL, "Unknown shell command.")


def split_shell_segments(command: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(command):
        char = command[index]
        next_char = command[index + 1] if index + 1 < len(command) else ""
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
            current.append(char)
            index += 1
            continue
        if quote is None and char == "\n":
            _append_segment(segments, current)
            index += 1
            continue
        if quote is None and char == ";" and next_char != ";":
            _append_segment(segments, current)
            index += 1
            continue
        if quote is None and char + next_char in {"&&", "||"}:
            _append_segment(segments, current)
            index += 2
            continue
        current.append(char)
        index += 1
    _append_segment(segments, current)
    return segments


def _ruby_rake_task(parts: list[str]) -> str | None:
    if parts and parts[0] == "rake":
        return parts[1] if len(parts) > 1 else "default"
    if len(parts) >= 3 and parts[0] in {"bundle", "bundler"} and parts[1:3] == ["exec", "rake"]:
        return parts[3] if len(parts) > 3 else "default"
    return None


def _ruby_task_is_test(task: str) -> bool:
    segments = re.split(r"[:/]", task)
    return any(segment in {"spec", "test", "tests"} for segment in segments)


def _java_build_tool(parts: list[str]) -> tuple[str | None, str]:
    if not parts:
        return None, ""
    executable = parts[0].replace("\\", "/").rsplit("/", 1)[-1]
    if executable in {"mvn", "mvnw", "mvnw.cmd"}:
        task = next((part for part in parts[1:] if not part.startswith("-")), "package")
        return "maven", task
    if executable in {"gradle", "gradlew", "gradlew.bat"}:
        task = next((part for part in parts[1:] if not part.startswith("-")), "build")
        return "gradle", task
    return None, ""


def _gradle_task_is_test(task: str) -> bool:
    segments = re.split(r"[:/]", task)
    return any(segment in {"check", "test", "tests"} or segment.endswith("test") for segment in segments)


_split_shell_segments = split_shell_segments


def _append_segment(segments: list[str], current: list[str]) -> None:
    segment = "".join(current).strip()
    if segment:
        segments.append(segment)
    current.clear()
