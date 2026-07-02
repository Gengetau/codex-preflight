import shlex
from dataclasses import dataclass

from codex_preflight_core.command.scope import CommandScope


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
    stripped = command.strip()
    lowered = stripped.lower()
    parts = [part.lower() for part in _split(stripped)]
    first = parts[0] if parts else ""
    second = parts[1] if len(parts) > 1 else ""

    if not stripped:
        return CommandClassification(command, CommandScope.UNKNOWN_SHELL, "Empty command.")

    if ("curl " in lowered or "wget " in lowered) and ("| bash" in lowered or "| sh" in lowered):
        return CommandClassification(command, CommandScope.NETWORK_SHELL, "Remote shell pipeline.")

    if "modelcontextprotocol" in lowered or "mcp" in lowered and first in {"npx", "node", "python"}:
        return CommandClassification(command, CommandScope.MCP_SERVER_START, "MCP server startup.")

    if first in {"npm", "pnpm", "yarn"} and second in {"install", "ci", "add"}:
        return CommandClassification(command, CommandScope.DEPENDENCY_INSTALL, "Node dependency install.")
    if first == "pip" and second == "install":
        return CommandClassification(command, CommandScope.DEPENDENCY_INSTALL, "Python dependency install.")
    if first == "poetry" and second == "install":
        return CommandClassification(command, CommandScope.DEPENDENCY_INSTALL, "Poetry dependency install.")
    if first == "uv" and second in {"sync", "pip"}:
        return CommandClassification(command, CommandScope.DEPENDENCY_INSTALL, "uv dependency install.")

    if first == "docker":
        return CommandClassification(command, CommandScope.DOCKER, "Docker command.")

    if first in {"bash", "sh", "powershell", "pwsh"}:
        return CommandClassification(command, CommandScope.SCRIPT_EXECUTION, "Shell script execution.")

    if first in {"pytest"} or first in {"mvn"} and second == "test":
        return CommandClassification(command, CommandScope.TEST, "Test command.")
    if first in {"make", "gradle"} or first == "mvn" and second in {"package", "compile"}:
        return CommandClassification(command, CommandScope.BUILD, "Build command.")

    if first in {"ls", "dir", "pwd"}:
        return CommandClassification(command, CommandScope.SAFE_READONLY, "Read-only shell command.")
    if first in {"cat", "type"}:
        return CommandClassification(command, CommandScope.SAFE_READONLY, "Read-only file command.")
    if first == "git" and second in {"status", "diff", "log", "show"}:
        return CommandClassification(command, CommandScope.SAFE_READONLY, "Read-only git command.")

    return CommandClassification(command, CommandScope.UNKNOWN_SHELL, "Unknown shell command.")
