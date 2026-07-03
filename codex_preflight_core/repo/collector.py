import os
import shlex
from pathlib import Path

CRITICAL_BASENAMES = {
    ".env",
    "package.json",
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "poetry.lock",
    "uv.lock",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "compose.yml",
    "compose.yaml",
    "AGENTS.md",
    "CLAUDE.md",
    ".mcp.json",
    "mcp.json",
    "README.md",
}
CRITICAL_PREFIXES = (
    ".github/workflows/",
    ".cursor/rules",
    "scripts/",
    "bin/",
    "tools/",
    ".mcp/",
)
SKIP_DIRS = {".git", "node_modules", "vendor", "target", "dist", "build", "__pycache__", ".venv", "venv"}
COMMAND_TARGET_TOOLS = {"bash", "sh", "python", "node", "powershell", "pwsh"}
FIXTURE_MARKER = ".codex-preflight-fixtures"


def is_critical_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    basename = Path(normalized).name
    return basename in CRITICAL_BASENAMES or any(normalized.startswith(prefix) for prefix in CRITICAL_PREFIXES)


def collect_critical_files(root: Path, command: str | None = None) -> list[Path]:
    root = root.resolve()
    collected: set[Path] = set()
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in SKIP_DIRS and not (current_path / directory / FIXTURE_MARKER).exists()
        ]
        for filename in files:
            path = current_path / filename
            if not _is_safe_file(root, path):
                continue
            relative = path.relative_to(root).as_posix()
            if is_critical_path(relative):
                collected.add(Path(relative))
    for target in _command_target_files(root, command):
        collected.add(target)
    return sorted(collected, key=lambda item: item.as_posix())


def _is_safe_file(root: Path, path: Path) -> bool:
    if not path.is_file():
        return False
    if path.is_symlink():
        try:
            path.resolve().relative_to(root)
        except ValueError:
            return False
    return True


def _command_target_files(root: Path, command: str | None) -> list[Path]:
    if not command:
        return []
    try:
        parts = shlex.split(command, posix=False)
    except ValueError:
        parts = command.split()
    if len(parts) < 2 or parts[0].lower() not in COMMAND_TARGET_TOOLS:
        return []
    target = Path(parts[1].strip("\"'"))
    if target.is_absolute():
        return []
    path = (root / target).resolve()
    try:
        relative = path.relative_to(root)
    except ValueError:
        return []
    if _is_safe_file(root, path):
        return [Path(relative.as_posix())]
    return []
