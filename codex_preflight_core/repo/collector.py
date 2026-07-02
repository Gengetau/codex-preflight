from pathlib import Path

CRITICAL_EXACT = {
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
SKIP_DIRS = {".git", "node_modules", "vendor", "target", "dist", "build", "__pycache__"}


def is_critical_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    return normalized in CRITICAL_EXACT or any(
        normalized.startswith(prefix) for prefix in CRITICAL_PREFIXES
    )


def collect_critical_files(root: Path) -> list[Path]:
    root = root.resolve()
    collected: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if not path.is_file():
            continue
        if path.is_symlink():
            try:
                path.resolve().relative_to(root)
            except ValueError:
                continue
        relative = path.relative_to(root).as_posix()
        if is_critical_path(relative):
            collected.append(Path(relative))
    return sorted(collected, key=lambda item: item.as_posix())
