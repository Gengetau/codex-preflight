import subprocess
from pathlib import Path

GIT_METADATA_TIMEOUT_SECONDS = 5.0


def run_git(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=GIT_METADATA_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None
