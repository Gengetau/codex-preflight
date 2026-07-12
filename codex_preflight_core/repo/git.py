import math
import os
import subprocess
from pathlib import Path

GIT_METADATA_TIMEOUT_SECONDS = 5.0


def run_git(
    root: Path,
    *args: str,
    timeout: float = GIT_METADATA_TIMEOUT_SECONDS,
) -> str | None:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Git metadata timeout must be a positive finite number.")
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            env=_sanitized_git_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=float(timeout),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _sanitized_git_environment() -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment
