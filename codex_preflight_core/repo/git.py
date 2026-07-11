import math
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
