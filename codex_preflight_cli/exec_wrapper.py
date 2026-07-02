import subprocess
from pathlib import Path

from codex_preflight_core.preflight import run_preflight


def run_checked_command(cwd: Path, command: list[str]) -> int:
    report = run_preflight(cwd, " ".join(command))
    if report["decision"] in {"ASK_USER", "BLOCK"}:
        return {"ASK_USER": 20, "BLOCK": 30}[report["decision"]]
    completed = subprocess.run(command, cwd=cwd, check=False)
    return completed.returncode
