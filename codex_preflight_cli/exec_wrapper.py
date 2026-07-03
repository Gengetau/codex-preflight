import json
import shlex
import subprocess
from collections.abc import Sequence
from pathlib import Path

from codex_preflight_core.preflight import run_preflight
from codex_preflight_core.report.markdown_renderer import render_markdown_report


def format_argv_for_preflight(command: Sequence[str]) -> str:
    """Serialize argv for static preflight while preserving the executed argv."""
    return shlex.join(command)


def run_checked_command(cwd: Path, command: list[str], report_format: str = "markdown") -> int:
    report = run_preflight(cwd, format_argv_for_preflight(command))
    if report["decision"] == "WARN":
        if report_format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(render_markdown_report(report))
    if report["decision"] in {"ASK_USER", "BLOCK"}:
        if report_format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(render_markdown_report(report))
        return {"ASK_USER": 20, "BLOCK": 30}[report["decision"]]
    completed = subprocess.run(command, cwd=cwd, check=False)
    return completed.returncode
