import json
import subprocess
from pathlib import Path

from codex_preflight_core.preflight import run_preflight
from codex_preflight_core.report.markdown_renderer import render_markdown_report


def run_checked_command(cwd: Path, command: list[str], report_format: str = "markdown") -> int:
    report = run_preflight(cwd, " ".join(command))
    if report["decision"] in {"ASK_USER", "BLOCK"}:
        if report_format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(render_markdown_report(report))
        return {"ASK_USER": 20, "BLOCK": 30}[report["decision"]]
    completed = subprocess.run(command, cwd=cwd, check=False)
    return completed.returncode
