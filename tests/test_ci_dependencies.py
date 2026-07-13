from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_full_ci_suite_installs_mcp_test_dependencies() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    test_install = next(
        step for step in workflow["jobs"]["test"]["steps"] if step.get("name") == "Install dependencies"
    )
    smoke_install = next(
        step for step in workflow["jobs"]["mcp-smoke"]["steps"] if step.get("name") == "Install MCP extras"
    )

    assert test_install["run"] == 'python -m pip install ".[dev,mcp]"'
    assert smoke_install["run"] == 'python -m pip install ".[dev,mcp]"'
