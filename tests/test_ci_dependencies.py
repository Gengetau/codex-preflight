from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_full_ci_suite_installs_mcp_test_dependencies() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    install_step = next(
        step for step in workflow["jobs"]["test"]["steps"] if step.get("name") == "Install dependencies"
    )

    assert install_step["run"] == 'python -m pip install -e ".[dev,mcp]"'
