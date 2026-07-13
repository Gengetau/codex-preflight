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
    isolated_install = next(
        step
        for step in workflow["jobs"]["test"]["steps"]
        if step.get("name") == "Install isolated release verifier"
    )
    release_verify = next(
        step for step in workflow["jobs"]["test"]["steps"] if step.get("name") == "Verify release readiness"
    )

    assert test_install["run"] == 'python -m pip install -e ".[dev,mcp]"'
    assert smoke_install["run"] == 'python -m pip install -e ".[dev,mcp]"'
    assert isolated_install["run"] == (
        'python -m pip install --target "${{ runner.temp }}/codex-preflight-release-verify" --no-deps .'
    )
    assert release_verify["env"]["PYTHONPATH"] == "${{ runner.temp }}/codex-preflight-release-verify"
    assert release_verify["run"].startswith("python -P -m codex_preflight_cli.main release verify")
