import json
from pathlib import Path

from codex_preflight_core.preflight import run_preflight

ROOT = Path(__file__).resolve().parents[2]


def stable_report(repo_name: str, command: str) -> dict[str, object]:
    report = run_preflight(ROOT / "demo_repos" / repo_name, command, use_cache=False)
    return {
        "decision": report["decision"],
        "riskScore": report["riskScore"],
        "commandScope": report["commandScope"],
        "summary": report["summary"],
        "ruleIds": [finding["ruleId"] for finding in report["findings"]],
    }


def test_key_demo_repo_json_reports_are_stable() -> None:
    reports = {
        "safe_node_app": stable_report("safe_node_app", "npm install"),
        "malicious_postinstall": stable_report("malicious_postinstall", "pnpm install"),
        "prompt_injection_readme": stable_report("prompt_injection_readme", "bash setup.sh"),
        "risky_docker_compose": stable_report("risky_docker_compose", "docker compose up"),
    }

    assert json.dumps(reports, indent=2, sort_keys=True) == json.dumps(
        {
            "malicious_postinstall": {
                "commandScope": "dependency_install",
                "decision": "BLOCK",
                "riskScore": 50,
                "ruleIds": ["NODE_LIFECYCLE_REMOTE_EXEC"],
                "summary": {"critical": 1, "high": 0, "info": 0, "low": 0, "medium": 0},
            },
            "prompt_injection_readme": {
                "commandScope": "script_execution",
                "decision": "ASK_USER",
                "riskScore": 50,
                "ruleIds": ["AGENT_IGNORE_INSTRUCTIONS", "AGENT_UNSAFE_COMMAND_REQUEST"],
                "summary": {"critical": 0, "high": 2, "info": 0, "low": 0, "medium": 0},
            },
            "risky_docker_compose": {
                "commandScope": "docker",
                "decision": "ASK_USER",
                "riskScore": 50,
                "ruleIds": ["DOCKER_PRIVILEGED_CONTAINER", "DOCKER_BROAD_HOST_MOUNT"],
                "summary": {"critical": 0, "high": 2, "info": 0, "low": 0, "medium": 0},
            },
            "safe_node_app": {
                "commandScope": "dependency_install",
                "decision": "ALLOW",
                "riskScore": 0,
                "ruleIds": [],
                "summary": {"critical": 0, "high": 0, "info": 0, "low": 0, "medium": 0},
            },
        },
        indent=2,
        sort_keys=True,
    )
