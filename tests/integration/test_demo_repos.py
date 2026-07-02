from pathlib import Path

from codex_preflight_core.command.classifier import classify_command
from codex_preflight_core.policy.engine import evaluate_policy
from codex_preflight_core.scanner.engine import scan_repository

ROOT = Path(__file__).resolve().parents[2]


def decision_for_demo(name: str, command: str) -> str:
    findings = scan_repository(ROOT / "demo_repos" / name)
    return evaluate_policy(findings, classify_command(command)).decision.value


def test_demo_repositories_have_expected_decisions() -> None:
    assert decision_for_demo("safe_node_app", "npm install") in {"ALLOW", "WARN"}
    assert decision_for_demo("malicious_postinstall", "pnpm install") == "BLOCK"
    assert decision_for_demo("risky_github_actions", "mvn test") == "ASK_USER"
    assert decision_for_demo("suspicious_mcp_config", "npx mcp-server") in {"ASK_USER", "BLOCK"}
    assert decision_for_demo("prompt_injection_readme", "bash setup.sh") == "ASK_USER"
    assert decision_for_demo("leaked_secret_sample", "cat README.md") == "BLOCK"
    assert decision_for_demo("risky_docker_compose", "docker compose up") == "ASK_USER"
