import json
import re
from pathlib import Path

import yaml
from typer.testing import CliRunner

from codex_preflight_cli.main import app

ROOT = Path(__file__).resolve().parents[2]
CASE_ROOT = ROOT / "case_corpus"


EXPECTED_CASES = {
    "npm-postinstall-remote-exec": ("BLOCK", ["NODE_LIFECYCLE_REMOTE_EXEC"]),
    "python-setup-remote-fetch": ("ASK_USER", ["PYTHON_SETUP_REMOTE_FETCH"]),
    "prompt-injection-readme": (
        "ASK_USER",
        ["AGENT_IGNORE_INSTRUCTIONS", "AGENT_UNSAFE_COMMAND_REQUEST"],
    ),
    "mcp-shell-server": ("ASK_USER", ["MCP_SHELL_COMMAND"]),
    "docker-socket-mount": ("ASK_USER", ["DOCKER_SOCKET_MOUNT"]),
    "github-actions-pull-request-target": ("ASK_USER", ["GHA_PULL_REQUEST_TARGET"]),
    "leaked-secret-fixture": ("BLOCK", ["SECRET_PRIVATE_KEY"]),
    "safe-node-package": ("ALLOW", []),
}


def test_corpus_list_outputs_case_ids() -> None:
    result = CliRunner().invoke(app, ["corpus", "list"])

    assert result.exit_code == 0
    for case_id in EXPECTED_CASES:
        assert case_id in result.output


def test_corpus_scan_json_passes_all_expectations() -> None:
    result = CliRunner().invoke(app, ["corpus", "scan", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["passed"] is True
    assert {case["id"] for case in payload["cases"]} == set(EXPECTED_CASES)
    for case in payload["cases"]:
        expected_decision, expected_rules = EXPECTED_CASES[case["id"]]
        assert case["actualDecision"] == expected_decision
        assert case["expectedDecision"] == expected_decision
        assert case["actualRules"] == expected_rules
        assert case["expectedRules"] == expected_rules
        assert case["passed"] is True


def test_corpus_scan_single_case_markdown() -> None:
    result = CliRunner().invoke(
        app,
        ["corpus", "scan", "--case", "npm-postinstall-remote-exec", "--format", "markdown"],
    )

    assert result.exit_code == 0
    assert "| npm-postinstall-remote-exec | BLOCK | BLOCK | pass |" in result.output


def test_corpus_fixtures_do_not_contain_active_payload_urls_or_real_secret_markers() -> None:
    assert CASE_ROOT.exists()
    for case_file in CASE_ROOT.glob("*/case.yml"):
        data = yaml.safe_load(case_file.read_text(encoding="utf-8"))
        assert data["safetyNote"]

    active_url = re.compile(r"https?://(?!example\.invalid\b|example\.com\b|localhost\b)", re.I)
    real_secret_markers = ("ghp_", "sk-", "AKIA")
    for path in CASE_ROOT.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert not active_url.search(text), path
            for marker in real_secret_markers:
                assert marker not in text, path


def test_batch_scan_markdown_uses_public_repo_config(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("safe fixture\n", encoding="utf-8")

    from contextlib import contextmanager

    @contextmanager
    def fake_clone(
        clone_url: str,
        *,
        ref: str | None = None,
        depth: int = 1,
        keep_temp: bool = False,
        temp_dir: Path | None = None,
    ):
        assert clone_url.startswith("https://github.com/")
        assert depth == 1
        assert keep_temp is False
        yield repo

    monkeypatch.setattr("codex_preflight_cli.main.clone_repo_to_temp", fake_clone)
    monkeypatch.setattr("codex_preflight_cli.main.resolve_cloned_commit", lambda cloned: "abc123")

    result = CliRunner().invoke(
        app,
        ["batch", "scan", "examples/public-repos.yml", "--format", "markdown"],
    )

    assert result.exit_code == 0
    assert "| Name | Decision | Expected | Result | Ref | Resolved commit |" in result.output
    assert "abc123" in result.output
