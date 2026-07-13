from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codex_preflight_cli.main import app
from codex_preflight_cli.release_diagnostics import (
    MCP_INSTALL_COMMAND,
    OPTIONAL_FLAGS,
    render_release_readiness_markdown,
    verify_release_readiness,
)


def _layout(root: Path, version: str = "0.3.7") -> None:
    files = {
        "pyproject.toml": f'[project]\nname = "codex-preflight"\nversion = "{version}"\n',
        "codex_preflight_core/__init__.py": f'__version__ = "{version}"\n',
        "codex_preflight_mcp/__init__.py": f'__version__ = "{version}"\n',
        ".codex-plugin/plugin.json": json.dumps({"name": "codex-preflight", "version": version}),
        ".mcp.json": "{}\n",
        "skills/codex-preflight/SKILL.md": "read-only skill\n",
    }
    copies = {
        ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json": files[
            ".codex-plugin/plugin.json"
        ],
        ".agents/plugins/plugins/codex-preflight/.mcp.json": files[".mcp.json"],
        ".agents/plugins/plugins/codex-preflight/skills/codex-preflight/SKILL.md": files[
            "skills/codex-preflight/SKILL.md"
        ],
    }
    for name, content in {**files, **copies}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _expected_inventory(environment: dict[str, str]) -> list[str]:
    names = ["preflight_check", "corpus_scan"]
    if environment.get(OPTIONAL_FLAGS[0]) == "1":
        names.append("remote_repository_scan")
    if environment.get(OPTIONAL_FLAGS[1]) == "1":
        names.append("trust_list")
    if environment.get(OPTIONAL_FLAGS[2]) == "1":
        names.extend(("trust_approve", "trust_revoke"))
    return names


def _runtime_ok(_argv, environment) -> subprocess.CompletedProcess[str]:
    tools = [{"name": name} for name in _expected_inventory(dict(environment))]
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps(tools), stderr="")


def _git(expected: str = "a" * 40, tag_target: str | None = None):
    def run(argv, _cwd) -> subprocess.CompletedProcess[str]:
        target = tag_target if argv[-1].endswith("^{}") else expected
        return subprocess.CompletedProcess(args=list(argv), returncode=0, stdout=f"{target}\n", stderr="")

    return run


def _checks(report: dict) -> dict[str, dict]:
    return {check["id"]: check for check in report["checks"]}


def test_clean_readiness_is_deterministic_and_non_mutating(tmp_path: Path) -> None:
    _layout(tmp_path)
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    kwargs = {
        "expected_version": "0.3.7",
        "expected_commit": "HEAD",
        "python_version": (3, 12),
        "executable_finder": lambda _name: "C:\\Program Files\\Git\\git.exe",
        "runtime_finder": lambda _name: object(),
        "git_runner": _git(),
        "tool_runner": _runtime_ok,
    }

    first = verify_release_readiness(tmp_path, **kwargs)
    second = verify_release_readiness(tmp_path, **kwargs)

    assert first == second
    assert first["ready"] is True
    assert first["expectedCommit"] == "a" * 40
    assert first["safety"] == {
        "mutating": False,
        "externalVerificationRequested": False,
        "externalEvidence": "untrusted-data",
    }
    assert _checks(first)["version.sources"]["status"] == "PASS"
    assert _checks(first)["plugin.copy"]["status"] == "PASS"
    assert _checks(first)["mcp.inventory.static"]["status"] == "PASS"
    assert _checks(first)["mcp.inventory.runtime"]["status"] == "PASS"
    assert {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before


def test_version_drift_is_reported_with_stable_evidence(tmp_path: Path) -> None:
    _layout(tmp_path)
    (tmp_path / "codex_preflight_mcp/__init__.py").write_text('__version__ = "0.3.6"\n', encoding="utf-8")

    report = verify_release_readiness(
        tmp_path,
        expected_version="0.3.7",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: None,
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["version.sources"]
    assert report["ready"] is False
    assert check["status"] == "FAIL"
    assert check["evidence"]["mismatched"] == ["codex_preflight_mcp/__init__.py"]


def test_marketplace_drift_is_reported_without_syncing(tmp_path: Path) -> None:
    _layout(tmp_path)
    copy = tmp_path / ".agents/plugins/plugins/codex-preflight/.mcp.json"
    copy.write_text('{"stale": true}\n', encoding="utf-8")

    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: None,
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["plugin.copy"]
    assert check["status"] == "FAIL"
    assert check["evidence"]["stale"] == [
        ".agents/plugins/plugins/codex-preflight/.mcp.json"
    ]
    assert json.loads(copy.read_text(encoding="utf-8")) == {"stale": True}


def test_runtime_inventory_drift_is_reported(tmp_path: Path) -> None:
    _layout(tmp_path)

    def drift(_argv, _environment) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='[{"name":"unexpected"}]', stderr="")

    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=drift,
    )

    check = _checks(report)["mcp.inventory.runtime"]
    assert check["status"] == "FAIL"
    assert len(check["evidence"]["mismatches"]) == 8


def test_static_inventory_drift_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _layout(tmp_path)
    monkeypatch.setattr(
        "codex_preflight_mcp.server.tool_definitions",
        lambda: [{"name": "unexpected"}],
    )

    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["mcp.inventory.static"]
    assert check["status"] == "FAIL"
    assert len(check["evidence"]["mismatches"]) == 8


def test_wrong_tag_target_fails_without_moving_tag(tmp_path: Path) -> None:
    _layout(tmp_path)
    report = verify_release_readiness(
        tmp_path,
        expected_commit="HEAD",
        tag="v0.3.7",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(tag_target="b" * 40),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["git.tag-target"]
    assert check["status"] == "FAIL"
    assert "Do not move" in check["remediation"]


def test_tag_name_must_match_expected_version(tmp_path: Path) -> None:
    _layout(tmp_path)
    report = verify_release_readiness(
        tmp_path,
        expected_version="0.3.7",
        tag="v0.3.6",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["git.tag-target"]
    assert check["status"] == "FAIL"
    assert "does not match expected version" in check["detail"]


@pytest.mark.parametrize(
    ("release_target", "branch_status", "release_status", "cleanup_status"),
    [
        ("b" * 40, 404, "FAIL", "PASS"),
        ("a" * 40, 200, "PASS", "FAIL"),
        ("a" * 40, 404, "PASS", "PASS"),
    ],
)
def test_github_release_target_and_branch_cleanup_are_independent(
    tmp_path: Path,
    release_target: str,
    branch_status: int,
    release_status: str,
    cleanup_status: str,
) -> None:
    _layout(tmp_path)

    def fetch(path: str):
        if "/releases/tags/" in path:
            return 200, {
                "tag_name": "v0.3.7",
                "target_commitish": "master",
                "draft": False,
                "prerelease": False,
            }
        if "/git/ref/tags/" in path:
            return 200, {"object": {"type": "commit", "sha": release_target}}
        return branch_status, {"name": "merged"} if branch_status == 200 else None

    report = verify_release_readiness(
        tmp_path,
        expected_commit="HEAD",
        tag="v0.3.7",
        github_repo="Gengetau/codex-preflight",
        merged_branch="codex/v0.3.7-release-automation-diagnostics",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
        github_fetcher=fetch,
    )

    checks = _checks(report)
    assert checks["github.release-target"]["status"] == release_status
    assert checks["github.branch-cleanup"]["status"] == cleanup_status
    assert checks["github.release-target"]["evidence"]["source"] == "github-api-untrusted-data"
    assert checks["github.release-target"]["evidence"]["tagTarget"] == release_target


def test_missing_optional_integration_is_skipped_with_exact_non_installing_remediation(tmp_path: Path) -> None:
    _layout(tmp_path)
    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: None,
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["integration.mcp-runtime"]
    assert check["status"] == "SKIP"
    assert MCP_INSTALL_COMMAND in check["remediation"]
    assert "No package was installed automatically" in check["remediation"]
    assert report["ready"] is True


def test_read_only_github_failure_is_sanitized(tmp_path: Path) -> None:
    _layout(tmp_path)

    def fail(_path: str):
        raise OSError("SECRET_REMOTE_TOKEN")

    report = verify_release_readiness(
        tmp_path,
        tag="v0.3.7",
        github_repo="Gengetau/codex-preflight",
        merged_branch="codex/merged",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
        github_fetcher=fail,
    )

    assert report["ready"] is False
    assert "SECRET_REMOTE_TOKEN" not in json.dumps(report)
    assert _checks(report)["github.release-target"]["detail"].endswith("OSError.")


def test_process_invocations_are_argument_lists_and_support_space_paths(tmp_path: Path) -> None:
    root = tmp_path / "checkout with spaces"
    _layout(root)
    git_calls: list[tuple[list[str], Path]] = []
    tool_calls: list[list[str]] = []
    tool_environments: list[dict[str, str]] = []

    def git_run(argv, cwd):
        git_calls.append((list(argv), cwd))
        return _git()(argv, cwd)

    def tool_run(argv, environment):
        tool_calls.append(list(argv))
        tool_environments.append(dict(environment))
        return _runtime_ok(argv, environment)

    report = verify_release_readiness(
        root,
        executable_finder=lambda _name: "C:\\Program Files\\Git\\git.exe",
        runtime_finder=lambda _name: object(),
        git_runner=git_run,
        tool_runner=tool_run,
    )

    assert report["ready"] is True
    assert git_calls[0][1] == root.resolve()
    assert git_calls[0][0][:2] == ["git", "rev-parse"]
    assert len(tool_calls) == 8
    assert all(call[-3:] == ["-m", "codex_preflight_mcp.server", "--list-tools"] for call in tool_calls)
    assert all(
        environment["PYTHONPATH"].split(os.pathsep)[0] == str(root.resolve())
        for environment in tool_environments
    )


def test_markdown_and_cli_json_have_stable_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    report = {
        "ready": True,
        "expectedVersion": "0.3.7",
        "expectedCommit": "a" * 40,
        "safety": {"externalVerificationRequested": False},
        "checks": [{"id": "clean", "status": "PASS", "detail": "ready", "remediation": None}],
    }
    assert "Overall result: **ready**" in render_release_readiness_markdown(report)
    monkeypatch.setattr("codex_preflight_cli.main.verify_release_readiness", lambda *_args, **_kwargs: report)

    result = CliRunner().invoke(app, ["release", "verify", "--format", "json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["ready"] is True


def test_cli_returns_one_for_not_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    report = {
        "ready": False,
        "expectedVersion": "0.3.7",
        "expectedCommit": "a" * 40,
        "safety": {"externalVerificationRequested": False},
        "checks": [{"id": "drift", "status": "FAIL", "detail": "not ready", "remediation": "fix"}],
    }
    monkeypatch.setattr("codex_preflight_cli.main.verify_release_readiness", lambda *_args, **_kwargs: report)

    result = CliRunner().invoke(app, ["release", "verify"])

    assert result.exit_code == 1
    assert "not ready" in result.stdout
