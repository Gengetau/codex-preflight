from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codex_preflight_cli.main import app
from codex_preflight_cli.release_diagnostics import (
    MAX_GITHUB_RESPONSE_SIZE,
    MCP_INSTALL_COMMAND,
    OPTIONAL_FLAGS,
    _github_fetch,
    _NoRedirect,
    _run_git,
    render_release_readiness_markdown,
    verify_release_readiness,
)


def _layout(root: Path, version: str = "0.3.7") -> None:
    inventory_source = '''import os

def tool_definitions():
    tools = [{"name": "preflight_check"}, {"name": "corpus_scan"}]
    if remote_scan_enabled():
        tools.append({"name": "remote_repository_scan"})
    if trust_read_enabled():
        tools.append({"name": "trust_list"})
    if trust_mutation_enabled():
        tools.extend([{"name": "trust_approve"}, {"name": "trust_revoke"}])
    return tools

def remote_scan_enabled():
    return os.environ.get("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN") == "1"

def trust_read_enabled():
    return os.environ.get("CODEX_PREFLIGHT_ENABLE_TRUST_READ") == "1"

def trust_mutation_enabled():
    return os.environ.get("CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION") == "1"
'''
    files = {
        "pyproject.toml": f'[project]\nname = "codex-preflight"\nversion = "{version}"\n',
        "codex_preflight_core/__init__.py": f'__version__ = "{version}"\n',
        "codex_preflight_mcp/__init__.py": f'__version__ = "{version}"\n',
        "codex_preflight_mcp/server.py": inventory_source,
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
    module_file = Path(environment["PYTHONPATH"]) / "codex_preflight_mcp" / "server.py"
    payload = {"moduleFile": str(module_file), "tools": tools}
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps(payload), stderr="")


def _git(
    expected: str = "a" * 40,
    tag_target: str | None = None,
    *,
    head: str | None = None,
    blob_overrides: dict[str, bytes] | None = None,
    tree_modes: dict[str, str] | None = None,
    tree_types: dict[str, str] | None = None,
    annotated: bool = True,
    repository: bool = True,
    unknown_ref: str | None = None,
):
    def run(argv, cwd) -> subprocess.CompletedProcess[str]:
        arguments = list(argv)
        if arguments[-1] == "--show-toplevel":
            return subprocess.CompletedProcess(
                args=arguments,
                returncode=0 if repository else 128,
                stdout=f"{cwd}\n" if repository else "",
                stderr="",
            )
        if arguments[1:3] == ["cat-file", "-t"]:
            kind = "tag" if annotated else "commit"
            return subprocess.CompletedProcess(args=arguments, returncode=0, stdout=f"{kind}\n", stderr="")
        reference = arguments[-1]
        if unknown_ref is not None and reference.startswith(unknown_ref):
            return subprocess.CompletedProcess(args=arguments, returncode=128, stdout="", stderr="unknown ref")
        if arguments[1] == "ls-tree":
            relative_name = reference
            try:
                data = (blob_overrides or {}).get(relative_name)
                if data is None:
                    data = (cwd / relative_name).read_bytes()
            except OSError:
                return subprocess.CompletedProcess(args=arguments, returncode=128, stdout="", stderr="missing blob")
            header = f"blob {len(data)}\0".encode("ascii")
            object_id = hashlib.sha1(header + data).hexdigest()
            mode = (tree_modes or {}).get(relative_name, "100644")
            object_type = (tree_types or {}).get(relative_name, "blob")
            entry = f"{mode} {object_type} {object_id}\t{relative_name}\0"
            return subprocess.CompletedProcess(args=arguments, returncode=0, stdout=entry, stderr="")
        if reference == "HEAD^{commit}" and head is not None:
            target = head
        else:
            target = tag_target if reference.startswith("v0.3.7") and tag_target is not None else expected
        return subprocess.CompletedProcess(args=arguments, returncode=0, stdout=f"{target}\n", stderr="")

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
        payload = {
            "moduleFile": str(Path(_environment["PYTHONPATH"]) / "codex_preflight_mcp" / "server.py"),
            "tools": [{"name": "unexpected"}],
        }
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps(payload), stderr="")

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


def test_static_inventory_drift_is_reported(tmp_path: Path) -> None:
    _layout(tmp_path)
    server = tmp_path / "codex_preflight_mcp/server.py"
    server.write_text(
        server.read_text(encoding="utf-8").replace('"preflight_check"', '"unexpected"'),
        encoding="utf-8",
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


def test_lightweight_local_tag_is_rejected(tmp_path: Path) -> None:
    _layout(tmp_path)
    report = verify_release_readiness(
        tmp_path,
        tag="v0.3.7",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(annotated=False),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["git.tag-target"]
    assert check["status"] == "FAIL"
    assert check["evidence"]["annotated"] is False


def test_annotated_local_tag_is_accepted(tmp_path: Path) -> None:
    _layout(tmp_path)
    report = verify_release_readiness(
        tmp_path,
        tag="v0.3.7",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(annotated=True),
        tool_runner=_runtime_ok,
    )

    assert _checks(report)["git.tag-target"]["status"] == "PASS"


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
        if path == "/repos/Gengetau/codex-preflight":
            return 200, {"full_name": "Gengetau/codex-preflight", "private": False}
        if "/releases/tags/" in path:
            return 200, {
                "tag_name": "v0.3.7",
                "target_commitish": "master",
                "draft": False,
                "prerelease": False,
            }
        if "/git/ref/tags/" in path:
            return 200, {"object": {"type": "tag", "sha": "c" * 40}}
        if "/git/tags/" in path:
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


def test_lightweight_github_tag_is_rejected(tmp_path: Path) -> None:
    _layout(tmp_path)

    def fetch(path: str):
        if path == "/repos/Gengetau/codex-preflight":
            return 200, {"full_name": "Gengetau/codex-preflight", "private": False}
        if "/releases/tags/" in path:
            return 200, {
                "tag_name": "v0.3.7",
                "target_commitish": "master",
                "draft": False,
                "prerelease": False,
            }
        if "/git/ref/tags/" in path:
            return 200, {"object": {"type": "commit", "sha": "a" * 40}}
        return 404, None

    report = verify_release_readiness(
        tmp_path,
        tag="v0.3.7",
        github_repo="Gengetau/codex-preflight",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
        github_fetcher=fetch,
    )

    assert _checks(report)["github.release-target"]["status"] == "FAIL"
    assert _checks(report)["github.release-target"]["evidence"]["tagTarget"] is None


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
    assert _checks(report)["github.repository-access"]["detail"].endswith("OSError.")


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
    assert git_calls[0][0] == ["git", "rev-parse", "--show-toplevel"]
    assert not any(call[0][1] == "status" for call in git_calls)
    assert len(tool_calls) == 8
    assert all(call[1:3] == ["-P", "-c"] for call in tool_calls)
    assert all(
        environment["PYTHONSAFEPATH"] == "1"
        and str(root.resolve()) not in environment["PYTHONPATH"]
        for environment in tool_environments
    )


def test_target_checkout_modules_are_never_imported_or_executed(tmp_path: Path) -> None:
    _layout(tmp_path)
    sentinel = tmp_path / "target-imported"
    server = tmp_path / "codex_preflight_mcp/server.py"
    server.write_text(
        'raise RuntimeError("target executed")\n' + server.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (tmp_path / "codex_preflight_mcp/__init__.py").write_text(
        '__version__ = "0.3.7"\nraise RuntimeError("target package executed")\n',
        encoding="utf-8",
    )
    calls: list[tuple[list[str], dict[str, str]]] = []

    def runtime(argv, environment):
        calls.append((list(argv), dict(environment)))
        return _runtime_ok(argv, environment)

    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=runtime,
    )

    assert report["ready"] is True
    assert not sentinel.exists()
    assert len(calls) == 8
    assert all(str(tmp_path) not in environment["PYTHONPATH"] for _, environment in calls)


def test_real_runtime_subprocess_ignores_target_checkout_on_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _layout(tmp_path)
    (tmp_path / "codex_preflight_mcp/__init__.py").write_text(
        '__version__ = "0.3.7"\nraise RuntimeError("target package executed")\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
    )

    assert report["ready"] is True
    assert _checks(report)["mcp.inventory.runtime"]["status"] == "PASS"


def test_symlinked_target_file_is_rejected_without_reading_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _layout(root)
    outside = tmp_path / "outside.toml"
    outside.write_text('[project]\nversion = "0.3.7"\n', encoding="utf-8")
    target = root / "pyproject.toml"
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("file symlinks are unavailable")

    report = verify_release_readiness(
        root,
        expected_version="0.3.7",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    assert report["ready"] is False
    assert "pyproject.toml" in _checks(report)["version.sources"]["evidence"]["invalid"]


def test_non_repository_and_unknown_ref_fail_canonical_commit_gate(tmp_path: Path) -> None:
    _layout(tmp_path)
    non_repository = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(repository=False),
        tool_runner=_runtime_ok,
    )
    unknown = verify_release_readiness(
        tmp_path,
        expected_commit="missing-ref",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(unknown_ref="missing-ref"),
        tool_runner=_runtime_ok,
    )

    for report in (non_repository, unknown):
        assert report["ready"] is False
        assert report["expectedCommit"] is None
        assert _checks(report)["git.repository-commit"]["status"] == "FAIL"


def test_repository_snapshot_requires_expected_head(tmp_path: Path) -> None:
    _layout(tmp_path)

    report = verify_release_readiness(
        tmp_path,
        expected_commit="a" * 40,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(head="b" * 40),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["git.repository-commit"]
    assert report["ready"] is False
    assert report["expectedCommit"] is None
    assert check["status"] == "FAIL"


def test_consumed_file_must_match_expected_commit_blob(tmp_path: Path) -> None:
    _layout(tmp_path)
    relative_name = "codex_preflight_core/__init__.py"
    path = tmp_path / relative_name
    committed = path.read_bytes()
    path.write_bytes(committed + b"# hidden worktree change\n")

    report = verify_release_readiness(
        tmp_path,
        expected_commit="a" * 40,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(blob_overrides={relative_name: committed}),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["git.repository-commit"]
    assert report["ready"] is False
    assert "mismatchedFiles" in check["evidence"], check
    assert check["evidence"]["mismatchedFiles"] == [relative_name]


def test_commit_blob_binding_accepts_only_safe_crlf_checkout_conversion(tmp_path: Path) -> None:
    _layout(tmp_path)
    relative_name = "pyproject.toml"
    path = tmp_path / relative_name
    committed = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(committed.replace(b"\n", b"\r\n"))

    report = verify_release_readiness(
        tmp_path,
        expected_commit="a" * 40,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(blob_overrides={relative_name: committed}),
        tool_runner=_runtime_ok,
    )

    assert report["ready"] is True
    assert _checks(report)["git.repository-commit"]["status"] == "PASS"


def test_all_content_checks_consume_the_same_verified_immutable_snapshot(tmp_path: Path) -> None:
    _layout(tmp_path)
    server = tmp_path / "codex_preflight_mcp/server.py"
    delegate = _git()
    mutated = False

    def mutate_after_server_snapshot(argv, cwd):
        nonlocal mutated
        arguments = list(argv)
        if arguments[1] == "ls-tree" and arguments[-1] == ".codex-plugin/plugin.json" and not mutated:
            server.write_text('raise RuntimeError("replaced after snapshot")\n', encoding="utf-8")
            mutated = True
        return delegate(argv, cwd)

    report = verify_release_readiness(
        tmp_path,
        expected_commit="a" * 40,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=mutate_after_server_snapshot,
        tool_runner=_runtime_ok,
    )

    assert mutated is True
    assert server.read_text(encoding="utf-8").startswith("raise RuntimeError")
    assert report["ready"] is True
    assert _checks(report)["git.repository-commit"]["evidence"]["immutableSnapshot"] is True
    assert _checks(report)["mcp.inventory.static"]["status"] == "PASS"


@pytest.mark.parametrize(
    ("mode", "object_type"),
    (("120000", "blob"), ("160000", "commit")),
)
def test_commit_tree_rejects_non_regular_entries_materialized_as_files(
    tmp_path: Path,
    mode: str,
    object_type: str,
) -> None:
    _layout(tmp_path)
    relative_name = "codex_preflight_core/__init__.py"

    report = verify_release_readiness(
        tmp_path,
        expected_commit="a" * 40,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(
            tree_modes={relative_name: mode},
            tree_types={relative_name: object_type},
        ),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["git.repository-commit"]
    assert report["ready"] is False
    assert check["evidence"]["invalidEntries"] == {relative_name: f"{mode} {object_type}"}


def _commit_test_repository(root: Path) -> str:
    commands = (
        ("git", "-c", "core.longpaths=true", "init"),
        ("git", "-c", "core.longpaths=true", "config", "core.longpaths", "true"),
        ("git", "-c", "core.longpaths=true", "config", "core.autocrlf", "false"),
        ("git", "-c", "core.longpaths=true", "config", "user.email", "release-test@example.invalid"),
        ("git", "-c", "core.longpaths=true", "config", "user.name", "Release Test"),
        ("git", "-c", "core.longpaths=true", "add", "."),
        ("git", "-c", "core.longpaths=true", "commit", "-m", "fixture"),
    )
    for command in commands:
        subprocess.run(
            command,
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    return subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout.strip()


@pytest.mark.parametrize("index_flag", ("--assume-unchanged", "--skip-worktree"))
def test_index_hidden_consumed_file_still_fails_commit_binding(
    tmp_path_factory: pytest.TempPathFactory,
    index_flag: str,
) -> None:
    root = tmp_path_factory.mktemp("git-index")
    _layout(root)
    commit = _commit_test_repository(root)
    relative_name = "codex_preflight_core/__init__.py"
    subprocess.run(
        ("git", "update-index", index_flag, relative_name),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    with (root / relative_name).open("a", encoding="utf-8") as handle:
        handle.write("# hidden by index flag\n")

    report = verify_release_readiness(
        root,
        expected_commit=commit,
        expected_version="0.3.7",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["git.repository-commit"]
    assert report["ready"] is False
    assert "mismatchedFiles" in check["evidence"], check
    assert check["evidence"]["mismatchedFiles"] == [relative_name]


@pytest.mark.skipif(os.name == "nt", reason="POSIX fsmonitor hook sentinel")
def test_release_verifier_does_not_invoke_repository_fsmonitor_hook(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    root = tmp_path_factory.mktemp("git-fsmonitor")
    _layout(root)
    commit = _commit_test_repository(root)
    sentinel = root / "fsmonitor-invoked"
    hook = root / "fsmonitor-sentinel.sh"
    hook.write_text(
        f"#!/bin/sh\nprintf invoked > {shlex.quote(str(sentinel))}\nprintf '\\n'\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    subprocess.run(
        ("git", "config", "core.fsmonitor", str(hook)),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    report = verify_release_readiness(
        root,
        expected_commit=commit,
        expected_version="0.3.7",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        tool_runner=_runtime_ok,
    )

    assert report["ready"] is True
    assert sentinel.exists() is False


def test_git_subprocess_scrubs_hostile_git_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    def fake_run(*_args, **kwargs):
        captured.update(kwargs["env"])
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setenv("GIT_DIR", str(tmp_path / "other.git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "other"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(tmp_path / "objects"))
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(tmp_path / "alternate"))
    monkeypatch.setattr(subprocess, "run", fake_run)

    _run_git(("git", "rev-parse", "--show-toplevel"), tmp_path)

    assert not any(name.startswith("GIT_") for name in captured if name not in {
        "GIT_NO_LAZY_FETCH", "GIT_NO_REPLACE_OBJECTS", "GIT_OPTIONAL_LOCKS", "GIT_TERMINAL_PROMPT"
    })
    assert captured["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert captured["GIT_OPTIONAL_LOCKS"] == "0"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda source: source.replace(
            "    if remote_scan_enabled():",
            "    return tools\n    if remote_scan_enabled():",
            1,
        ),
        lambda source: source.replace("    return tools\n\ndef remote_scan_enabled", "\ndef remote_scan_enabled", 1),
        lambda source: source.replace(
            '        tools.append({"name": "remote_repository_scan"})',
            '        tools.append({"name": "remote_repository_scan"})\n        tools.clear()',
            1,
        ),
        lambda source: source.replace(
            '    return os.environ.get("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN") == "1"',
            "    return True",
            1,
        ),
        lambda source: source + "\nremote_scan_enabled = lambda: True\n",
        lambda source: source + "\nif True:\n    remote_scan_enabled = lambda: True\n",
        lambda source: source + "\nif True:\n    tool_definitions = lambda: []\n",
        lambda source: source + "\nif True:\n    del trust_read_enabled\n",
        lambda source: source + '\nglobals()["remote_scan_enabled"] = lambda: True\n',
        lambda source: source + '\nexec("remote_scan_enabled = lambda: True")\n',
        lambda source: source + '\nos.environ["CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN"] = "1"\n',
        lambda source: source + '\nenv = os.environ\nenv.update(CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN="1")\n',
        lambda source: source + '\nos.putenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")\n',
        lambda source: source + '\nfrom os import environ\nenviron["CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN"] = "1"\n',
    ],
)
def test_static_inventory_strict_ast_rejects_semantic_bypasses(tmp_path: Path, mutation) -> None:
    _layout(tmp_path)
    server = tmp_path / "codex_preflight_mcp/server.py"
    server.write_text(mutation(server.read_text(encoding="utf-8")), encoding="utf-8")

    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    assert _checks(report)["mcp.inventory.static"]["status"] == "FAIL"


def test_python_version_requires_one_top_level_literal_assignment(tmp_path: Path) -> None:
    _layout(tmp_path)
    core = tmp_path / "codex_preflight_core/__init__.py"
    core.write_text('__version__ = "0.3.7"\n__version__ = "9.9.9"\n', encoding="utf-8")

    duplicate = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    core.write_text('__version__ = "0.3.7"\nif True:\n    __version__ = "9.9.9"\n', encoding="utf-8")
    nested = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    core.write_text('fake = \'__version__ = "9.9.9"\'\n__version__ = "0.3.7"\n', encoding="utf-8")
    string_decoy = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    assert "codex_preflight_core/__init__.py" in _checks(duplicate)["version.sources"]["evidence"]["invalid"]
    assert "codex_preflight_core/__init__.py" in _checks(nested)["version.sources"]["evidence"]["invalid"]
    assert _checks(string_decoy)["version.sources"]["status"] == "PASS"


@pytest.mark.parametrize(
    "dynamic_write",
    (
        'globals()["__version__"] = "9.9.9"',
        'exec("__version__ = \'9.9.9\'")',
        '__builtins__["exec"]("__version__ = \'9.9.9\'")',
    ),
)
def test_python_version_rejects_dynamic_global_writes(tmp_path: Path, dynamic_write: str) -> None:
    _layout(tmp_path)
    relative_name = "codex_preflight_core/__init__.py"
    core = tmp_path / relative_name
    core.write_text(f'__version__ = "0.3.7"\n{dynamic_write}\n', encoding="utf-8")

    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    assert relative_name in _checks(report)["version.sources"]["evidence"]["invalid"]


def test_editable_self_runtime_overlap_fails_without_executing_probe(tmp_path: Path) -> None:
    _layout(tmp_path)
    called = False

    def forbidden(_argv, _environment):
        nonlocal called
        called = True
        raise AssertionError("overlapping target must not be executed")

    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=forbidden,
        trusted_package_root=tmp_path,
    )

    check = _checks(report)["mcp.inventory.runtime"]
    assert called is False
    assert check["status"] == "FAIL"
    assert check["evidence"] == {"provenanceVerified": False, "overlapsTarget": True}


def test_runtime_probe_rejects_module_provenance_inside_target(tmp_path: Path) -> None:
    _layout(tmp_path)
    trusted_root = Path(__file__).resolve().parents[1]

    def spoofed(_argv, environment):
        tools = [{"name": name} for name in _expected_inventory(dict(environment))]
        payload = {"moduleFile": str(tmp_path / "codex_preflight_mcp/server.py"), "tools": tools}
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps(payload), stderr="")

    report = verify_release_readiness(
        tmp_path,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=spoofed,
        trusted_package_root=trusted_root,
    )

    check = _checks(report)["mcp.inventory.runtime"]
    assert check["status"] == "FAIL"
    assert len(check["evidence"]["failures"]) == 8


def test_noncanonical_expected_version_fails_closed(tmp_path: Path) -> None:
    _layout(tmp_path)
    report = verify_release_readiness(
        tmp_path,
        expected_version="0.3.7`\n| injected |",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
    )

    check = _checks(report)["version.sources"]
    assert report["ready"] is False
    assert check["status"] == "FAIL"
    assert check["evidence"]["expectedValid"] is False


@pytest.mark.parametrize(
    ("github_repo", "merged_branch", "expected_detail"),
    [
        (None, "codex/merged", "--merged-branch requires --github-repo"),
        ("Gengetau/codex-preflight", None, "requires at least --tag or --merged-branch"),
    ],
)
def test_incomplete_external_option_combinations_fail_without_network(
    tmp_path: Path,
    github_repo: str | None,
    merged_branch: str | None,
    expected_detail: str,
) -> None:
    _layout(tmp_path)

    def unexpected(_path: str):
        raise AssertionError("network must not be called")

    report = verify_release_readiness(
        tmp_path,
        github_repo=github_repo,
        merged_branch=merged_branch,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
        github_fetcher=unexpected,
    )

    assert report["ready"] is False
    assert expected_detail in _checks(report)["options.external"]["detail"]


@pytest.mark.parametrize("branch", ["", "-option", "bad branch", "bad..branch", ".hidden", "topic.lock"])
def test_empty_or_invalid_merged_branch_fails_before_network(tmp_path: Path, branch: str) -> None:
    _layout(tmp_path)

    def unexpected(_path: str):
        raise AssertionError("network must not be called")

    report = verify_release_readiness(
        tmp_path,
        github_repo="Gengetau/codex-preflight",
        merged_branch=branch,
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
        github_fetcher=unexpected,
    )

    assert report["ready"] is False
    assert "canonical Git branch" in _checks(report)["options.external"]["detail"]


@pytest.mark.parametrize("repository", ["./repo", "../repo", f"{'a' * 40}/repo", "owner/.."])
def test_invalid_repository_components_fail_before_network(tmp_path: Path, repository: str) -> None:
    _layout(tmp_path)

    def unexpected(_path: str):
        raise AssertionError("network must not be called")

    report = verify_release_readiness(
        tmp_path,
        github_repo=repository,
        merged_branch="codex/merged",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
        github_fetcher=unexpected,
    )

    assert report["ready"] is False
    assert _checks(report)["options.external"]["status"] == "FAIL"


def test_github_fetch_caps_response_before_json_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    reads: list[int] = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self):
            return "https://api.github.com/repos/owner/repo"

        def read(self, size: int):
            reads.append(size)
            return b"x" * size

    class Opener:
        def open(self, _request, timeout):
            assert timeout == 10
            return Response()

    monkeypatch.setattr("urllib.request.build_opener", lambda *_handlers: Opener())

    with pytest.raises(OSError):
        _github_fetch("/repos/owner/repo")

    assert reads == [MAX_GITHUB_RESPONSE_SIZE + 1]


def test_github_fetch_disables_redirects_and_rejects_off_host_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handlers: list[object] = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self):
            return "https://attacker.invalid/redirected"

        def read(self, _size: int):
            raise AssertionError("off-host response must be rejected before reading")

    class Opener:
        def open(self, _request, timeout):
            assert timeout == 10
            return Response()

    def build_opener(*provided):
        handlers.extend(provided)
        return Opener()

    monkeypatch.setattr("urllib.request.build_opener", build_opener)

    with pytest.raises(OSError):
        _github_fetch("/repos/owner/repo")

    assert len(handlers) == 1
    assert isinstance(handlers[0], _NoRedirect)
    assert handlers[0].redirect_request(None, None, 302, "Found", {}, "https://attacker.invalid") is None


@pytest.mark.parametrize(
    "repository_response",
    [
        (404, None),
        (200, {"full_name": "missing/private", "private": True}),
    ],
)
def test_unavailable_repository_cannot_prove_branch_deletion(
    tmp_path: Path,
    repository_response,
) -> None:
    _layout(tmp_path)

    def fetch(path: str):
        if path == "/repos/missing/private":
            return repository_response
        return 404, None

    report = verify_release_readiness(
        tmp_path,
        github_repo="missing/private",
        merged_branch="codex/merged",
        executable_finder=lambda _name: "git",
        runtime_finder=lambda _name: object(),
        git_runner=_git(),
        tool_runner=_runtime_ok,
        github_fetcher=fetch,
    )

    checks = _checks(report)
    assert report["ready"] is False
    assert checks["github.repository-access"]["status"] == "FAIL"
    assert checks["github.branch-cleanup"]["status"] == "FAIL"


def test_markdown_escapes_every_untrusted_field_and_table_value() -> None:
    payload = "`value|next\n<img src=x>`[link](javascript:x)\\**"
    report = {
        "ready": False,
        "expectedVersion": payload,
        "expectedCommit": payload,
        "safety": {"externalVerificationRequested": True},
        "checks": [
            {
                "id": payload,
                "status": payload,
                "detail": payload,
                "remediation": payload,
            }
        ],
    }

    markdown = render_release_readiness_markdown(report)

    assert payload not in markdown
    assert "<img" not in markdown
    assert (
        "&#96;value&#124;next&#10;&lt;img src=x&gt;&#96;"
        "&#91;link&#93;(javascript:x)&#92;&#42;&#42;"
    ) in markdown
    assert len(markdown.splitlines()) == 14


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
