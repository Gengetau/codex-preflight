from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

from typer.testing import CliRunner

from codex_preflight_cli.main import app
from codex_preflight_cli.release_diagnostics import verify_release_readiness
from codex_preflight_core import __version__ as core_version
from codex_preflight_mcp import __version__ as mcp_version

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.7"
HEAD = "a" * 40
SAFE_GIT = str(Path(shutil.which("git") or sys.executable).resolve())


def _git_executable(_name: str) -> str:
    return SAFE_GIT


def _git(argv, cwd) -> subprocess.CompletedProcess[str]:
    if argv[-1] == "--show-toplevel":
        output = str(cwd)
    elif argv[1] == "ls-tree":
        relative_name = argv[-1]
        data = (cwd / relative_name).read_bytes()
        header = f"blob {len(data)}\0".encode("ascii")
        object_id = hashlib.sha1(header + data).hexdigest()
        output = f"100644 blob {object_id}\t{relative_name}\0"
    else:
        output = HEAD
    stdout = output if "\0" in output else f"{output}\n"
    return subprocess.CompletedProcess(args=list(argv), returncode=0, stdout=stdout, stderr="")


def test_v037_version_sources_plugin_copy_and_release_history_are_aligned() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    root_plugin = json.loads((ROOT / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
    marketplace = json.loads(
        (ROOT / ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json").read_text(encoding="utf-8")
    )
    history = (ROOT / "docs/release-history.md").read_text(encoding="utf-8")

    assert project["project"]["version"] == VERSION
    assert core_version == VERSION
    assert mcp_version == VERSION
    assert root_plugin["version"] == VERSION
    assert marketplace["version"] == VERSION
    assert history.startswith("# Release History\n\n## v0.3.7")


def test_v037_release_gate_pins_clean_readiness_and_no_new_authority(tmp_path: Path) -> None:
    trusted_root = ROOT.parent / f"trusted-site-packages-{tmp_path.name}"
    shutil.copytree(ROOT / "codex_preflight_core", trusted_root / "codex_preflight_core")
    shutil.copytree(ROOT / "codex_preflight_mcp", trusted_root / "codex_preflight_mcp")
    try:
        report = verify_release_readiness(
            ROOT,
            expected_version=VERSION,
            expected_commit=HEAD,
            python_version=(3, 12),
            executable_finder=_git_executable,
            runtime_finder=lambda _name: object(),
            git_runner=_git,
            trusted_package_root=trusted_root,
        )
    finally:
        shutil.rmtree(trusted_root)
    checks = {check["id"]: check for check in report["checks"]}

    assert report["schemaVersion"] == "release-readiness/v1"
    assert report["ready"] is True, [check for check in report["checks"] if check["status"] == "FAIL"]
    assert report["safety"]["mutating"] is False
    assert checks["repository.root"]["status"] == "PASS"
    assert checks["git.repository-commit"]["status"] == "PASS"
    assert checks["mcp.inventory.static"]["status"] == "PASS"
    assert checks["mcp.inventory.runtime"]["status"] == "PASS"
    assert checks["mcp.inventory.runtime"]["evidence"]["provenanceVerified"] is True
    assert checks["mcp.inventory.runtime"]["evidence"]["registrySource"] == "FastMCP ToolManager"
    assert checks["github.release-target"]["status"] == "SKIP"
    assert checks["github.branch-cleanup"]["status"] == "SKIP"


def test_v037_docs_and_protected_ci_pin_read_only_release_verification() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    process = (ROOT / "docs/release-process.md").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for document in (readme, process):
        assert "codex-preflight release verify" in document
        assert "never" in document.lower() or "does not" in document.lower()
    assert "--github-repo OWNER/NAME" in process
    assert "--merged-branch" in process
    assert "runtime probe's `PYTHONPATH`" in readme
    assert "filesystem separation" in readme
    assert "non-editable Codex Preflight" not in process
    assert "must be annotated" in process
    assert "positively identify" in process
    assert "--expected-version 0.3.7" in workflow
    assert "--expected-commit HEAD" in workflow


def test_v037_cli_version_probe_exits_without_requiring_a_command() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "codex-preflight 0.3.7"
