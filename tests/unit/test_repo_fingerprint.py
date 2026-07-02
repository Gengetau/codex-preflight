from pathlib import Path

from codex_preflight_core.repo.collector import collect_critical_files
from codex_preflight_core.repo.fingerprint import compute_critical_fingerprint
from codex_preflight_core.repo.identity import resolve_repo_identity


def test_fingerprint_changes_for_critical_files_only(tmp_path: Path) -> None:
    package = tmp_path / "package.json"
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    package.write_text('{"scripts": {}}', encoding="utf-8")
    source.write_text("print('hello')", encoding="utf-8")

    first = compute_critical_fingerprint(tmp_path)
    source.write_text("print('changed')", encoding="utf-8")
    after_source_change = compute_critical_fingerprint(tmp_path)
    package.write_text('{"scripts": {"postinstall": "node install.js"}}', encoding="utf-8")
    after_package_change = compute_critical_fingerprint(tmp_path)

    assert first == after_source_change
    assert first != after_package_change


def test_collects_nested_workflows_scripts_and_tools(tmp_path: Path) -> None:
    paths = [
        tmp_path / ".github" / "workflows" / "ci.yml",
        tmp_path / "scripts" / "install.sh",
        tmp_path / "tools" / "helper.py",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("echo ok", encoding="utf-8")

    collected = {path.as_posix() for path in collect_critical_files(tmp_path)}

    assert ".github/workflows/ci.yml" in collected
    assert "scripts/install.sh" in collected
    assert "tools/helper.py" in collected


def test_non_git_repo_identity_has_low_confidence(tmp_path: Path) -> None:
    identity = resolve_repo_identity(tmp_path)

    assert identity.path == tmp_path.resolve()
    assert identity.identity_confidence == "low"
    assert identity.head_commit is None
