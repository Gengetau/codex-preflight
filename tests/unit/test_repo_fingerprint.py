import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, BinaryIO

import pytest

from codex_preflight_core.repo import collector as collector_module
from codex_preflight_core.repo import fingerprint as fingerprint_module
from codex_preflight_core.repo import git as git_module
from codex_preflight_core.repo import identity as identity_module
from codex_preflight_core.repo.collector import CriticalFileCollectionError, collect_critical_files
from codex_preflight_core.repo.fingerprint import CriticalFingerprintError, compute_critical_fingerprint
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


def test_fingerprint_cancellation_is_checked_during_empty_tree_traversal(tmp_path: Path) -> None:
    (tmp_path / "nested" / "empty").mkdir(parents=True)
    checks = 0

    def cancel_during_walk() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 2

    with pytest.raises(CriticalFingerprintError) as caught:
        compute_critical_fingerprint(tmp_path, cancellation_check=cancel_during_walk)

    assert caught.value.code == "cancelled"
    assert checks == 2


def test_scandir_checks_cancellation_before_consuming_the_next_large_directory_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index in range(100):
        (tmp_path / f"ordinary-{index}.txt").write_text("data", encoding="utf-8")
    real_scandir = collector_module.os.scandir
    next_calls = [0]

    class GuardedScandir:
        def __init__(self, path: object) -> None:
            self.inner = real_scandir(path)

        def __enter__(self):
            self.inner.__enter__()
            return self

        def __exit__(self, *args: object):
            return self.inner.__exit__(*args)

        def __iter__(self):
            return self

        def __next__(self):
            next_calls[0] += 1
            return next(self.inner)

    def budget_check() -> None:
        if next_calls[0]:
            raise CriticalFingerprintError("cancelled", "cancelled inside one large directory")

    def guarded_scandir(path: object):
        if Path(path) == tmp_path:
            return GuardedScandir(path)
        return real_scandir(path)

    monkeypatch.setattr(collector_module.os, "scandir", guarded_scandir)

    with pytest.raises(CriticalFingerprintError) as caught:
        collect_critical_files(tmp_path, budget_check=budget_check, reject_unsafe=True)

    assert caught.value.code == "cancelled"
    assert next_calls == [1]


@pytest.mark.skipif(os.name != "nt", reason="Windows UNC symlink fixture")
def test_strict_scandir_rejects_junction_like_entry_without_following_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    link = tmp_path / "remote-dir"
    try:
        link.symlink_to(r"\\192.0.2.1\unreachable-share", target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    real_scandir = collector_module.os.scandir

    class GuardedEntry:
        def __init__(self, entry: Any) -> None:
            self.entry = entry
            self.name = entry.name
            self.path = entry.path

        def is_dir(self, *, follow_symlinks: bool = True) -> bool:
            if Path(self.path) == link and follow_symlinks:
                raise AssertionError("strict traversal followed the UNC reparse target")
            return bool(self.entry.is_dir(follow_symlinks=follow_symlinks))

        def stat(self, *, follow_symlinks: bool = True):
            if Path(self.path) == link and follow_symlinks:
                raise AssertionError("strict traversal stat followed the UNC reparse target")
            return self.entry.stat(follow_symlinks=follow_symlinks)

        def is_symlink(self) -> bool:
            return bool(self.entry.is_symlink())

    class GuardedScandir:
        def __init__(self, path: object) -> None:
            self.inner = real_scandir(path)

        def __enter__(self):
            self.inner.__enter__()
            return self

        def __exit__(self, *args: object):
            return self.inner.__exit__(*args)

        def __iter__(self):
            return self

        def __next__(self):
            return GuardedEntry(next(self.inner))

    def guarded_scandir(path: object):
        if Path(path) == tmp_path:
            return GuardedScandir(path)
        return real_scandir(path)

    monkeypatch.setattr(collector_module.os, "scandir", guarded_scandir)

    with pytest.raises(CriticalFileCollectionError):
        collect_critical_files(tmp_path, reject_unsafe=True)


def test_ordinary_collection_and_fingerprint_preserve_internal_critical_symlink_compatibility(
    tmp_path: Path,
) -> None:
    source = tmp_path / "readme-source.txt"
    critical = tmp_path / "README.md"
    source.write_text("internal linked documentation", encoding="utf-8")
    try:
        critical.symlink_to(source)
    except OSError:
        pytest.skip("file symlinks are unavailable")

    assert collect_critical_files(tmp_path) == [Path("README.md")]
    assert compute_critical_fingerprint(tmp_path).startswith("sha256:")


def test_fingerprint_reads_bounded_chunks_and_checks_cancellation_between_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "README.md"
    target.write_bytes(b"x" * (128 * 1024))

    class GuardedReader:
        def __init__(self, handle: BinaryIO) -> None:
            self.handle = handle
            self.read_calls = 0

        def read(self, size: int = -1) -> bytes:
            assert 0 < size <= 64 * 1024
            self.read_calls += 1
            return self.handle.read(size)

        def fileno(self) -> int:
            return self.handle.fileno()

        def __enter__(self) -> "GuardedReader":
            return self

        def __exit__(self, *_args: object) -> None:
            self.handle.close()

    path_type = type(target)
    real_open = path_type.open
    reader = GuardedReader(real_open(target, "rb"))

    def guarded_open(path: Path, mode: str = "r", *args: object, **kwargs: object):
        if path == target and mode == "rb":
            return reader
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(path_type, "open", guarded_open)

    with pytest.raises(CriticalFingerprintError) as caught:
        compute_critical_fingerprint(tmp_path, cancellation_check=lambda: reader.read_calls >= 1)

    assert caught.value.code == "cancelled"
    assert reader.read_calls == 1


def test_fingerprint_rejects_hard_linked_critical_files(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    target = tmp_path / "README.md"
    source.write_text("shared critical content", encoding="utf-8")
    os.link(source, target)

    with pytest.raises(CriticalFingerprintError) as caught:
        compute_critical_fingerprint(tmp_path, strict_safety=True)

    assert caught.value.code == "unavailable"


def test_fingerprint_rejects_critical_file_reparse_points(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    target = tmp_path / "README.md"
    source.write_text("linked critical content", encoding="utf-8")
    try:
        target.symlink_to(source)
    except OSError:
        pytest.skip("file symlinks are unavailable")

    with pytest.raises(CriticalFingerprintError) as caught:
        compute_critical_fingerprint(tmp_path, strict_safety=True)

    assert caught.value.code == "unavailable"


@pytest.mark.skipif(os.name != "nt", reason="Windows junction fixture")
def test_fingerprint_rejects_windows_junction_roots(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    junction_root = tmp_path / "junction"
    real_root.mkdir()
    (real_root / "README.md").write_text("junction content", encoding="utf-8")
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction_root), str(real_root)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("unable to create a Windows junction fixture")

    with pytest.raises(CriticalFingerprintError) as caught:
        compute_critical_fingerprint(junction_root, strict_safety=True)

    assert caught.value.code == "unavailable"


@pytest.mark.parametrize("boundary", ["timeout", "cancelled"])
def test_repo_identity_checks_budget_after_each_fixed_git_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    calls: list[tuple[str, ...]] = []
    expired = False

    def fixed_git_read(_root: Path, *args: str, timeout: float) -> str:
        nonlocal expired
        calls.append(args)
        expired = True
        return str(tmp_path)

    monkeypatch.setattr(identity_module, "run_git", fixed_git_read)

    with pytest.raises(OSError) as caught:
        resolve_repo_identity(
            tmp_path,
            deadline=30.0 if boundary == "timeout" else None,
            monotonic=lambda: 31.0 if expired else 0.0,
            cancellation_check=(lambda: expired) if boundary == "cancelled" else None,
        )

    assert getattr(caught.value, "code", None) == boundary
    assert calls == [("rev-parse", "--show-toplevel")]


def test_repo_identity_passes_remaining_deadline_to_git_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeouts: list[float] = []

    def fixed_git_read(_root: Path, *_args: str, timeout: float) -> None:
        timeouts.append(timeout)

    monkeypatch.setattr(identity_module, "run_git", fixed_git_read)

    identity = resolve_repo_identity(tmp_path, deadline=30.0, monotonic=lambda: 29.75)

    assert identity.identity_confidence == "low"
    assert timeouts == [pytest.approx(0.25)]


def test_run_git_forwards_supplied_remaining_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[float] = []

    def observed_run(*_args: object, timeout: float, **_kwargs: object) -> object:
        seen.append(timeout)
        return SimpleNamespace(returncode=0, stdout="ok\n")

    monkeypatch.setattr(git_module.subprocess, "run", observed_run)

    assert git_module.run_git(tmp_path, "status", timeout=0.25) == "ok"
    assert seen == [0.25]


def test_run_git_sanitizes_inherited_repository_and_config_redirections(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inherited = {
        "GIT_DIR": str(tmp_path / "redirected-git-dir"),
        "GIT_WORK_TREE": str(tmp_path / "redirected-worktree"),
        "GIT_COMMON_DIR": str(tmp_path / "redirected-common-dir"),
        "GIT_CONFIG": str(tmp_path / "redirected-config"),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.worktree",
        "GIT_CONFIG_VALUE_0": str(tmp_path / "redirected-config-worktree"),
    }
    for name, value in inherited.items():
        monkeypatch.setenv(name, value)
    seen_environment: dict[str, str] = {}

    def observed_run(*_args: object, env: dict[str, str], **_kwargs: object) -> object:
        seen_environment.update(env)
        return SimpleNamespace(returncode=0, stdout="ok\n")

    monkeypatch.setattr(git_module.subprocess, "run", observed_run)

    assert git_module.run_git(tmp_path, "status") == "ok"
    assert not (set(inherited) & set(seen_environment))
    assert seen_environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert seen_environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert seen_environment["GIT_TERMINAL_PROMPT"] == "0"


def _write_git_config_worktree(repo: Path, value: str) -> None:
    initialized = subprocess.run(
        ["git", "init", "--quiet", str(repo)],
        capture_output=True,
        text=True,
        check=False,
    )
    if initialized.returncode != 0:
        pytest.skip("Git repository fixtures are unavailable")
    with (repo / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write(f"[core]\n\tworktree = {value}\n")


@pytest.mark.skipif(os.name != "nt", reason="Windows UNC core.worktree fixture")
def test_identity_rejects_core_worktree_unc_before_git_or_target_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_git_config_worktree(repo, r"\\192.0.2.1\unreachable-worktree")
    calls: list[tuple[str, ...]] = []

    def forbidden_git(_root: Path, *args: str, timeout: float) -> None:
        calls.append(args)
        raise AssertionError("unsafe core.worktree reached Git")

    monkeypatch.setattr(identity_module, "run_git", forbidden_git)

    with pytest.raises(identity_module.RepoIdentityError) as caught:
        resolve_repo_identity(repo)

    assert caught.value.code == "unsafe"
    assert calls == []


def test_identity_rejects_core_worktree_reparse_before_git_or_target_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    target = tmp_path / "target"
    redirected = tmp_path / "redirected-worktree"
    repo.mkdir()
    target.mkdir()
    try:
        redirected.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    _write_git_config_worktree(repo, str(redirected))
    calls: list[tuple[str, ...]] = []

    def forbidden_git(_root: Path, *args: str, timeout: float) -> None:
        calls.append(args)
        raise AssertionError("unsafe core.worktree reached Git")

    monkeypatch.setattr(identity_module, "run_git", forbidden_git)

    with pytest.raises(identity_module.RepoIdentityError) as caught:
        resolve_repo_identity(repo)

    assert caught.value.code == "unsafe"
    assert calls == []


@pytest.mark.parametrize("redirect", ["gitfile", "commondir"])
def test_identity_rejects_git_control_directory_reparse_before_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    redirect: str,
) -> None:
    repo = tmp_path / "repo"
    actual = tmp_path / "actual-git-dir"
    linked = tmp_path / "linked-git-dir"
    repo.mkdir()
    actual.mkdir()
    try:
        linked.symlink_to(actual, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    if redirect == "gitfile":
        (repo / ".git").write_text(f"gitdir: {linked}\n", encoding="utf-8")
    else:
        worktree_git_dir = tmp_path / "worktree-git-dir"
        worktree_git_dir.mkdir()
        (repo / ".git").write_text(f"gitdir: {worktree_git_dir}\n", encoding="utf-8")
        (worktree_git_dir / "commondir").write_text(f"{linked}\n", encoding="utf-8")
    calls: list[tuple[str, ...]] = []

    def forbidden_git(_root: Path, *args: str, timeout: float) -> None:
        calls.append(args)
        raise AssertionError("unsafe Git control path reached Git")

    monkeypatch.setattr(identity_module, "run_git", forbidden_git)

    with pytest.raises(identity_module.RepoIdentityError) as caught:
        resolve_repo_identity(repo)

    assert caught.value.code == "unsafe"
    assert calls == []


def test_identity_supports_valid_gitfile_and_common_dir_from_linked_worktree(tmp_path: Path) -> None:
    main = tmp_path / "main"
    linked = tmp_path / "linked"
    commands = [
        (["git", "init", "--quiet", str(main)], None),
        (
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "base",
            ],
            main,
        ),
        (["git", "worktree", "add", "--quiet", "-b", "linked-test", str(linked)], main),
    ]
    for command, cwd in commands:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            pytest.skip("linked Git worktree fixtures are unavailable")

    identity = resolve_repo_identity(linked)

    assert identity.path == linked.absolute()
    assert identity.identity_confidence == "high"
    assert identity.branch == "linked-test"
    assert identity.head_commit is not None and len(identity.head_commit) == 40


def test_strict_command_target_rejects_intermediate_symlink_under_skipped_directory(tmp_path: Path) -> None:
    skipped = tmp_path / "node_modules"
    outside = tmp_path / "outside-bin"
    linked = skipped / "bin"
    skipped.mkdir()
    outside.mkdir()
    (outside / "runner.py").write_text("print('outside')\n", encoding="utf-8")
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(CriticalFingerprintError) as caught:
        compute_critical_fingerprint(
            tmp_path,
            "python node_modules/bin/runner.py",
            strict_safety=True,
        )

    assert caught.value.code == "unavailable"


@pytest.mark.skipif(os.name != "nt", reason="Windows UNC command-target fixture")
def test_strict_command_target_rejects_unc_intermediate_without_touching_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skipped = tmp_path / "node_modules"
    linked = skipped / "bin"
    command_target = linked / "runner.py"
    skipped.mkdir()
    try:
        linked.symlink_to(r"\\192.0.2.1\unreachable-command-target", target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    real_lexists = collector_module.os.path.lexists

    def guarded_lexists(path: object) -> bool:
        if Path(path) == command_target:
            raise AssertionError("strict command-target validation touched the UNC target")
        return bool(real_lexists(path))

    monkeypatch.setattr(collector_module.os.path, "lexists", guarded_lexists)

    with pytest.raises(CriticalFingerprintError) as caught:
        compute_critical_fingerprint(
            tmp_path,
            "python node_modules/bin/runner.py",
            strict_safety=True,
        )

    assert caught.value.code == "unavailable"


def test_strict_fingerprint_rejects_command_target_ancestor_swap_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skipped = tmp_path / "node_modules"
    original_bin = skipped / "bin"
    moved_bin = skipped / "original-bin"
    outside = tmp_path / "outside-bin"
    skipped.mkdir()
    original_bin.mkdir()
    outside.mkdir()
    (original_bin / "runner.py").write_text("print('reviewed')\n", encoding="utf-8")
    (outside / "runner.py").write_text("print('swapped')\n", encoding="utf-8")
    real_collect = fingerprint_module.collect_critical_files

    def collect_then_swap(*args: object, **kwargs: object) -> list[Path]:
        files = real_collect(*args, **kwargs)
        original_bin.rename(moved_bin)
        try:
            original_bin.symlink_to(outside, target_is_directory=True)
        except OSError:
            moved_bin.rename(original_bin)
            pytest.skip("directory symlinks are unavailable")
        return files

    monkeypatch.setattr(fingerprint_module, "collect_critical_files", collect_then_swap)

    with pytest.raises(CriticalFingerprintError) as caught:
        compute_critical_fingerprint(
            tmp_path,
            "python node_modules/bin/runner.py",
            strict_safety=True,
        )

    assert caught.value.code == "unavailable"
