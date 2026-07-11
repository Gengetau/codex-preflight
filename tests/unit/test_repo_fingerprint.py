import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, BinaryIO

import pytest

from codex_preflight_core.repo import collector as collector_module
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
