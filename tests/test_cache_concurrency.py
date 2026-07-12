import json
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from codex_preflight_core.cache import file_lock
from codex_preflight_core.cache.file_lock import (
    CacheLockTimeoutError,
    UnsafeCacheStorageError,
    locked_cache_file,
)
from codex_preflight_core.cache.scan_cache import ScanCache
from codex_preflight_core.cache.trust_cache import TrustCache, TrustCacheMutationPrepared

HEAD = "a" * 40


@pytest.mark.skipif(os.name != "nt", reason="Windows ACE fixture")
@pytest.mark.parametrize("ace_type", [0x05, 0x09, 0x0B])
def test_unsupported_allow_ace_with_world_sid_fails_closed(ace_type: int) -> None:
    world_sid = b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    ace_size = file_lock.ctypes.sizeof(file_lock._ACE_HEADER) + file_lock.ctypes.sizeof(file_lock.wintypes.DWORD)
    fixture = file_lock.ctypes.create_string_buffer(ace_size + len(world_sid))
    header = file_lock._ACE_HEADER.from_buffer(fixture)
    header.AceType = ace_type
    header.AceSize = len(fixture)
    file_lock.ctypes.memmove(file_lock.ctypes.addressof(fixture) + ace_size, world_sid, len(world_sid))

    assert not file_lock._windows_ace_is_private(
        file_lock.ctypes.c_void_p(file_lock.ctypes.addressof(fixture)),
        {file_lock._windows_current_sid_string()},
    )


def test_lock_helper_creates_sidecar_lock_file(tmp_path: Path) -> None:
    cache_path = tmp_path / "scan_cache.json"

    with locked_cache_file(cache_path):
        assert cache_path.with_suffix(cache_path.suffix + ".lock").exists()


def test_lock_helper_accepts_a_secure_opener_without_changing_default_semantics(tmp_path: Path) -> None:
    cache_path = tmp_path / "secure.json"
    opened: list[Path] = []

    def secure_opener(path: Path):
        opened.append(path)
        return path.open("a+b")

    with locked_cache_file(cache_path, lock_opener=secure_opener):
        pass

    assert opened == [cache_path.with_suffix(".json.lock")]


def _create_v033_cache_storage(cache_path: Path) -> Path:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("[]", encoding="utf-8")
    lock_path = cache_path.with_suffix(cache_path.suffix + ".lock")
    with lock_path.open("a+b"):
        pass
    return lock_path


def _create_windows_v033_app_root(path: Path) -> None:
    file_lock._windows_create_private_directory(path)
    changed = subprocess.run(
        ["icacls", str(path), "/grant", "*S-1-5-11:(OI)(CI)(RX)"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert changed.returncode == 0, changed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission regression")
def test_private_lock_migrates_v033_posix_directory_and_lock(tmp_path: Path) -> None:
    cache_path = tmp_path / "private" / "trust.json"
    lock_path = _create_v033_cache_storage(cache_path)
    cache_path.parent.chmod(0o755)
    cache_path.chmod(0o600)
    lock_path.chmod(0o644)

    with locked_cache_file(cache_path, private_storage=True):
        pass

    assert cache_path.parent.stat().st_mode & 0o777 == 0o700
    assert cache_path.stat().st_mode & 0o777 == 0o600
    assert lock_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL regression")
def test_private_lock_migrates_v033_windows_directory_and_lock(tmp_path: Path) -> None:
    app_root = tmp_path / "v033-app-root"
    _create_windows_v033_app_root(app_root)
    cache_path = app_root / "private" / "trust.json"
    lock_path = _create_v033_cache_storage(cache_path)
    file_lock.set_current_user_owner(cache_path.parent, directory=True)
    file_lock.set_current_user_owner(cache_path)
    file_lock.set_current_user_owner(lock_path)
    assert not file_lock._windows_permissions_are_private(cache_path.parent)
    assert not file_lock._windows_permissions_are_private(lock_path)

    with locked_cache_file(cache_path, private_storage=True):
        pass

    file_lock.validate_private_cache_storage(cache_path)
    assert file_lock._windows_permissions_are_private(cache_path.parent)
    assert file_lock._windows_permissions_are_private(lock_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX replacement regression")
def test_v033_posix_migration_rejects_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "legacy.lock"
    path.write_bytes(b"")
    path.chmod(0o644)
    moved = tmp_path / "moved.lock"
    real_fchmod = file_lock.os.fchmod

    def replace_after_hardening(descriptor: int, mode: int) -> None:
        real_fchmod(descriptor, mode)
        path.replace(moved)
        path.write_bytes(b"")
        path.chmod(0o644)

    monkeypatch.setattr(file_lock.os, "fchmod", replace_after_hardening)

    with pytest.raises(UnsafeCacheStorageError):
        file_lock._harden_v033_path(path, directory=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows replacement regression")
def test_v033_windows_migration_rejects_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_root = tmp_path / "v033-replacement-root"
    _create_windows_v033_app_root(app_root)
    path = app_root / "legacy.lock"
    path.write_bytes(b"")
    file_lock.set_current_user_owner(path)
    moved = app_root / "moved.lock"
    real_set_dacl = file_lock._windows_set_private_dacl_handle

    def replace_after_hardening(handle: object, *, directory: bool) -> None:
        real_set_dacl(handle, directory=directory)
        path.replace(moved)
        path.write_bytes(b"")

    monkeypatch.setattr(file_lock, "_windows_set_private_dacl_handle", replace_after_hardening)

    with pytest.raises(UnsafeCacheStorageError):
        file_lock._harden_v033_path(path, directory=False)


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner regression")
def test_v033_posix_migration_rejects_non_current_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "legacy.lock"
    path.write_bytes(b"")
    path.chmod(0o644)
    monkeypatch.setattr(file_lock.os, "getuid", lambda: path.stat().st_uid + 1)

    with pytest.raises(UnsafeCacheStorageError, match="permissions are unsafe"):
        file_lock._harden_v033_path(path, directory=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows owner regression")
def test_v033_windows_migration_rejects_non_current_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_root = tmp_path / "v033-owner-root"
    _create_windows_v033_app_root(app_root)
    path = app_root / "legacy.lock"
    path.write_bytes(b"")
    file_lock.set_current_user_owner(path)
    monkeypatch.setattr(file_lock, "_windows_current_sid_string", lambda: "S-1-5-18")

    with pytest.raises(UnsafeCacheStorageError, match="ACL is unsafe"):
        file_lock._harden_v033_path(path, directory=False)


def test_lock_timeout_has_a_stable_exception(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(_handle: object) -> None:
        raise OSError("hidden lock detail")

    monkeypatch.setattr(file_lock, "_lock", unavailable)

    with pytest.raises(CacheLockTimeoutError):
        with locked_cache_file(tmp_path / "trust.json", timeout=0):
            pass


def test_private_shared_lock_rejects_hard_link_before_opener_is_called(tmp_path: Path) -> None:
    cache_path = tmp_path / "private" / "trust.json"
    with locked_cache_file(cache_path, private_storage=True):
        pass
    lock_path = cache_path.with_suffix(".json.lock")
    lock_path.unlink()
    source = lock_path.with_name("shared.lock")
    source.write_bytes(b"")
    os.link(source, lock_path)
    opened = False

    def forbidden_opener(_path: Path):
        nonlocal opened
        opened = True
        raise AssertionError("unsafe shared lock was followed")

    with pytest.raises(UnsafeCacheStorageError):
        with locked_cache_file(cache_path, private_storage=True, lock_opener=forbidden_opener):
            pass

    assert opened is False


def test_private_cache_path_rejects_hard_link_before_lock_open(tmp_path: Path) -> None:
    cache_path = tmp_path / "private" / "trust.json"
    with locked_cache_file(cache_path, private_storage=True):
        pass
    source = cache_path.with_name("shared.json")
    source.write_text("[]", encoding="utf-8")
    os.link(source, cache_path)
    opened = False

    def forbidden_opener(_path: Path):
        nonlocal opened
        opened = True
        raise AssertionError("unsafe cache path reached the shared lock opener")

    with pytest.raises(UnsafeCacheStorageError):
        with locked_cache_file(cache_path, private_storage=True, lock_opener=forbidden_opener):
            pass

    assert opened is False


def test_private_shared_lock_rejects_reparse_before_opener_is_called(tmp_path: Path) -> None:
    cache_path = tmp_path / "private" / "trust.json"
    with locked_cache_file(cache_path, private_storage=True):
        pass
    lock_path = cache_path.with_suffix(".json.lock")
    lock_path.unlink()
    source = lock_path.with_name("linked.lock")
    source.write_bytes(b"")
    try:
        lock_path.symlink_to(source)
    except OSError:
        pytest.skip("file symlinks are unavailable")
    opened = False

    def forbidden_opener(_path: Path):
        nonlocal opened
        opened = True
        raise AssertionError("reparse lock reached the shared lock opener")

    with pytest.raises(UnsafeCacheStorageError):
        with locked_cache_file(cache_path, private_storage=True, lock_opener=forbidden_opener):
            pass

    assert opened is False


def test_scan_cache_concurrent_stores_keep_valid_json(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "scan_cache.json")

    def store(index: int) -> None:
        cache.store(
            {
                "repoId": f"repo-{index}",
                "headCommit": "abc",
                "criticalFingerprint": f"sha256:{index}",
                "commandScope": "test",
                "policyVersion": "default-v1",
                "rulesetVersion": "2026.07.02",
            },
            {"decision": "ALLOW", "index": index},
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(store, range(40)))

    data = json.loads(cache.path.read_text(encoding="utf-8"))
    assert len(data) == 40
    assert {entry["report"]["index"] for entry in data} == set(range(40))


def test_trust_cache_concurrent_approvals_keep_valid_json(tmp_path: Path) -> None:
    cache = TrustCache(tmp_path / "trust_cache.json")

    def approve(index: int) -> None:
        cache.approve(
            repo_id=f"repo-{index}",
            path=tmp_path,
            remote_url=None,
            head_commit=HEAD,
            critical_fingerprint=f"sha256:{index:064x}",
            command_scope="test",
            approved_command=f"pytest {index}",
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(approve, range(40)))

    data = json.loads(cache.path.read_text(encoding="utf-8"))
    assert len(data) == 40
    assert {entry["repoId"] for entry in data} == {f"repo-{index}" for index in range(40)}


def test_concurrent_trust_approve_and_revoke_keep_valid_json(tmp_path: Path) -> None:
    cache = TrustCache(tmp_path / "trust_cache.json")
    expires_at = datetime.now(UTC) + timedelta(days=1)
    for index in range(10):
        cache.approve(
            repo_id=f"repo-{index}",
            path=tmp_path,
            remote_url=None,
            head_commit=HEAD,
            critical_fingerprint=f"sha256:{index:064x}",
            command_scope="test",
            approved_command=f"pytest {index}",
            expires_at=expires_at,
        )

    def mutate(index: int) -> None:
        if index % 2:
            cache.revoke_identity(f"repo-{index % 10}")
        else:
            cache.approve(
                repo_id=f"new-{index}",
                path=tmp_path,
                remote_url=None,
                head_commit="b" * 40,
                critical_fingerprint=f"sha256:{index + 100:064x}",
                command_scope="test",
                approved_command=f"pytest {index}",
                expires_at=expires_at,
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(mutate, range(40)))

    data = json.loads(cache.path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert all("repoId" in entry for entry in data)


def test_concurrent_trust_reads_and_cli_mutations_share_one_lock(tmp_path: Path) -> None:
    cache = TrustCache(tmp_path / "trust_cache.json")
    expires_at = datetime.now(UTC) + timedelta(days=1)
    for index in range(8):
        cache.approve(
            repo_id=f"seed-{index}",
            path=tmp_path,
            remote_url=None,
            head_commit=HEAD,
            critical_fingerprint=f"sha256:{index:064x}",
            command_scope="test",
            approved_command=f"pytest {index}",
            expires_at=expires_at,
        )

    def operate(index: int) -> None:
        if index % 3 == 0:
            cache.list()
        elif index % 3 == 1:
            cache.approve(
                repo_id=f"new-{index}",
                path=tmp_path,
                remote_url=None,
                head_commit="b" * 40,
                critical_fingerprint=f"sha256:{index + 100:064x}",
                command_scope="build",
                approved_command=f"build {index}",
                expires_at=expires_at,
            )
        else:
            cache.revoke_identity(f"seed-{index % 8}")

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(operate, range(60)))

    stored = json.loads(cache.path.read_text(encoding="utf-8"))
    listed = cache.list()
    assert isinstance(stored, list)
    assert all(entry["entryVersion"] == 1 for entry in stored)
    assert all(entry["entryVersion"] == 1 for entry in listed)


def test_concurrent_mcp_approvals_keep_one_exact_match_and_valid_json(tmp_path: Path) -> None:
    cache = TrustCache(tmp_path / "trust_cache.json")
    prepared_count = 0
    count_lock = threading.Lock()

    def prepare(plan):
        nonlocal prepared_count
        with count_lock:
            prepared_count += 1
        return TrustCacheMutationPrepared(plan.planned_event_id, plan.entry_id)

    def approve(index: int) -> str:
        return cache.approve_mcp(
            repo_id="same-repo",
            path=tmp_path,
            remote_url=None,
            head_commit=HEAD,
            critical_fingerprint=f"sha256:{'f' * 64}",
            command_scope="test",
            approved_command=f"pytest {index}",
            expires_at="2030-07-12T00:00:00Z",
            policy_version="default-v1",
            ruleset_version="2026.07.02",
            entry_id=str(uuid4()),
            approved_at="2026-07-12T00:00:00Z",
            approval_reason="reviewed",
            mutation_audit_event_id=str(uuid4()),
            prepare=prepare,
            commit=lambda _prepared: str(uuid4()),
        ).outcome

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(approve, range(40)))

    data = json.loads(cache.path.read_text(encoding="utf-8"))
    assert outcomes.count("approved") == 1
    assert outcomes.count("already-approved") == 39
    assert prepared_count == 1
    assert len(data) == 1
    assert data[0]["repoId"] == "same-repo"
