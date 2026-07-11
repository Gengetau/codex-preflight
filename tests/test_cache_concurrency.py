import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from codex_preflight_core.cache import file_lock
from codex_preflight_core.cache.file_lock import CacheLockTimeoutError, locked_cache_file
from codex_preflight_core.cache.scan_cache import ScanCache
from codex_preflight_core.cache.trust_cache import TrustCache

HEAD = "a" * 40


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


def test_lock_timeout_has_a_stable_exception(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(_handle: object) -> None:
        raise OSError("hidden lock detail")

    monkeypatch.setattr(file_lock, "_lock", unavailable)

    with pytest.raises(CacheLockTimeoutError):
        with locked_cache_file(tmp_path / "trust.json", timeout=0):
            pass


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
