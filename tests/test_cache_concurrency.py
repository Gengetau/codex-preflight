import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from codex_preflight_core.cache.file_lock import locked_cache_file
from codex_preflight_core.cache.scan_cache import ScanCache
from codex_preflight_core.cache.trust_cache import TrustCache


def test_lock_helper_creates_sidecar_lock_file(tmp_path: Path) -> None:
    cache_path = tmp_path / "scan_cache.json"

    with locked_cache_file(cache_path):
        assert cache_path.with_suffix(cache_path.suffix + ".lock").exists()


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
            head_commit="abc",
            critical_fingerprint=f"sha256:{index}",
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
            head_commit="abc",
            critical_fingerprint=f"sha256:{index}",
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
                head_commit="def",
                critical_fingerprint=f"sha256:new-{index}",
                command_scope="test",
                approved_command=f"pytest {index}",
                expires_at=expires_at,
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(mutate, range(40)))

    data = json.loads(cache.path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert all("repoId" in entry for entry in data)
