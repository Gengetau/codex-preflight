from datetime import UTC, datetime, timedelta
from pathlib import Path

from codex_preflight_core.cache.scan_cache import ScanCache
from codex_preflight_core.cache.trust_cache import TrustCache


def test_scan_cache_reuses_matching_allow_report_and_invalidates_fingerprint(
    tmp_path: Path,
) -> None:
    cache = ScanCache(tmp_path / "scan-cache.json")
    key = {
        "repoId": "repo",
        "headCommit": "abc",
        "criticalFingerprint": "sha256:a",
        "commandScope": "dependency_install",
        "policyVersion": "default-v1",
        "rulesetVersion": "2026.07.02",
    }
    cache.store(key, {"decision": "ALLOW", "riskScore": 0})

    assert cache.get(key)["decision"] == "ALLOW"
    changed = {**key, "criticalFingerprint": "sha256:b"}
    assert cache.get(changed) is None


def test_scan_cache_does_not_reuse_block_or_ask_user(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "scan-cache.json")
    key = {
        "repoId": "repo",
        "headCommit": "abc",
        "criticalFingerprint": "sha256:a",
        "commandScope": "dependency_install",
        "policyVersion": "default-v1",
        "rulesetVersion": "2026.07.02",
    }
    cache.store(key, {"decision": "BLOCK"})

    assert cache.get(key) is None


def test_trust_cache_scopes_by_command_scope_and_expiry(tmp_path: Path) -> None:
    cache = TrustCache(tmp_path / "trust.json")
    expires = datetime.now(UTC) + timedelta(days=7)
    cache.approve(
        repo_id="repo",
        path=Path("repo"),
        remote_url="https://example/repo.git",
        head_commit="abc",
        critical_fingerprint="sha256:a",
        command_scope="dependency_install",
        approved_command="pnpm install",
        expires_at=expires,
    )

    assert cache.match(
        repo_id="repo",
        head_commit="abc",
        critical_fingerprint="sha256:a",
        command_scope="dependency_install",
    )
    assert cache.match(
        repo_id="repo",
        head_commit="abc",
        critical_fingerprint="sha256:a",
        command_scope="docker",
    ) is None
    assert len(cache.list()) == 1
    cache.revoke(Path("repo"))
    assert cache.list() == []
