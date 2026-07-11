import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from codex_preflight_core.cache import atomic_json
from codex_preflight_core.cache.atomic_json import read_json, write_json_atomic
from codex_preflight_core.cache.scan_cache import ScanCache
from codex_preflight_core.cache.trust_cache import TrustCache, TrustCacheMutationPrepared

HEAD = "a" * 40
FINGERPRINT = f"sha256:{'b' * 64}"


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
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="dependency_install",
        approved_command="pnpm install",
        expires_at=expires,
    )

    assert cache.match(
        repo_id="repo",
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="dependency_install",
    )
    assert cache.match(
        repo_id="repo",
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="docker",
    ) is None
    assert len(cache.list()) == 1
    assert cache.revoke_identity("repo") == 1
    assert cache.list() == []


def test_trust_cache_scopes_by_policy_and_ruleset(tmp_path: Path) -> None:
    cache = TrustCache(tmp_path / "trust.json")
    expires = datetime.now(UTC) + timedelta(days=7)
    cache.approve(
        repo_id="repo",
        path=Path("repo"),
        remote_url="https://example/repo.git",
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="dependency_install",
        approved_command="pnpm install",
        expires_at=expires,
        policy_version="default-v1",
        ruleset_version="2026.07.08",
    )

    assert cache.match(
        repo_id="repo",
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="dependency_install",
        policy_version="default-v1",
        ruleset_version="2026.07.08",
    )
    assert (
        cache.match(
            repo_id="repo",
            head_commit=HEAD,
            critical_fingerprint=FINGERPRINT,
            command_scope="dependency_install",
            policy_version="strict-v2",
            ruleset_version="2026.07.08",
        )
        is None
    )


def test_trust_cache_has_identity_based_public_revoke_api() -> None:
    assert not hasattr(TrustCache, "revoke")
    assert hasattr(TrustCache, "revoke_identity")


def test_cli_match_and_identity_revoke_accept_mcp_created_entries(tmp_path: Path) -> None:
    cache = TrustCache(tmp_path / "trust.json")
    result = cache.approve_mcp(
        repo_id="repo",
        path=tmp_path,
        remote_url=None,
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="dependency_install",
        approved_command="pnpm install",
        expires_at="2030-07-12T00:00:00Z",
        policy_version="default-v1",
        ruleset_version="2026.07.02",
        entry_id="123e4567-e89b-42d3-a456-426614174000",
        approved_at="2026-07-12T00:00:00Z",
        approval_reason="reviewed",
        mutation_audit_event_id="123e4567-e89b-42d3-a456-426614174001",
        prepare=lambda plan: TrustCacheMutationPrepared(plan.planned_event_id, None),
        commit=lambda _prepared: "123e4567-e89b-42d3-a456-426614174002",
    )

    assert result.outcome == "approved"
    assert cache.match(
        repo_id="repo",
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="dependency_install",
    ) == result.entry
    assert cache.revoke_identity("repo") == 1
    assert cache.list() == []


def test_corrupt_json_is_backed_up_and_default_is_returned(tmp_path: Path) -> None:
    path = tmp_path / "scan-cache.json"
    path.write_text("{not-json", encoding="utf-8")

    assert read_json(path, []) == []

    backups = list(tmp_path.glob("scan-cache.json.corrupt.*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "{not-json"


def test_write_json_atomic_replaces_target_and_leaves_no_temp_files(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"

    write_json_atomic(path, [{"decision": "ALLOW"}])

    assert json.loads(path.read_text(encoding="utf-8")) == [{"decision": "ALLOW"}]
    assert not list(tmp_path.glob("*.tmp"))


def test_write_json_atomic_uses_atomic_replace_on_windows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "cache.json"
    calls: list[tuple[Path, Path]] = []
    real_replace = atomic_json.os.replace

    def tracked_replace(source: Path, target: Path) -> None:
        calls.append((source, target))
        real_replace(source, target)

    monkeypatch.setattr(atomic_json.os, "name", "nt")
    monkeypatch.setattr(atomic_json.os, "replace", tracked_replace)

    atomic_json.write_json_atomic(path, [{"decision": "ALLOW"}])

    assert len(calls) == 1
    assert calls[0][1] == path
    assert calls[0][0].parent == path.parent
    assert json.loads(path.read_text(encoding="utf-8")) == [{"decision": "ALLOW"}]
    assert not list(tmp_path.glob("*.tmp"))
