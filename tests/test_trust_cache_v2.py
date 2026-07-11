from __future__ import annotations

import json
import stat
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from codex_preflight_core.cache import trust_cache
from codex_preflight_core.cache.trust_cache import (
    TRUST_CACHE_MAX_BYTES,
    TrustCache,
    TrustCacheError,
    TrustCacheMutationCommitError,
    TrustCacheMutationPrepared,
)

HEAD = "a" * 40
FINGERPRINT = f"sha256:{'b' * 64}"
MCP_ENTRY_ID = "123e4567-e89b-42d3-a456-426614174000"
MCP_PREPARED_EVENT_ID = "123e4567-e89b-42d3-a456-426614174001"
MCP_FINAL_EVENT_ID = "123e4567-e89b-42d3-a456-426614174002"
MCP_APPROVED_AT = "2026-07-12T00:00:00Z"
MCP_EXPIRES_AT = "2030-07-12T00:00:00Z"


def mcp_approval_kwargs(tmp_path: Path, **overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "repo_id": "mcp-repository",
        "path": tmp_path,
        "remote_url": None,
        "head_commit": HEAD,
        "critical_fingerprint": FINGERPRINT,
        "command_scope": "test",
        "approved_command": "python -m pytest",
        "expires_at": MCP_EXPIRES_AT,
        "policy_version": "default-v1",
        "ruleset_version": "2026.07.02",
        "entry_id": MCP_ENTRY_ID,
        "approved_at": MCP_APPROVED_AT,
        "approval_reason": "reviewed",
        "mutation_audit_event_id": MCP_PREPARED_EVENT_ID,
    }
    kwargs.update(overrides)
    return kwargs


def legacy_entry(*, repo_id: str = "https://github.com/example/project") -> dict[str, object]:
    return {
        "repoId": repo_id,
        "path": "C:/work/project",
        "remoteUrl": "https://github.com/example/project",
        "headCommit": HEAD,
        "criticalFingerprint": FINGERPRINT,
        "commandScope": "dependency_install",
        "approvedCommand": "python -m pip install -e .",
        "decision": "USER_APPROVED",
        "approvedAt": datetime.now(UTC).isoformat(),
        "expiresAt": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
        "approvedBy": "local-user",
        "policyVersion": "default-v1",
        "rulesetVersion": "2026.07.02",
    }


def test_legacy_migration_adds_only_v2_metadata_and_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    original = legacy_entry()
    path.write_text(json.dumps([original], indent=2), encoding="utf-8")

    cache = TrustCache(path)
    listed = cache.list()
    migrated = json.loads(path.read_text(encoding="utf-8"))

    assert listed == migrated
    assert len(migrated) == 1
    for name, value in original.items():
        assert migrated[0][name] == value
    assert UUID(migrated[0]["entryId"]).version == 4
    assert migrated[0]["entryVersion"] == 1
    assert migrated[0]["provenance"] == {
        "schema": "trust-cache-array-v2",
        "source": "legacy-migration",
        "migrationVersion": "v0.3.3-trust-read-foundation",
        "migratedAt": migrated[0]["provenance"]["migratedAt"],
    }
    datetime.fromisoformat(migrated[0]["provenance"]["migratedAt"])
    backups = list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text(encoding="utf-8")) == [original]

    first_bytes = path.read_bytes()
    first_entry_id = migrated[0]["entryId"]
    assert cache.list()[0]["entryId"] == first_entry_id
    assert path.read_bytes() == first_bytes
    assert len(list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))) == 1
    assert cache.match(
        repo_id=str(original["repoId"]),
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="dependency_install",
    )


def test_cli_approve_creates_v2_metadata_without_migration_backup(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)

    cache.approve(
        repo_id="C:/work/project",
        path=Path("C:/work/project"),
        remote_url=None,
        head_commit=None,
        critical_fingerprint=FINGERPRINT,
        command_scope="test",
        approved_command="python -m pytest",
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert len(stored) == 1
    assert UUID(stored[0]["entryId"]).version == 4
    assert stored[0]["entryVersion"] == 1
    assert stored[0]["provenance"] == {
        "schema": "trust-cache-array-v2",
        "source": "cli-trust-approve",
        "migrationVersion": "v0.3.3-trust-read-foundation",
        "createdAt": stored[0]["provenance"]["createdAt"],
    }
    datetime.fromisoformat(stored[0]["provenance"]["createdAt"])
    assert not list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))
    assert cache.match(
        repo_id="C:/work/project",
        head_commit=None,
        critical_fingerprint=FINGERPRINT,
        command_scope="test",
    )
    assert cache.revoke_identity("C:/work/project") == 1
    assert cache.list() == []


def test_missing_trust_store_lists_empty_without_creating_store(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"

    assert TrustCache(path).list() == []
    assert not path.exists()


def test_expired_legacy_entry_is_migrated_but_not_returned(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    entry = legacy_entry()
    entry["expiresAt"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    path.write_text(json.dumps([entry]), encoding="utf-8")

    assert TrustCache(path).list() == []
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert len(stored) == 1
    assert stored[0]["expiresAt"] == entry["expiresAt"]
    assert stored[0]["entryVersion"] == 1


def test_migration_write_failure_keeps_original_and_reports_migration_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "trust.json"
    original = json.dumps([legacy_entry()], indent=2).encode()
    path.write_bytes(original)

    def fail_write(_path: Path, _data: object) -> None:
        raise OSError("hidden replace detail")

    monkeypatch.setattr(trust_cache, "write_json_atomic", fail_write)

    with pytest.raises(TrustCacheError) as caught:
        TrustCache(path).list()

    assert caught.value.code == "migration-failed"
    assert path.read_bytes() == original
    assert len(list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))) == 1


def test_failed_migrations_keep_three_backups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "trust.json"
    original = json.dumps([legacy_entry()]).encode("utf-8")
    path.write_bytes(original)

    def fail_write(_path: Path, _data: object) -> None:
        raise OSError("hidden replace detail")

    monkeypatch.setattr(trust_cache, "write_json_atomic", fail_write)

    for _ in range(7):
        with pytest.raises(TrustCacheError) as caught:
            TrustCache(path).list()
        assert caught.value.code == "migration-failed"
        assert path.read_bytes() == original

    assert len(list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))) == 3


def test_prune_failure_does_not_add_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "trust.json"
    original = json.dumps([legacy_entry()]).encode("utf-8")
    path.write_bytes(original)
    for index in range(3):
        (tmp_path / f"trust.json.v0.3.3-migration.20000101T00000000000{index}Z.old.bak").write_text(
            "[]",
            encoding="utf-8",
        )
    real_unlink = Path.unlink

    def fail_backup_unlink(target: Path, *args: object, **kwargs: object) -> None:
        if ".v0.3.3-migration." in target.name:
            raise OSError("hidden prune failure")
        real_unlink(target, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_backup_unlink)

    for _ in range(3):
        with pytest.raises(TrustCacheError) as caught:
            TrustCache(path).list()
        assert caught.value.code == "migration-failed"
        assert path.read_bytes() == original

    assert len(list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))) == 3


def test_migration_retains_at_most_three_bounded_backups(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    path.write_text(json.dumps([legacy_entry()]), encoding="utf-8")
    for index in range(3):
        (tmp_path / f"trust.json.v0.3.3-migration.20000101T00000000000{index}Z.old.bak").write_text(
            "[]",
            encoding="utf-8",
        )

    TrustCache(path).list()

    backups = list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))
    assert len(backups) == 3
    payloads = [json.loads(backup.read_text(encoding="utf-8")) for backup in backups]
    assert any(payload and payload[0]["repoId"] == legacy_entry()["repoId"] for payload in payloads)


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (lambda entry: entry.update(decision="ALLOW"), "corrupt"),
        (lambda entry: entry.update(approvedBy="repository-agent"), "corrupt"),
        (lambda entry: entry.update(headCommit="abc"), "corrupt"),
        (lambda entry: entry.update(criticalFingerprint="sha256:test"), "corrupt"),
        (lambda entry: entry.update(commandScope="anything"), "corrupt"),
        (lambda entry: entry.update(repoId=""), "corrupt"),
        (lambda entry: entry.update(repoId="repo\x85value"), "corrupt"),
        (lambda entry: entry.update(repoId="repo\ud800value"), "corrupt"),
        (lambda entry: entry.update(path=7), "corrupt"),
        (lambda entry: entry.update(approvedCommand="run\x00hidden"), "corrupt"),
        (lambda entry: entry.update(remoteUrl=""), "corrupt"),
        (lambda entry: entry.update(policyVersion="x" * 4097), "corrupt"),
        (lambda entry: entry.update(approvedAt="not-a-timestamp"), "corrupt"),
        (lambda entry: entry.update(approvedAt="2026-01-01T00:00:00\ud800+00:00"), "corrupt"),
        (lambda entry: entry.update(approvedAt="2026-01-01 00:00:00+00:00"), "corrupt"),
        (
            lambda entry: entry.update(approvedAt=f"2026-01-01T00:00:00.{'1' * 4100}+00:00"),
            "corrupt",
        ),
        (lambda entry: entry.update(expiresAt="2026-01-01T00:00:00"), "corrupt"),
        (lambda entry: entry.update(entryVersion=True), "unsupported-schema"),
        (lambda entry: entry.update(entryVersion=1.0), "unsupported-schema"),
        (lambda entry: entry.update(entryVersion=2), "unsupported-schema"),
    ],
    ids=[
        "decision",
        "actor",
        "head",
        "fingerprint",
        "scope",
        "empty-repo-id",
        "repo-id-c1-control",
        "repo-id-unpaired-surrogate",
        "path-type",
        "command-control",
        "empty-remote-url",
        "oversized-policy",
        "approved-at",
        "approved-at-unpaired-surrogate",
        "approved-at-space",
        "approved-at-oversized",
        "expires-at",
        "boolean-partial-entry-version",
        "float-partial-entry-version",
        "future-entry-version",
    ],
)
def test_invalid_or_unsupported_trust_entries_fail_closed(
    tmp_path: Path,
    mutate,
    expected_code: str,
) -> None:
    path = tmp_path / "trust.json"
    entry = deepcopy(legacy_entry())
    mutate(entry)
    path.write_text(json.dumps([entry]), encoding="utf-8")

    with pytest.raises(TrustCacheError) as caught:
        TrustCache(path).list()

    assert caught.value.code == expected_code
    assert not list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))


@pytest.mark.parametrize(
    "entry_version",
    [True, 1.0],
    ids=["boolean", "float"],
)
def test_non_integer_v2_entry_versions_fail_closed(tmp_path: Path, entry_version: object) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    cache.approve(
        repo_id="C:/work/project",
        path=Path("C:/work/project"),
        remote_url=None,
        head_commit=None,
        critical_fingerprint=FINGERPRINT,
        command_scope="test",
        approved_command="python -m pytest",
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    entries = json.loads(path.read_text(encoding="utf-8"))
    entries[0]["entryVersion"] = entry_version
    path.write_text(json.dumps(entries), encoding="utf-8")

    with pytest.raises(TrustCacheError) as caught:
        cache.list()

    assert caught.value.code == "unsupported-schema"


def test_corrupt_and_oversized_trust_stores_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(TrustCacheError) as corrupt:
        TrustCache(path).list()
    assert corrupt.value.code == "corrupt"

    path.write_bytes(b" " * (TRUST_CACHE_MAX_BYTES + 1))
    with pytest.raises(TrustCacheError) as oversized:
        TrustCache(path).list()
    assert oversized.value.code == "unavailable"


def test_unsupported_top_level_shape_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    path.write_text(json.dumps({"entries": []}), encoding="utf-8")

    with pytest.raises(TrustCacheError) as caught:
        TrustCache(path).list()

    assert caught.value.code == "unsupported-schema"


@pytest.mark.parametrize("migrated", [False, True], ids=["legacy", "v2"])
def test_legacy_and_v2_stores_over_one_mib_fail_before_listing(
    tmp_path: Path,
    migrated: bool,
) -> None:
    path = tmp_path / "trust.json"
    entry = legacy_entry()
    if migrated:
        seed = TrustCache(path)
        seed.approve(
            repo_id="repo",
            path=tmp_path,
            remote_url=None,
            head_commit=HEAD,
            critical_fingerprint=FINGERPRINT,
            command_scope="test",
            approved_command="pytest",
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        entry = json.loads(path.read_text(encoding="utf-8"))[0]
    payload = json.dumps([entry] * 2500).encode("utf-8")
    assert len(payload) > TRUST_CACHE_MAX_BYTES
    path.write_bytes(payload)

    with pytest.raises(TrustCacheError) as caught:
        TrustCache(path).list()

    assert caught.value.code == "unavailable"
    assert not list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))


def test_migration_backup_failure_preserves_original_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "trust.json"
    original = json.dumps([legacy_entry()]).encode("utf-8")
    path.write_bytes(original)
    monkeypatch.setattr(trust_cache.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("hidden")))

    with pytest.raises(TrustCacheError) as caught:
        TrustCache(path).list()

    assert caught.value.code == "migration-failed"
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))


def test_migration_preserves_trust_file_and_backup_permissions(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    path.write_text(json.dumps([legacy_entry()]), encoding="utf-8")
    before = stat.S_IMODE(path.stat().st_mode)

    TrustCache(path).list()

    backup = next(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))
    assert stat.S_IMODE(path.stat().st_mode) == before
    assert stat.S_IMODE(backup.stat().st_mode) == before


def test_duplicate_v2_entry_ids_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    expires_at = datetime.now(UTC) + timedelta(days=7)
    for index in range(2):
        cache.approve(
            repo_id=f"repo-{index}",
            path=tmp_path,
            remote_url=None,
            head_commit=HEAD,
            critical_fingerprint=f"sha256:{index:064x}",
            command_scope="test",
            approved_command="pytest",
            expires_at=expires_at,
        )
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored[1]["entryId"] = stored[0]["entryId"]
    path.write_text(json.dumps(stored), encoding="utf-8")

    with pytest.raises(TrustCacheError) as caught:
        cache.list()

    assert caught.value.code == "corrupt"


def test_migration_id_collision_fails_before_replace(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    entries = [legacy_entry(repo_id=f"repo-{index}") for index in range(2)]
    original = json.dumps(entries).encode("utf-8")
    path.write_bytes(original)
    cache = TrustCache(
        path,
        entry_id_factory=lambda: "123e4567-e89b-42d3-a456-426614174000",
    )

    with pytest.raises(TrustCacheError) as caught:
        cache.list()

    assert caught.value.code == "migration-failed"
    assert path.read_bytes() == original
    assert len(list(tmp_path.glob("trust.json.v0.3.3-migration.*.bak"))) == 1


def test_size_cap_rejects_cli_write_before_replacing_existing_store(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path, max_bytes=1400)
    expires_at = datetime.now(UTC) + timedelta(days=7)
    cache.approve(
        repo_id="repo-one",
        path=tmp_path,
        remote_url=None,
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="test",
        approved_command="pytest",
        expires_at=expires_at,
    )
    original = path.read_bytes()

    with pytest.raises(TrustCacheError) as caught:
        cache.approve(
            repo_id="repo-two",
            path=tmp_path,
            remote_url=None,
            head_commit=HEAD,
            critical_fingerprint=f"sha256:{'c' * 64}",
            command_scope="test",
            approved_command="x" * 1000,
            expires_at=expires_at,
        )

    assert caught.value.code == "unavailable"
    assert path.read_bytes() == original
    assert [entry["repoId"] for entry in cache.list()] == ["repo-one"]


def test_mcp_approval_records_exact_provenance_and_write_ahead_bytes(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    cache.approve(
        repo_id="unrelated",
        path=tmp_path,
        remote_url=None,
        head_commit=HEAD,
        critical_fingerprint=f"sha256:{'c' * 64}",
        command_scope="test",
        approved_command="existing command",
        expires_at=datetime(2031, 1, 1, tzinfo=UTC),
    )
    before = path.read_bytes()
    before_entry = json.loads(before)[0]
    callbacks: list[str] = []
    seen_after: list[bytes] = []

    def prepare(plan):
        callbacks.append("prepare")
        assert plan.operation == "approve"
        assert plan.entry_id == MCP_ENTRY_ID
        assert plan.before_bytes == before
        assert path.read_bytes() == before
        seen_after.append(plan.after_bytes)
        return TrustCacheMutationPrepared(MCP_PREPARED_EVENT_ID, "prepared")

    def commit(prepared):
        callbacks.append("commit")
        assert prepared.event_id == MCP_PREPARED_EVENT_ID
        assert prepared.state == "prepared"
        assert path.read_bytes() == seen_after[0]
        return MCP_FINAL_EVENT_ID

    result = cache.approve_mcp(
        **mcp_approval_kwargs(tmp_path),
        prepare=prepare,
        commit=commit,
    )

    stored = json.loads(path.read_bytes())
    assert callbacks == ["prepare", "commit"]
    assert path.read_bytes() == seen_after[0]
    assert stored[0] == before_entry
    assert stored[1]["approvedAt"] == MCP_APPROVED_AT
    assert stored[1]["expiresAt"] == MCP_EXPIRES_AT
    assert stored[1]["provenance"] == {
        "schema": "trust-cache-array-v2",
        "source": "mcp-trust-approve",
        "migrationVersion": "v0.3.4-trust-mutation",
        "createdAt": MCP_APPROVED_AT,
        "approvalReason": "reviewed",
        "mutationAuditEventId": MCP_PREPARED_EVENT_ID,
    }
    assert result.outcome == "approved"
    assert result.applied is True
    assert result.entry == stored[1]
    assert result.prepared_event_id == MCP_PREPARED_EVENT_ID
    assert result.final_event_id == MCP_FINAL_EVENT_ID


def test_mcp_approval_duplicate_is_a_no_write_no_ttl_extension(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)

    def prepare(plan):
        return TrustCacheMutationPrepared(plan.planned_event_id, object())

    def commit(_prepared):
        return MCP_FINAL_EVENT_ID

    initial = cache.approve_mcp(
        **mcp_approval_kwargs(tmp_path),
        prepare=prepare,
        commit=commit,
    )
    before = path.read_bytes()
    callbacks: list[str] = []

    def unexpected_prepare(_plan):
        callbacks.append("prepare")
        raise AssertionError("duplicate approval must not prepare a mutation")

    duplicate = cache.approve_mcp(
        **mcp_approval_kwargs(
            tmp_path,
            approved_command="changed command is not part of matching",
            expires_at="2031-07-12T00:00:00Z",
            entry_id="123e4567-e89b-42d3-a456-426614174003",
            mutation_audit_event_id="123e4567-e89b-42d3-a456-426614174004",
        ),
        prepare=unexpected_prepare,
        commit=lambda _prepared: (_ for _ in ()).throw(AssertionError("must not commit")),
    )

    assert initial.entry is not None
    assert duplicate.outcome == "already-approved"
    assert duplicate.applied is False
    assert duplicate.entry == initial.entry
    assert duplicate.prepared_event_id is None
    assert duplicate.final_event_id is None
    assert callbacks == []
    assert path.read_bytes() == before


def test_mcp_approval_rejects_an_entry_id_collision_before_preparing(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    cache.approve_mcp(
        **mcp_approval_kwargs(tmp_path),
        prepare=lambda plan: TrustCacheMutationPrepared(plan.planned_event_id, None),
        commit=lambda _prepared: MCP_FINAL_EVENT_ID,
    )
    before = path.read_bytes()

    with pytest.raises(TrustCacheError) as caught:
        cache.approve_mcp(
            **mcp_approval_kwargs(
                tmp_path,
                repo_id="different-repository",
                critical_fingerprint=f"sha256:{'f' * 64}",
                mutation_audit_event_id="123e4567-e89b-42d3-a456-426614174003",
            ),
            prepare=lambda _plan: (_ for _ in ()).throw(AssertionError("collision must not prepare")),
            commit=lambda _prepared: (_ for _ in ()).throw(AssertionError("collision must not commit")),
        )

    assert caught.value.code == "corrupt"
    assert path.read_bytes() == before


def test_mcp_mutations_preserve_expired_and_unrelated_entries(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    now = datetime(2026, 7, 12, tzinfo=UTC)
    cache = TrustCache(path, clock=lambda: now)
    cache.approve(
        repo_id="expired",
        path=tmp_path,
        remote_url=None,
        head_commit=HEAD,
        critical_fingerprint=f"sha256:{'d' * 64}",
        command_scope="test",
        approved_command="expired command",
        expires_at=now - timedelta(seconds=1),
    )
    expired = json.loads(path.read_bytes())[0]

    result = cache.approve_mcp(
        **mcp_approval_kwargs(tmp_path),
        prepare=lambda plan: TrustCacheMutationPrepared(plan.planned_event_id, None),
        commit=lambda _prepared: MCP_FINAL_EVENT_ID,
    )
    after_approval = path.read_bytes()

    absent = cache.revoke_entry_id(
        expired["entryId"],
        expected_version=1,
        prepare=lambda _plan: (_ for _ in ()).throw(AssertionError("expired entry is not revocable")),
        commit=lambda _prepared: (_ for _ in ()).throw(AssertionError("expired entry is not revocable")),
    )

    assert result.outcome == "approved"
    assert json.loads(after_approval)[0] == expired
    assert absent.outcome == "not-found"
    assert absent.applied is False
    assert path.read_bytes() == after_approval


def test_mcp_revocation_deletes_only_one_entry_and_hides_missing_ids(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)

    def prepare(plan):
        return TrustCacheMutationPrepared(plan.planned_event_id or MCP_PREPARED_EVENT_ID, "prepared")

    first = cache.approve_mcp(
        **mcp_approval_kwargs(tmp_path),
        prepare=prepare,
        commit=lambda _prepared: MCP_FINAL_EVENT_ID,
    )
    second = cache.approve_mcp(
        **mcp_approval_kwargs(
            tmp_path,
            repo_id="second-repository",
            critical_fingerprint=f"sha256:{'e' * 64}",
            entry_id="123e4567-e89b-42d3-a456-426614174005",
            mutation_audit_event_id="123e4567-e89b-42d3-a456-426614174006",
        ),
        prepare=prepare,
        commit=lambda _prepared: MCP_FINAL_EVENT_ID,
    )
    assert first.entry is not None
    assert second.entry is not None
    before_revoke = path.read_bytes()
    seen_after: list[bytes] = []

    def revoke_prepare(plan):
        assert plan.operation == "revoke"
        assert plan.before_bytes == before_revoke
        seen_after.append(plan.after_bytes)
        return TrustCacheMutationPrepared(MCP_PREPARED_EVENT_ID, "revocation")

    revoked = cache.revoke_entry_id(
        first.entry["entryId"],
        expected_version=1,
        prepare=revoke_prepare,
        commit=lambda _prepared: MCP_FINAL_EVENT_ID,
    )
    after_revoke = path.read_bytes()
    missing = cache.revoke_entry_id(
        "123e4567-e89b-42d3-a456-426614174007",
        expected_version=1,
        prepare=lambda _plan: (_ for _ in ()).throw(AssertionError("missing entry must not prepare")),
        commit=lambda _prepared: (_ for _ in ()).throw(AssertionError("missing entry must not commit")),
    )

    assert revoked.outcome == "revoked"
    assert revoked.applied is True
    assert revoked.entry == first.entry
    assert after_revoke == seen_after[0]
    assert [entry["entryId"] for entry in json.loads(after_revoke)] == [second.entry["entryId"]]
    assert missing.outcome == "not-found"
    assert missing.applied is False
    assert path.read_bytes() == after_revoke


def test_mcp_revocation_detects_complete_entry_drift_without_writing(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    created = cache.approve_mcp(
        **mcp_approval_kwargs(tmp_path),
        prepare=lambda plan: TrustCacheMutationPrepared(plan.planned_event_id, None),
        commit=lambda _prepared: MCP_FINAL_EVENT_ID,
    )
    assert created.entry is not None
    expected_entry = deepcopy(created.entry)
    expected_entry["approvedCommand"] = "command from a stale challenge"
    before = path.read_bytes()

    drift = cache.revoke_entry_id(
        MCP_ENTRY_ID,
        expected_version=1,
        expected_entry=expected_entry,
        prepare=lambda _plan: (_ for _ in ()).throw(AssertionError("drift must not prepare")),
        commit=lambda _prepared: (_ for _ in ()).throw(AssertionError("drift must not commit")),
    )

    assert drift.outcome == "version-conflict"
    assert drift.applied is False
    assert drift.entry == created.entry
    assert path.read_bytes() == before


@pytest.mark.parametrize("expected_version", [True, 1.0], ids=["boolean", "float"])
def test_mcp_revocation_rejects_non_integer_expected_versions(
    tmp_path: Path,
    expected_version: object,
) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    cache.approve_mcp(
        **mcp_approval_kwargs(tmp_path),
        prepare=lambda plan: TrustCacheMutationPrepared(plan.planned_event_id, None),
        commit=lambda _prepared: MCP_FINAL_EVENT_ID,
    )
    before = path.read_bytes()

    with pytest.raises(ValueError):
        cache.revoke_entry_id(
            MCP_ENTRY_ID,
            expected_version=expected_version,
            prepare=lambda _plan: (_ for _ in ()).throw(AssertionError("must not prepare")),
            commit=lambda _prepared: (_ for _ in ()).throw(AssertionError("must not commit")),
        )

    assert path.read_bytes() == before


def test_mcp_callback_failure_before_replace_preserves_store(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    path.write_text("[]", encoding="utf-8")
    before = path.read_bytes()
    committed = False

    def fail_prepare(_plan):
        raise RuntimeError("prepare failed")

    def commit(_prepared):
        nonlocal committed
        committed = True
        return MCP_FINAL_EVENT_ID

    with pytest.raises(RuntimeError, match="prepare failed"):
        cache.approve_mcp(**mcp_approval_kwargs(tmp_path), prepare=fail_prepare, commit=commit)

    assert committed is False
    assert path.read_bytes() == before


def test_mcp_callback_failure_after_replace_reports_committed_state(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    path.write_text("[]", encoding="utf-8")
    after: list[bytes] = []

    def prepare(plan):
        after.append(plan.after_bytes)
        return TrustCacheMutationPrepared(plan.planned_event_id, "prepared")

    with pytest.raises(TrustCacheMutationCommitError) as caught:
        cache.approve_mcp(
            **mcp_approval_kwargs(tmp_path),
            prepare=prepare,
            commit=lambda _prepared: (_ for _ in ()).throw(RuntimeError("commit failed")),
        )

    assert path.read_bytes() == after[0]
    assert caught.value.result.outcome == "approved"
    assert caught.value.result.applied is True
    assert caught.value.result.prepared_event_id == MCP_PREPARED_EVENT_ID
    assert caught.value.result.final_event_id is None


def test_mcp_approval_rejects_an_intended_store_over_the_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path, max_bytes=800)
    path.write_text("[]", encoding="utf-8")
    before = path.read_bytes()

    with pytest.raises(TrustCacheError) as caught:
        cache.approve_mcp(
            **mcp_approval_kwargs(tmp_path, approved_command="x" * 1000),
            prepare=lambda _plan: (_ for _ in ()).throw(AssertionError("must not prepare")),
            commit=lambda _prepared: (_ for _ in ()).throw(AssertionError("must not commit")),
        )

    assert caught.value.code == "unavailable"
    assert path.read_bytes() == before


@pytest.mark.parametrize("field", ["approved_at", "expires_at"], ids=["approved-at", "expires-at"])
def test_mcp_approval_requires_exact_utc_z_timestamps(tmp_path: Path, field: str) -> None:
    cache = TrustCache(tmp_path / "trust.json")
    invalid = {field: "2030-07-12T00:00:00+00:00"}

    with pytest.raises(TrustCacheError) as caught:
        cache.approve_mcp(
            **mcp_approval_kwargs(tmp_path, **invalid),
            prepare=lambda _plan: (_ for _ in ()).throw(AssertionError("invalid timestamps must not prepare")),
            commit=lambda _prepared: (_ for _ in ()).throw(AssertionError("invalid timestamps must not commit")),
        )

    assert caught.value.code == "corrupt"


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda provenance: provenance.update(unexpected="field"),
            "corrupt",
        ),
        (
            lambda provenance: provenance.update(migrationVersion="v0.3.3-trust-read-foundation"),
            "unsupported-schema",
        ),
        (
            lambda provenance: provenance.update(approvalReason="reviewed\x00hidden"),
            "corrupt",
        ),
        (
            lambda provenance: provenance.pop("mutationAuditEventId"),
            "corrupt",
        ),
        (
            lambda provenance: provenance.update(mutationAuditEventId="123e4567-e89b-52d3-a456-426614174001"),
            "corrupt",
        ),
    ],
    ids=["unknown-field", "wrong-version", "control-reason", "missing-audit-id", "non-v4-audit-id"],
)
def test_mcp_provenance_requires_the_exact_source_specific_schema(
    tmp_path: Path,
    mutate,
    expected_code: str,
) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    cache.approve_mcp(
        **mcp_approval_kwargs(tmp_path),
        prepare=lambda plan: TrustCacheMutationPrepared(plan.planned_event_id, None),
        commit=lambda _prepared: MCP_FINAL_EVENT_ID,
    )
    entries = json.loads(path.read_text(encoding="utf-8"))
    mutate(entries[0]["provenance"])
    path.write_text(json.dumps(entries), encoding="utf-8")

    with pytest.raises(TrustCacheError) as caught:
        cache.list()

    assert caught.value.code == expected_code


def test_mcp_provenance_rejects_non_z_approved_and_created_timestamps(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    cache = TrustCache(path)
    cache.approve_mcp(
        **mcp_approval_kwargs(tmp_path),
        prepare=lambda plan: TrustCacheMutationPrepared(plan.planned_event_id, None),
        commit=lambda _prepared: MCP_FINAL_EVENT_ID,
    )
    entries = json.loads(path.read_text(encoding="utf-8"))
    entries[0]["approvedAt"] = "2026-07-12T00:00:00+00:00"
    entries[0]["provenance"]["createdAt"] = "2026-07-12T00:00:00+00:00"
    path.write_text(json.dumps(entries), encoding="utf-8")

    with pytest.raises(TrustCacheError) as caught:
        cache.list()

    assert caught.value.code == "corrupt"
