from __future__ import annotations

import json
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
)

HEAD = "a" * 40
FINGERPRINT = f"sha256:{'b' * 64}"


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
        (lambda entry: entry.update(entryVersion=2), "unsupported-schema"),
    ],
    ids=["decision", "actor", "head", "fingerprint", "scope", "future-entry-version"],
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
