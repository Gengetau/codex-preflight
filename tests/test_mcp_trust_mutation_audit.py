from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

import pytest

from codex_preflight_core.cache.paths import trust_mutation_audit_key_path, trust_mutation_audit_path
from codex_preflight_mcp.trust_mutation_audit import (
    AUDIT_MAX_RECORD_BYTES,
    AUDIT_MAX_ROTATED_SEGMENTS,
    AUDIT_MAX_SEGMENT_BYTES,
    AUDIT_MAX_TOTAL_BYTES,
    AuditContext,
    TrustMutationAuditError,
    TrustMutationAuditLog,
)

ENTRY_ID = "123e4567-e89b-42d3-a456-426614174000"
OPERATION_ID = "223e4567-e89b-42d3-a456-426614174000"
CHALLENGE_ID = "323e4567-e89b-42d3-a456-426614174000"
KEY = b"k" * 32
AFTER = b'[{"trusted":true}]\n'


def _context(**changes: object) -> AuditContext:
    values: dict[str, object] = {
        "tool": "trust_approve",
        "operation_id": OPERATION_ID,
        "operation": "approve",
        "target_hash": f"hmac-sha256:{'a' * 64}",
        "entry_id": ENTRY_ID,
        "scope": "test",
        "policy_version": "policy-v1",
        "ruleset_version": "rules-v1",
        "challenge_id": CHALLENGE_ID,
        "outcome": "pending",
        "error_code": None,
        "entry_version": 1,
    }
    values.update(changes)
    return AuditContext(**values)  # type: ignore[arg-type]


def _audit(tmp_path: Path, **changes: object) -> TrustMutationAuditLog:
    values: dict[str, object] = {
        "path": trust_mutation_audit_path(tmp_path),
        "key_path": trust_mutation_audit_key_path(tmp_path),
        "key_factory": lambda size: KEY,
        "clock": lambda: 1_700_000_000.0,
    }
    values.update(changes)
    return TrustMutationAuditLog(**values)  # type: ignore[arg-type]


def _segments(path: Path) -> list[Path]:
    return [path.with_name(f"{path.name}.{index}") for index in range(3, 0, -1)] + [path]


def _records(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for segment in _segments(path):
        if segment.exists():
            records.extend(json.loads(line) for line in segment.read_text(encoding="utf-8").splitlines())
    return records


def test_mutation_paths_use_a_dedicated_application_home_namespace(tmp_path: Path) -> None:
    assert trust_mutation_audit_path(tmp_path) == tmp_path / "trust-mutation" / "audit.jsonl"
    assert trust_mutation_audit_key_path(tmp_path) == tmp_path / "trust-mutation" / "audit.key"


def test_limits_are_exact() -> None:
    assert AUDIT_MAX_RECORD_BYTES == 4096
    assert AUDIT_MAX_SEGMENT_BYTES == 1024 * 1024
    assert AUDIT_MAX_ROTATED_SEGMENTS == 3
    assert AUDIT_MAX_TOTAL_BYTES == 4 * 1024 * 1024


def test_key_is_created_atomically_once_with_owner_only_permissions(tmp_path: Path) -> None:
    calls: list[int] = []
    audit = _audit(tmp_path, key_factory=lambda size: calls.append(size) or KEY)

    audit.record("request_validated", context=_context(outcome="validated"))
    audit.record("success", context=_context(outcome="success"))

    key_path = trust_mutation_audit_key_path(tmp_path)
    assert calls == [32]
    assert key_path.read_bytes() == KEY
    if os.name != "nt":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


@pytest.mark.parametrize("stored_key", [b"", b"x" * 31])
def test_invalid_persistent_key_fails_closed_without_private_detail(tmp_path: Path, stored_key: bytes) -> None:
    audit = _audit(tmp_path)
    audit.key_path.parent.mkdir(parents=True)
    audit.key_path.write_bytes(stored_key)

    with pytest.raises(TrustMutationAuditError) as caught:
        audit.record("success", context=_context(outcome="success"))

    assert caught.value.code == "MCP_TRUST_MUTATION_AUDIT_FAILED"
    assert str(audit.key_path) not in str(caught.value)
    if stored_key:
        assert stored_key.hex() not in str(caught.value)


def test_key_symlink_and_hard_link_are_rejected(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    audit.key_path.parent.mkdir(parents=True)
    source = tmp_path / "source.key"
    source.write_bytes(KEY)
    try:
        audit.key_path.symlink_to(source)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(TrustMutationAuditError):
        audit.record("success", context=_context(outcome="success"))

    audit.key_path.unlink()
    os.link(source, audit.key_path)
    with pytest.raises(TrustMutationAuditError):
        audit.record("success", context=_context(outcome="success"))


def test_lock_symlink_is_rejected(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    audit._load_or_create_key()
    source = tmp_path / "source.lock"
    source.write_bytes(b"")
    lock_path = audit.path.with_suffix(f"{audit.path.suffix}.lock")
    try:
        lock_path.symlink_to(source)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(TrustMutationAuditError):
        audit.record("success", context=_context(outcome="success"))

    assert not audit.path.exists()


def test_unexpected_runtime_failure_is_normalized(tmp_path: Path) -> None:
    audit = _audit(tmp_path, clock=lambda: float("inf"))

    with pytest.raises(TrustMutationAuditError) as caught:
        audit.record("success", context=_context(outcome="success"))

    assert caught.value.code == "MCP_TRUST_MUTATION_AUDIT_FAILED"


def test_records_are_canonical_hmac_chained_and_key_identified(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    first_id = audit.record("request_validated", context=_context(outcome="validated"))
    second_id = audit.record("success", context=_context(outcome="success"))

    lines = audit.path.read_bytes().splitlines(keepends=True)
    records = _records(audit.path)
    assert [record["eventId"] for record in records] == [first_id, second_id]
    assert records[0]["previousMac"] == "0" * 64
    assert records[1]["previousMac"] == records[0]["recordMac"]
    assert records[0]["auditKeyId"] == hashlib.sha256(KEY).hexdigest()[:16]
    assert records[0]["runtimeIdentity"] == {
        "transport": "stdio",
        "identityStatus": "unavailable",
        "clientId": None,
        "sessionId": None,
    }
    for line, record in zip(lines, records, strict=True):
        assert line == json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        UUID(str(record["eventId"]), version=4)


def test_record_rejects_private_values_and_oversize_before_append(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    private_values = [
        _context(target_hash="C:/private/repo"),
        _context(scope="git status --show-origin"),
        _context(error_code="secret\nfilesystem detail"),
    ]
    for context in private_values:
        with pytest.raises(TrustMutationAuditError):
            audit.record("failure", context=context)
    with pytest.raises(TrustMutationAuditError):
        audit.record("failure", context=_context(scope="x" * 5000))
    assert not audit.path.exists()


def test_rotation_reserves_first_retains_three_segments_and_chains_across_them(tmp_path: Path) -> None:
    audit = _audit(tmp_path, max_segment_bytes=1100, max_total_bytes=4400)
    for index in range(12):
        audit.record("request_validated", context=_context(operation_id=str(UUID(int=index + 1, version=4))))

    existing = [segment for segment in _segments(audit.path) if segment.exists()]
    assert len(existing) == 4
    assert all(segment.stat().st_size <= 1100 for segment in existing)
    assert sum(segment.stat().st_size for segment in existing) <= 4400
    records = _records(audit.path)
    assert all(records[index]["previousMac"] == records[index - 1]["recordMac"] for index in range(1, len(records)))
    assert audit.verify_and_recover(read_store_bytes=lambda: None).status == "clean"


def test_record_over_exact_4096_byte_limit_fails_without_rotation(tmp_path: Path) -> None:
    audit = _audit(tmp_path, max_record_bytes=700)
    with pytest.raises(TrustMutationAuditError):
        audit.record("failure", context=_context(scope="x" * 500))
    assert not audit.path.exists()


def test_chain_tampering_and_noncanonical_json_fail_closed(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    audit.record("success", context=_context(outcome="success"))
    original = audit.path.read_text(encoding="utf-8")
    record = json.loads(original)
    record["outcome"] = "failure"
    audit.path.write_text(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(TrustMutationAuditError) as tampered:
        audit.verify_and_recover(read_store_bytes=lambda: None)
    assert tampered.value.code == "MCP_TRUST_MUTATION_CORRUPT"

    audit.path.write_text(original.replace(":", ": ", 1), encoding="utf-8")
    with pytest.raises(TrustMutationAuditError) as noncanonical:
        audit.verify_and_recover(read_store_bytes=lambda: None)
    assert noncanonical.value.code == "MCP_TRUST_MUTATION_CORRUPT"


def test_unexpected_rotated_segment_fails_closed(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    audit.record("success", context=_context(outcome="success"))
    audit.path.with_name("audit.jsonl.4").write_bytes(audit.path.read_bytes())

    with pytest.raises(TrustMutationAuditError) as caught:
        audit.verify_and_recover(read_store_bytes=lambda: None)

    assert caught.value.code == "MCP_TRUST_MUTATION_CORRUPT"


def test_missing_key_is_not_recreated_beside_an_existing_chain(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    audit.record("success", context=_context(outcome="success"))
    audit.key_path.unlink()

    with pytest.raises(TrustMutationAuditError):
        audit.verify_and_recover(read_store_bytes=lambda: None)

    assert not audit.key_path.exists()


def test_prepare_fsyncs_before_store_write_and_commit_fsyncs_after(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    order: list[str] = []
    original = audit._append_record_unlocked

    def observed(record: dict[str, object], key: bytes) -> str:
        order.append(str(record["event"]))
        return original(record, key)

    audit._append_record_unlocked = observed  # type: ignore[method-assign]
    prepared = audit.prepare_mutation(
        operation="approve", before_bytes=None, after_bytes=AFTER, entry_id=ENTRY_ID, context=_context()
    )
    order.append("trust_store_replaced")
    committed_id = audit.commit_mutation(prepared, context=_context(outcome="success"))

    assert order == ["mutation_prepared", "trust_store_replaced", "mutation_committed"]
    assert prepared.event_id != committed_id
    assert prepared.before_state_digest != prepared.after_state_digest
    assert prepared.before_state_digest.startswith("hmac-sha256:")


def test_absent_store_digest_is_explicit_and_domain_separated(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    absent = audit.prepare_mutation(
        operation="approve", before_bytes=None, after_bytes=b"", entry_id=ENTRY_ID, context=_context()
    )
    empty = audit.prepare_mutation(
        operation="approve", before_bytes=b"", after_bytes=AFTER, entry_id=ENTRY_ID, context=_context()
    )
    assert absent.before_state_digest != absent.after_state_digest
    assert absent.before_state_digest != empty.before_state_digest


def test_recovery_commits_or_aborts_the_sole_unmatched_prepare(tmp_path: Path) -> None:
    committed_audit = _audit(tmp_path / "committed")
    committed = committed_audit.prepare_mutation(
        operation="approve", before_bytes=None, after_bytes=AFTER, entry_id=ENTRY_ID, context=_context()
    )
    result = committed_audit.verify_and_recover(read_store_bytes=lambda: AFTER)
    assert result.status == "recovery_committed"
    assert result.prepared_event_id == committed.event_id
    assert _records(committed_audit.path)[-1]["event"] == "recovery_committed"

    aborted_audit = _audit(tmp_path / "aborted")
    aborted = aborted_audit.prepare_mutation(
        operation="approve", before_bytes=None, after_bytes=AFTER, entry_id=ENTRY_ID, context=_context()
    )
    result = aborted_audit.verify_and_recover(read_store_bytes=lambda: None)
    assert result.status == "recovery_aborted"
    assert result.prepared_event_id == aborted.event_id
    assert _records(aborted_audit.path)[-1]["event"] == "recovery_aborted"


def test_committed_prepare_is_clean_and_recovery_is_idempotent(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    prepared = audit.prepare_mutation(
        operation="revoke",
        before_bytes=b"before",
        after_bytes=None,
        entry_id=ENTRY_ID,
        context=_context(tool="trust_revoke", operation="revoke"),
    )
    audit.commit_mutation(prepared, context=_context(tool="trust_revoke", operation="revoke", outcome="success"))
    before = audit.path.read_bytes()
    assert audit.verify_and_recover(read_store_bytes=lambda: None).status == "clean"
    assert audit.path.read_bytes() == before


def test_ambiguous_bytes_and_multiple_unmatched_prepares_require_recovery(tmp_path: Path) -> None:
    ambiguous = _audit(tmp_path / "ambiguous")
    ambiguous.prepare_mutation(
        operation="approve", before_bytes=b"before", after_bytes=AFTER, entry_id=ENTRY_ID, context=_context()
    )
    with pytest.raises(TrustMutationAuditError) as bytes_error:
        ambiguous.verify_and_recover(read_store_bytes=lambda: b"neither")
    assert bytes_error.value.code == "MCP_TRUST_MUTATION_RECOVERY_REQUIRED"

    multiple = _audit(tmp_path / "multiple")
    multiple.prepare_mutation(
        operation="approve", before_bytes=None, after_bytes=b"one", entry_id=ENTRY_ID, context=_context()
    )
    multiple.prepare_mutation(
        operation="approve", before_bytes=b"one", after_bytes=b"two", entry_id=ENTRY_ID, context=_context()
    )
    with pytest.raises(TrustMutationAuditError) as prepare_error:
        multiple.verify_and_recover(read_store_bytes=lambda: b"two")
    assert prepare_error.value.code == "MCP_TRUST_MUTATION_RECOVERY_REQUIRED"


@pytest.mark.parametrize(
    "boundary",
    ["key", "lock", "append", "flush_fsync", "reserve", "rotation", "retention"],
)
def test_persistence_boundary_failures_are_redacted_and_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    audit = _audit(tmp_path, max_segment_bytes=1100, max_total_bytes=4400)

    def hidden_failure(*_args: object, **_kwargs: object) -> object:
        raise OSError("C:/private/repo secret-key raw filesystem detail")

    if boundary == "key":
        monkeypatch.setattr(audit, "_load_or_create_key", hidden_failure)
    elif boundary == "lock":
        @contextmanager
        def broken_lock():
            hidden_failure()
            yield

        monkeypatch.setattr(audit, "_locked", broken_lock)
    elif boundary == "append":
        audit._load_or_create_key()
        monkeypatch.setattr(audit, "_write_bytes", hidden_failure)
    elif boundary == "flush_fsync":
        audit._load_or_create_key()
        monkeypatch.setattr(audit, "_flush_and_fsync", hidden_failure)
    else:
        audit.record("success", context=_context(outcome="success"))
        if boundary == "reserve":
            monkeypatch.setattr(audit, "_reserve_capacity", hidden_failure)
        elif boundary == "rotation":
            monkeypatch.setattr(audit, "_rotate_unlocked", hidden_failure)
        else:
            monkeypatch.setattr(audit, "_discard_oldest_unlocked", hidden_failure)

    with pytest.raises(TrustMutationAuditError) as caught:
        for index in range(5):
            audit.record(
                "failure",
                context=_context(operation_id=str(UUID(int=index + 100, version=4)), outcome="failure"),
            )
    assert caught.value.code == "MCP_TRUST_MUTATION_AUDIT_FAILED"
    assert "private" not in str(caught.value)
    assert "secret-key" not in str(caught.value)


def test_recovery_read_and_append_failures_close_without_private_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit = _audit(tmp_path)
    audit.prepare_mutation(
        operation="approve", before_bytes=None, after_bytes=AFTER, entry_id=ENTRY_ID, context=_context()
    )

    def fail_read() -> bytes | None:
        raise OSError("raw trust content and path")

    with pytest.raises(TrustMutationAuditError) as read_error:
        audit.verify_and_recover(read_store_bytes=fail_read)
    assert read_error.value.code == "MCP_TRUST_MUTATION_RECOVERY_REQUIRED"
    assert "raw trust" not in str(read_error.value)

    monkeypatch.setattr(audit, "_append_record_unlocked", lambda *_args: (_ for _ in ()).throw(OSError("secret")))
    with pytest.raises(TrustMutationAuditError) as append_error:
        audit.verify_and_recover(read_store_bytes=lambda: AFTER)
    assert append_error.value.code == "MCP_TRUST_MUTATION_RECOVERY_REQUIRED"


def test_public_record_vocabulary_is_closed(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    with pytest.raises(TrustMutationAuditError):
        audit.record("contains_raw_reason", context=_context())
    assert not audit.path.exists()


def test_exact_default_total_never_exceeds_four_mib(tmp_path: Path) -> None:
    assert AUDIT_MAX_TOTAL_BYTES == AUDIT_MAX_SEGMENT_BYTES * (AUDIT_MAX_ROTATED_SEGMENTS + 1)
