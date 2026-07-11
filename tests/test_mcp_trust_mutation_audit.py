from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from uuid import UUID

import pytest

import codex_preflight_mcp.trust_mutation_audit as audit_module
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
    assert audit._read_key() == KEY
    assert key_path.read_bytes() != KEY
    if os.name != "nt":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_directory_key_audit_lock_and_rotated_segments_are_owner_only_on_every_platform(tmp_path: Path) -> None:
    audit = _audit(tmp_path, max_segment_bytes=1100, max_total_bytes=4400)
    for index in range(5):
        audit.record(
            "request_validated",
            context=_context(
                operation_id=str(UUID(int=index + 1, version=4)),
                outcome="validated",
            ),
        )

    lock_path = audit.path.with_suffix(f"{audit.path.suffix}.lock")
    paths = [audit.path.parent, audit.key_path, audit.path, lock_path, audit.path.with_name("audit.jsonl.1")]
    assert all(path.exists() for path in paths)
    assert audit_module._paths_are_owner_only(paths)


def test_owner_only_enforcement_failure_is_fail_closed_before_audit_exposure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit = _audit(tmp_path)

    def cannot_prove(_handle: object, *, directory: bool) -> None:
        raise OSError("private ACL detail")

    monkeypatch.setattr(audit_module, "_enforce_and_verify_owner_only", cannot_prove)
    with pytest.raises(TrustMutationAuditError) as caught:
        audit.record("success", context=_context(outcome="success"))

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert not audit.path.exists()


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
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_public_errors_do_not_retain_private_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit = _audit(tmp_path)

    def private_failure(*_args: object, **_kwargs: object) -> object:
        raise OSError("C:/private/repo raw trust bytes")

    monkeypatch.setattr(audit, "_load_or_create_key", private_failure)
    with pytest.raises(TrustMutationAuditError) as audit_error:
        audit.record("success", context=_context(outcome="success"))
    assert audit_error.value.__cause__ is None
    assert audit_error.value.__context__ is None

    recovery = _audit(tmp_path / "recovery")
    recovery.prepare_mutation(
        operation="approve", before_bytes=None, after_bytes=AFTER, entry_id=ENTRY_ID, context=_context()
    )
    with pytest.raises(TrustMutationAuditError) as recovery_error:
        recovery.verify_and_recover(read_store_bytes=lambda: private_failure())  # type: ignore[arg-type]
    assert recovery_error.value.__cause__ is None
    assert recovery_error.value.__context__ is None


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
        audit.record(
            "request_validated",
            context=_context(operation_id=str(UUID(int=index + 1, version=4)), outcome="validated"),
        )

    existing = [segment for segment in _segments(audit.path) if segment.exists()]
    assert len(existing) == 4
    assert all(segment.stat().st_size <= 1100 for segment in existing)
    assert sum(segment.stat().st_size for segment in existing) <= 4400
    records = _records(audit.path)
    assert all(records[index]["previousMac"] == records[index - 1]["recordMac"] for index in range(1, len(records)))
    assert audit.verify_and_recover(read_store_bytes=lambda: None).status == "clean"


def test_reserve_is_held_until_rotated_append_is_fsynced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit = _audit(tmp_path, max_segment_bytes=1100, max_total_bytes=4400)
    audit.record("request_validated", context=_context(outcome="validated"))
    original = audit._flush_and_fsync
    observed_append = False

    def observe(handle: object) -> None:
        nonlocal observed_append
        if Path(str(getattr(handle, "name", ""))) == audit.path:
            observed_append = True
            assert (audit.path.parent / "audit.reserve").exists()
        original(handle)  # type: ignore[arg-type]

    monkeypatch.setattr(audit, "_flush_and_fsync", observe)
    audit.record(
        "request_validated",
        context=_context(operation_id="423e4567-e89b-42d3-a456-426614174000", outcome="validated"),
    )

    assert observed_append
    assert not (audit.path.parent / "audit.reserve").exists()


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


def test_authenticated_anchor_detects_active_prefix_truncation(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    for index in range(3):
        audit.record(
            "request_validated",
            context=_context(operation_id=str(UUID(int=index + 1, version=4)), outcome="validated"),
        )
    lines = audit.path.read_bytes().splitlines(keepends=True)
    audit.path.write_bytes(b"".join(lines[1:]))

    with pytest.raises(TrustMutationAuditError) as caught:
        audit.verify_and_recover(read_store_bytes=lambda: None)

    assert caught.value.code == "MCP_TRUST_MUTATION_CORRUPT"


def test_authenticated_anchor_detects_deleted_oldest_retained_segment(tmp_path: Path) -> None:
    audit = _audit(tmp_path, max_segment_bytes=1100, max_total_bytes=4400)
    for index in range(8):
        audit.record(
            "request_validated",
            context=_context(operation_id=str(UUID(int=index + 1, version=4)), outcome="validated"),
        )
    oldest = audit.path.with_name("audit.jsonl.3")
    assert oldest.exists()
    oldest.unlink()

    with pytest.raises(TrustMutationAuditError) as caught:
        audit.verify_and_recover(read_store_bytes=lambda: None)

    assert caught.value.code == "MCP_TRUST_MUTATION_CORRUPT"


@pytest.mark.parametrize("failure_point", ["before-retention", "after-append"])
def test_pending_anchor_reconciles_crash_safe_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    audit = _audit(tmp_path, max_segment_bytes=1100, max_total_bytes=4400)
    for index in range(4):
        audit.record(
            "request_validated",
            context=_context(operation_id=str(UUID(int=index + 1, version=4)), outcome="validated"),
        )
    original_write_state = audit._write_key_state
    original_rotate = audit._rotate_unlocked

    if failure_point == "before-retention":
        monkeypatch.setattr(audit, "_rotate_unlocked", lambda: (_ for _ in ()).throw(OSError("private")))
    else:
        def fail_final_anchor(state: object) -> None:
            if getattr(state, "pending", None) is None:
                raise OSError("private")
            original_write_state(state)  # type: ignore[arg-type]

        monkeypatch.setattr(audit, "_write_key_state", fail_final_anchor)

    with pytest.raises(TrustMutationAuditError):
        audit.record(
            "request_validated",
            context=_context(operation_id="723e4567-e89b-42d3-a456-426614174000", outcome="validated"),
        )

    monkeypatch.setattr(audit, "_write_key_state", original_write_state)
    monkeypatch.setattr(audit, "_rotate_unlocked", original_rotate)
    restarted = _audit(tmp_path, max_segment_bytes=1100, max_total_bytes=4400)
    assert restarted.verify_and_recover(read_store_bytes=lambda: None).status == "clean"
    assert restarted._read_key_state().pending is None


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


def test_prepare_rejects_identical_before_and_after_state(tmp_path: Path) -> None:
    audit = _audit(tmp_path)

    with pytest.raises(TrustMutationAuditError) as caught:
        audit.prepare_mutation(
            operation="approve",
            before_bytes=AFTER,
            after_bytes=AFTER,
            entry_id=ENTRY_ID,
            context=_context(),
        )

    assert caught.value.code == "MCP_TRUST_MUTATION_AUDIT_FAILED"
    assert not audit.path.exists()


def test_recovery_refuses_equal_before_and_after_digests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit = _audit(tmp_path)
    digest = f"hmac-sha256:{'b' * 64}"
    key = audit._load_or_create_key()
    record = audit._build_record(
        "mutation_prepared",
        context=_context(outcome="prepared"),
        before_state_digest=digest,
        after_state_digest=digest,
    )
    with audit._locked():
        audit._append_record_unlocked(record, key)
    monkeypatch.setattr(audit, "_state_digest", lambda _value, _key: digest)

    with pytest.raises(TrustMutationAuditError) as caught:
        audit.verify_and_recover(read_store_bytes=lambda: AFTER)

    assert caught.value.code == "MCP_TRUST_MUTATION_RECOVERY_REQUIRED"


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


@pytest.mark.parametrize("forgery", ["entry", "challenge", "digest", "operation"])
def test_commit_binds_to_complete_actual_unmatched_prepare(tmp_path: Path, forgery: str) -> None:
    audit = _audit(tmp_path)
    prepared = audit.prepare_mutation(
        operation="approve", before_bytes=None, after_bytes=AFTER, entry_id=ENTRY_ID, context=_context()
    )
    context = _context(outcome="committed")
    forged = prepared
    if forgery == "entry":
        forged = replace(prepared, entry_id="523e4567-e89b-42d3-a456-426614174000")
        context = _context(entry_id=forged.entry_id, outcome="committed")
    elif forgery == "challenge":
        context = _context(challenge_id="623e4567-e89b-42d3-a456-426614174000", outcome="committed")
    elif forgery == "digest":
        forged = replace(prepared, after_state_digest=f"hmac-sha256:{'c' * 64}")
    else:
        forged = replace(prepared, operation="revoke")
        context = _context(tool="trust_revoke", operation="revoke", outcome="committed")

    with pytest.raises(TrustMutationAuditError):
        audit.commit_mutation(forged, context=context)

    assert _records(audit.path)[-1]["event"] == "mutation_prepared"


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


@pytest.mark.parametrize(
    ("event", "changes"),
    [
        ("success", {"tool": "trust_import", "outcome": "success"}),
        ("success", {"tool": "trust_approve", "operation": "extend", "outcome": "success"}),
        ("success", {"scope": "anything", "outcome": "success"}),
        ("success", {"outcome": "syntactically-valid"}),
        ("failure", {"outcome": "failure", "error_code": "MCP_TRUST_MUTATION_MADE_UP"}),
        ("request_validated", {"outcome": "success"}),
    ],
)
def test_semantic_audit_fields_use_exact_allowlists(tmp_path: Path, event: str, changes: dict[str, object]) -> None:
    audit = _audit(tmp_path)

    with pytest.raises(TrustMutationAuditError):
        audit.record(event, context=_context(**changes))

    assert not audit.path.exists()


def test_ancestor_symlink_is_rejected_without_creating_state(tmp_path: Path) -> None:
    real_home = tmp_path / "real-home"
    real_home.mkdir()
    alias_home = tmp_path / "alias-home"
    alias_home.symlink_to(real_home, target_is_directory=True)
    audit = _audit(alias_home)

    with pytest.raises(TrustMutationAuditError):
        audit.record("success", context=_context(outcome="success"))

    assert not (real_home / "trust-mutation").exists()


def test_exact_default_total_never_exceeds_four_mib(tmp_path: Path) -> None:
    assert AUDIT_MAX_TOTAL_BYTES == AUDIT_MAX_SEGMENT_BYTES * (AUDIT_MAX_ROTATED_SEGMENTS + 1)
