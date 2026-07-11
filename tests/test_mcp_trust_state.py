from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_preflight_core.cache.paths import (
    remote_audit_path,
    scan_cache_path,
    trust_cache_path,
    trust_read_audit_path,
)
from codex_preflight_mcp.trust_state import (
    TrustCursorManager,
    TrustReadAuditLog,
    TrustReadStateError,
)


class Clock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


RUNTIME_IDENTITY = {
    "transport": "stdio",
    "identityStatus": "unavailable",
    "clientId": None,
    "sessionId": None,
}


def test_trust_read_audit_path_is_dedicated(tmp_path: Path) -> None:
    path = trust_read_audit_path(tmp_path)

    assert path == tmp_path / "trust-read" / "audit.jsonl"
    assert path not in {trust_cache_path(tmp_path), scan_cache_path(tmp_path), remote_audit_path(tmp_path)}


def test_cursor_is_bound_reusable_expiring_and_restart_invalid() -> None:
    clock = Clock()
    manager = TrustCursorManager(secret=b"c" * 32, clock=clock, nonce_factory=lambda: "nonce")
    token = manager.issue(
        repo_id_hash="hmac-sha256:repo",
        command_scope="test",
        limit=2,
        snapshot_digest="hmac-sha256:snapshot",
        offset=2,
    )

    for _ in range(2):
        assert manager.consume(
            token,
            repo_id_hash="hmac-sha256:repo",
            command_scope="test",
            limit=2,
            snapshot_digest="hmac-sha256:snapshot",
        ) == 2
    assert len(token.encode("utf-8")) <= 512

    with pytest.raises(TrustReadStateError) as mismatch:
        manager.consume(
            token,
            repo_id_hash="hmac-sha256:other",
            command_scope="test",
            limit=2,
            snapshot_digest="hmac-sha256:snapshot",
        )
    assert mismatch.value.code == "MCP_TRUST_LIST_CURSOR_INVALID"

    clock.value += 301
    with pytest.raises(TrustReadStateError):
        manager.consume(
            token,
            repo_id_hash="hmac-sha256:repo",
            command_scope="test",
            limit=2,
            snapshot_digest="hmac-sha256:snapshot",
        )

    restarted = TrustCursorManager(secret=b"d" * 32, clock=Clock())
    with pytest.raises(TrustReadStateError):
        restarted.consume(
            token,
            repo_id_hash="hmac-sha256:repo",
            command_scope="test",
            limit=2,
            snapshot_digest="hmac-sha256:snapshot",
        )


def test_cursor_rejects_oversized_and_snapshot_changed_values() -> None:
    manager = TrustCursorManager(secret=b"c" * 32, clock=Clock())
    token = manager.issue(
        repo_id_hash=None,
        command_scope=None,
        limit=50,
        snapshot_digest="hmac-sha256:first",
        offset=50,
    )

    for value, snapshot in (("x" * 513, "hmac-sha256:first"), (token, "hmac-sha256:changed")):
        with pytest.raises(TrustReadStateError) as caught:
            manager.consume(
                value,
                repo_id_hash=None,
                command_scope=None,
                limit=50,
                snapshot_digest=snapshot,
            )
        assert caught.value.code == "MCP_TRUST_LIST_CURSOR_INVALID"


def test_audit_records_are_redacted_bounded_and_rotated(tmp_path: Path) -> None:
    path = trust_read_audit_path(tmp_path)
    clock = Clock()
    audit = TrustReadAuditLog(
        path,
        privacy_key=b"p" * 32,
        clock=clock,
        event_id_factory=lambda: "event-id",
        max_record_bytes=4096,
        max_segment_bytes=700,
        max_rotated_segments=3,
    )

    event_id = audit.record(
        "request_validated",
        repo_id="C:/Users/private/project",
        command_scope="test",
        result_count=0,
        cursor_status="absent",
        migration_status="not-needed",
        outcome="validated",
        error_code=None,
        runtime_identity=RUNTIME_IDENTITY,
    )
    assert event_id == "event-id"
    first = path.read_text(encoding="utf-8")
    assert "C:/Users/private/project" not in first
    assert "hmac-sha256:" in first

    for index in range(20):
        audit.record(
            "page_returned",
            repo_id=f"private-{index}",
            command_scope="test",
            result_count=1,
            cursor_status="issued",
            migration_status="not-needed",
            outcome="success",
            error_code=None,
            runtime_identity=RUNTIME_IDENTITY,
        )

    segments = [
        path,
        *[
            path.with_name(f"{path.name}.{index}")
            for index in range(1, 4)
            if path.with_name(f"{path.name}.{index}").exists()
        ],
    ]
    assert path.exists()
    assert len(segments) <= 4
    assert sum(item.stat().st_size for item in segments) <= 4 * 700
    for segment in segments:
        for line in segment.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            assert set(record) == {
                "commandScope",
                "cursorStatus",
                "errorCode",
                "event",
                "eventId",
                "migrationStatus",
                "operation",
                "outcome",
                "repoIdHash",
                "resultCount",
                "runtimeIdentity",
                "schemaVersion",
                "timestamp",
                "tool",
            }


def test_audit_rejects_unknown_or_oversized_records(tmp_path: Path) -> None:
    audit = TrustReadAuditLog(
        trust_read_audit_path(tmp_path),
        privacy_key=b"p" * 32,
        max_record_bytes=200,
    )

    with pytest.raises(TrustReadStateError) as unknown:
        audit.record(
            "not-an-event",
            outcome="failed",
            runtime_identity=RUNTIME_IDENTITY,
        )
    assert unknown.value.code == "MCP_TRUST_LIST_AUDIT_FAILED"

    with pytest.raises(TrustReadStateError) as oversized:
        audit.record(
            "failure",
            command_scope="x" * 500,
            outcome="failed",
            runtime_identity=RUNTIME_IDENTITY,
        )
    assert oversized.value.code == "MCP_TRUST_LIST_AUDIT_FAILED"
