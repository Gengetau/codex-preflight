from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from codex_preflight_core.cache.paths import trust_read_audit_path
from codex_preflight_core.cache.trust_cache import TrustCache
from codex_preflight_mcp.trust_read import TrustReadError, TrustReadService
from codex_preflight_mcp.trust_state import TrustCursorManager, TrustReadAuditLog, TrustReadStateError

HEAD = "a" * 40


class Clock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def build_service(tmp_path: Path, *, limit_entries: int = 3) -> tuple[TrustReadService, TrustCache]:
    clock = Clock()
    cache = TrustCache(tmp_path / "trust.json")
    for index in range(limit_entries):
        cache.approve(
            repo_id=f"C:/private/repo-{index}",
            path=Path(f"C:/private/repo-{index}"),
            remote_url=f"https://github.com/example/repo-{index}",
            head_commit=HEAD,
            critical_fingerprint=f"sha256:{index:064x}",
            command_scope="test" if index % 2 == 0 else "build",
            approved_command=f"python private-{index}.py",
            expires_at=datetime.now(UTC) + timedelta(days=index + 1),
        )
    audit = TrustReadAuditLog(
        trust_read_audit_path(tmp_path),
        privacy_key=b"p" * 32,
        clock=clock,
        event_id_factory=lambda: "audit-event",
    )
    return (
        TrustReadService(
            cache=cache,
            audit=audit,
            privacy_key=b"p" * 32,
            cursor_manager=TrustCursorManager(secret=b"c" * 32, clock=clock, nonce_factory=lambda: "nonce"),
        ),
        cache,
    )


def test_trust_list_response_is_exact_redacted_and_paginated(tmp_path: Path) -> None:
    service, _cache = build_service(tmp_path)

    first = service.list(limit=1)

    assert set(first) == {
        "auditEventId",
        "entries",
        "mcpSchemaVersion",
        "pagination",
        "runtimeIdentity",
        "safety",
        "schemaVersion",
        "sourceType",
        "tool",
        "trustMutationAllowed",
        "trustReadOnly",
    }
    assert first["mcpSchemaVersion"] == "1.0"
    assert first["tool"] == "trust_list"
    assert first["schemaVersion"] == "trust-list/v1"
    assert first["sourceType"] == "trust-cache"
    assert first["trustReadOnly"] is True
    assert first["trustMutationAllowed"] is False
    assert first["auditEventId"] == "audit-event"
    assert first["runtimeIdentity"] == {
        "transport": "stdio",
        "identityStatus": "unavailable",
        "clientId": None,
        "sessionId": None,
    }
    assert first["pagination"]["resultCount"] == 1
    assert first["pagination"]["limit"] == 1
    assert first["pagination"]["complete"] is False
    assert first["pagination"]["nextCursor"]
    assert first["pagination"]["snapshotDigest"].startswith("hmac-sha256:")

    entry = first["entries"][0]
    assert set(entry) == {
        "approvedAt",
        "approvedBy",
        "commandScope",
        "criticalFingerprint",
        "decision",
        "entryId",
        "entryVersion",
        "expiresAt",
        "hasRemoteUrl",
        "headCommit",
        "policyVersion",
        "provenance",
        "remoteUrlHash",
        "repoIdHash",
        "repoIdRedacted",
        "rulesetVersion",
    }
    serialized = json.dumps(first, sort_keys=True)
    assert "C:/private" not in serialized
    assert "https://github.com" not in serialized
    assert "python private" not in serialized
    assert entry["repoIdRedacted"] is True
    assert entry["repoIdHash"].startswith("hmac-sha256:")
    assert entry["remoteUrlHash"].startswith("hmac-sha256:")
    assert entry["provenance"]["migrated"] is False

    second = service.list(limit=1, cursor=first["pagination"]["nextCursor"])
    assert second["entries"][0]["entryId"] != entry["entryId"]


def test_trust_list_exact_filters_do_not_open_or_return_repo_identity(tmp_path: Path) -> None:
    service, _cache = build_service(tmp_path)

    result = service.list(repo_id="C:/private/repo-2", command_scope="test")

    assert result["pagination"]["resultCount"] == 1
    assert result["entries"][0]["criticalFingerprint"] == f"sha256:{2:064x}"
    assert "C:/private/repo-2" not in json.dumps(result)


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"repo_id": ""}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"repo_id": "a" * 4097}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"repo_id": "repo\nvalue"}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"repo_id": 7}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"command_scope": "anything"}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"command_scope": []}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"limit": 0}, "MCP_TRUST_LIST_LIMIT_EXCEEDED"),
        ({"limit": 101}, "MCP_TRUST_LIST_LIMIT_EXCEEDED"),
        ({"limit": True}, "MCP_TRUST_LIST_LIMIT_EXCEEDED"),
        ({"limit": "1"}, "MCP_TRUST_LIST_LIMIT_EXCEEDED"),
        ({"cursor": "x" * 513}, "MCP_TRUST_LIST_CURSOR_INVALID"),
        ({"cursor": 1}, "MCP_TRUST_LIST_CURSOR_INVALID"),
    ],
)
def test_trust_list_rejects_invalid_arguments_before_read(
    tmp_path: Path,
    kwargs: dict[str, object],
    code: str,
) -> None:
    service, cache = build_service(tmp_path, limit_entries=0)
    cache.path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(TrustReadError) as caught:
        service.list(**kwargs)

    assert caught.value.code == code


def test_cursor_fails_after_trust_snapshot_changes(tmp_path: Path) -> None:
    service, cache = build_service(tmp_path, limit_entries=2)
    first = service.list(limit=1)
    cache.approve(
        repo_id="C:/private/new",
        path=Path("C:/private/new"),
        remote_url=None,
        head_commit=HEAD,
        critical_fingerprint=f"sha256:{99:064x}",
        command_scope="test",
        approved_command="python -m pytest",
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )

    with pytest.raises(TrustReadError) as caught:
        service.list(limit=1, cursor=first["pagination"]["nextCursor"])
    assert caught.value.code == "MCP_TRUST_LIST_CURSOR_INVALID"


def test_missing_store_returns_empty_but_audit_failure_fails_closed(tmp_path: Path) -> None:
    service, cache = build_service(tmp_path, limit_entries=0)

    result = service.list()
    assert result["entries"] == []
    assert result["pagination"]["complete"] is True
    assert not cache.path.exists()

    class FailingAudit:
        def record(self, *_args: object, **_kwargs: object) -> str:
            raise TrustReadStateError("MCP_TRUST_LIST_AUDIT_FAILED", "hidden audit detail")

    service.audit = FailingAudit()
    with pytest.raises(TrustReadError) as caught:
        service.list()
    assert caught.value.code == "MCP_TRUST_LIST_AUDIT_FAILED"
    assert "hidden" not in caught.value.message
