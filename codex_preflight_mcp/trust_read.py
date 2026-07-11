from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from typing import Any, Protocol

from codex_preflight_core.cache.file_lock import CacheLockTimeoutError
from codex_preflight_core.cache.paths import trust_cache_path, trust_read_audit_path
from codex_preflight_core.cache.trust_cache import TrustCache, TrustCacheError
from codex_preflight_mcp.trust_state import (
    TrustCursorManager,
    TrustReadAuditLog,
    TrustReadStateError,
    privacy_hash,
)

TRUST_LIST_SCHEMA_VERSION = "trust-list/v1"
RUNTIME_IDENTITY = {
    "transport": "stdio",
    "identityStatus": "unavailable",
    "clientId": None,
    "sessionId": None,
}
TRUST_LIST_SAFETY = {
    "repositoryContentTrust": "untrusted",
    "evidenceTreatAsData": True,
    "trustReadOnly": True,
    "trustMutationAllowed": False,
    "preflightUsesTrust": False,
    "remoteConfirmationUsesTrust": False,
    "rawRepoIdReturned": False,
    "rawPathReturned": False,
    "rawRemoteUrlReturned": False,
    "approvedCommandReturned": False,
}

_PROCESS_PRIVACY_KEY = secrets.token_bytes(32)
_PROCESS_CURSOR_MANAGER = TrustCursorManager()
_COMMAND_SCOPES = {
    "dependency_install",
    "script_execution",
    "build",
    "test",
    "docker",
    "network_shell",
    "mcp_server_start",
    "unknown_shell",
}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class AuditWriter(Protocol):
    def record(self, event: str, **values: object) -> str: ...


class TrustReadError(RuntimeError):
    def __init__(self, code: str, message: str, *, field: str | None = None) -> None:
        self.code = code
        self.message = message
        self.field = field
        super().__init__(message)


class TrustReadService:
    def __init__(
        self,
        *,
        cache: TrustCache,
        audit: AuditWriter,
        privacy_key: bytes,
        cursor_manager: TrustCursorManager,
    ) -> None:
        self.cache = cache
        self.audit = audit
        self.privacy_key = privacy_key
        self.cursor_manager = cursor_manager

    def record_registration_state(self) -> str:
        return self._audit_or_raise(
            "registration_state",
            repo_id=None,
            command_scope=None,
            result_count=0,
            cursor_status="unavailable",
            migration_status="not-started",
            outcome="enabled",
            error_code=None,
        )

    def list(
        self,
        *,
        repo_id: object = None,
        command_scope: object = None,
        limit: object = 50,
        cursor: object = None,
    ) -> dict[str, Any]:
        try:
            validated_repo_id = _validate_repo_id(repo_id)
            validated_scope = _validate_command_scope(command_scope)
            validated_limit = _validate_limit(limit)
            validated_cursor = _validate_cursor(cursor)
        except TrustReadError as error:
            self._audit_or_raise(
                "request_validation_failed",
                repo_id=repo_id if isinstance(repo_id, str) else None,
                command_scope=(
                    command_scope
                    if isinstance(command_scope, str) and command_scope in _COMMAND_SCOPES
                    else None
                ),
                result_count=0,
                cursor_status="rejected" if cursor is not None else "absent",
                migration_status="not-started",
                outcome="failed",
                error_code=error.code,
            )
            raise

        repo_id_hash = privacy_hash(validated_repo_id, self.privacy_key) if validated_repo_id else None
        cursor_status = "provided" if validated_cursor is not None else "absent"
        migration_status = "not-needed"
        self._audit_or_raise(
            "request_validated",
            repo_id=validated_repo_id,
            command_scope=validated_scope,
            result_count=0,
            cursor_status=cursor_status,
            migration_status=migration_status,
            outcome="validated",
            error_code=None,
        )

        def cache_event(event: str) -> None:
            nonlocal migration_status
            if event == "migration_started":
                migration_status = "started"
            elif event == "migration_completed":
                migration_status = "completed"
            elif event == "migration_failed":
                migration_status = "failed"
            self._audit_or_raise(
                event,
                repo_id=validated_repo_id,
                command_scope=validated_scope,
                result_count=0,
                cursor_status=cursor_status,
                migration_status=migration_status,
                outcome=_cache_event_outcome(event),
                error_code=None,
            )

        try:
            entries = self.cache.list(event_hook=cache_event)
        except CacheLockTimeoutError as error:
            raise self._storage_error(
                "lock_timeout",
                "MCP_TRUST_LIST_LOCK_TIMEOUT",
                "The local trust-store lock timed out.",
                validated_repo_id,
                validated_scope,
                cursor_status,
                migration_status,
                error,
            ) from error
        except TrustCacheError as error:
            event, code, message = _map_cache_error(error)
            raise self._storage_error(
                event,
                code,
                message,
                validated_repo_id,
                validated_scope,
                cursor_status,
                migration_status,
                error,
            ) from error
        except TrustReadStateError as error:
            raise _audit_read_error() from error
        except OSError as error:
            raise self._storage_error(
                "trust_file_read_failed",
                "MCP_TRUST_LIST_UNAVAILABLE",
                "The local trust store is unavailable.",
                validated_repo_id,
                validated_scope,
                cursor_status,
                migration_status,
                error,
            ) from error

        filtered = [
            entry
            for entry in entries
            if (validated_repo_id is None or entry["repoId"] == validated_repo_id)
            and (validated_scope is None or entry["commandScope"] == validated_scope)
        ]
        public_entries = [_public_entry(entry, self.privacy_key) for entry in filtered]
        public_entries.sort(key=_entry_sort_key)
        snapshot_digest = _snapshot_digest(public_entries, self.privacy_key)
        self._audit_or_raise(
            "filter_applied",
            repo_id=validated_repo_id,
            command_scope=validated_scope,
            result_count=len(public_entries),
            cursor_status=cursor_status,
            migration_status=migration_status,
            outcome="filtered",
            error_code=None,
        )

        offset = 0
        if validated_cursor is not None:
            try:
                offset = self.cursor_manager.consume(
                    validated_cursor,
                    repo_id_hash=repo_id_hash,
                    command_scope=validated_scope,
                    limit=validated_limit,
                    snapshot_digest=snapshot_digest,
                )
                if offset > len(public_entries):
                    raise TrustReadStateError(
                        "MCP_TRUST_LIST_CURSOR_INVALID",
                        "The trust-list cursor offset is outside the current snapshot.",
                    )
            except TrustReadStateError as error:
                self._audit_or_raise(
                    "cursor_rejected",
                    repo_id=validated_repo_id,
                    command_scope=validated_scope,
                    result_count=0,
                    cursor_status="rejected",
                    migration_status=migration_status,
                    outcome="failed",
                    error_code="MCP_TRUST_LIST_CURSOR_INVALID",
                )
                raise TrustReadError(
                    "MCP_TRUST_LIST_CURSOR_INVALID",
                    "The trust-list cursor is invalid, expired, restart-invalid, or stale.",
                    field="cursor",
                ) from error

        page = public_entries[offset : offset + validated_limit]
        next_offset = offset + len(page)
        next_cursor: str | None = None
        if next_offset < len(public_entries):
            try:
                next_cursor = self.cursor_manager.issue(
                    repo_id_hash=repo_id_hash,
                    command_scope=validated_scope,
                    limit=validated_limit,
                    snapshot_digest=snapshot_digest,
                    offset=next_offset,
                )
            except TrustReadStateError as error:
                raise TrustReadError(error.code, error.message, field="cursor") from error
            self._audit_or_raise(
                "cursor_issued",
                repo_id=validated_repo_id,
                command_scope=validated_scope,
                result_count=len(page),
                cursor_status="issued",
                migration_status=migration_status,
                outcome="issued",
                error_code=None,
            )
        page_cursor_status = "issued" if next_cursor else "complete"
        self._audit_or_raise(
            "page_returned",
            repo_id=validated_repo_id,
            command_scope=validated_scope,
            result_count=len(page),
            cursor_status=page_cursor_status,
            migration_status=migration_status,
            outcome="success",
            error_code=None,
        )
        audit_event_id = self._audit_or_raise(
            "success",
            repo_id=validated_repo_id,
            command_scope=validated_scope,
            result_count=len(page),
            cursor_status=page_cursor_status,
            migration_status=migration_status,
            outcome="success",
            error_code=None,
        )
        return {
            "mcpSchemaVersion": "1.0",
            "tool": "trust_list",
            "schemaVersion": TRUST_LIST_SCHEMA_VERSION,
            "sourceType": "trust-cache",
            "trustReadOnly": True,
            "trustMutationAllowed": False,
            "entries": page,
            "pagination": {
                "resultCount": len(page),
                "limit": validated_limit,
                "nextCursor": next_cursor,
                "complete": next_cursor is None,
                "snapshotDigest": snapshot_digest,
            },
            "runtimeIdentity": dict(RUNTIME_IDENTITY),
            "auditEventId": audit_event_id,
            "safety": dict(TRUST_LIST_SAFETY),
        }

    def _storage_error(
        self,
        event: str,
        code: str,
        message: str,
        repo_id: str | None,
        command_scope: str | None,
        cursor_status: str,
        migration_status: str,
        error: BaseException,
    ) -> TrustReadError:
        try:
            self._audit_or_raise(
                event,
                repo_id=repo_id,
                command_scope=command_scope,
                result_count=0,
                cursor_status=cursor_status,
                migration_status=migration_status,
                outcome="failed",
                error_code=code,
            )
            self._audit_or_raise(
                "failure",
                repo_id=repo_id,
                command_scope=command_scope,
                result_count=0,
                cursor_status=cursor_status,
                migration_status=migration_status,
                outcome="failed",
                error_code=code,
            )
        except TrustReadError as audit_error:
            return audit_error
        return TrustReadError(code, message)

    def _audit_or_raise(self, event: str, **values: object) -> str:
        try:
            return self.audit.record(event, runtime_identity=RUNTIME_IDENTITY, **values)
        except TrustReadStateError as error:
            raise _audit_read_error() from error
        except Exception as error:
            raise _audit_read_error() from error


def default_trust_read_service() -> TrustReadService:
    return TrustReadService(
        cache=TrustCache(trust_cache_path()),
        audit=TrustReadAuditLog(
            trust_read_audit_path(),
            privacy_key=_PROCESS_PRIVACY_KEY,
        ),
        privacy_key=_PROCESS_PRIVACY_KEY,
        cursor_manager=_PROCESS_CURSOR_MANAGER,
    )


def _public_entry(entry: dict[str, Any], privacy_key: bytes) -> dict[str, Any]:
    provenance = entry["provenance"]
    migrated = provenance["source"] == "legacy-migration"
    remote_url = entry["remoteUrl"]
    return {
        "entryId": entry["entryId"],
        "entryVersion": entry["entryVersion"],
        "repoIdHash": privacy_hash(entry["repoId"], privacy_key),
        "repoIdRedacted": True,
        "hasRemoteUrl": remote_url is not None,
        "remoteUrlHash": privacy_hash(remote_url, privacy_key) if isinstance(remote_url, str) else None,
        "headCommit": entry["headCommit"],
        "criticalFingerprint": entry["criticalFingerprint"],
        "commandScope": entry["commandScope"],
        "decision": entry["decision"],
        "approvedAt": entry["approvedAt"],
        "expiresAt": entry["expiresAt"],
        "approvedBy": entry["approvedBy"],
        "policyVersion": entry["policyVersion"],
        "rulesetVersion": entry["rulesetVersion"],
        "provenance": {
            "schema": provenance["schema"],
            "source": provenance["source"],
            "migrationVersion": provenance["migrationVersion"],
            "migrated": migrated,
            "migratedAt": provenance.get("migratedAt"),
            "createdAt": provenance.get("createdAt"),
        },
    }


def _entry_sort_key(entry: dict[str, Any]) -> tuple[object, ...]:
    return (
        entry["expiresAt"],
        entry["repoIdHash"],
        entry["commandScope"],
        entry["policyVersion"],
        entry["rulesetVersion"],
        entry["criticalFingerprint"],
        entry["entryId"],
    )


def _snapshot_digest(entries: list[dict[str, Any]], privacy_key: bytes) -> str:
    encoded = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"hmac-sha256:{hmac.new(privacy_key, encoded, hashlib.sha256).hexdigest()}"


def _validate_repo_id(value: object) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or _CONTROL.search(value)
    ):
        raise TrustReadError(
            "MCP_TRUST_LIST_INVALID_ARGUMENT",
            "repoId must be a bounded exact repository identity without control characters.",
            field="repoId",
        )
    return value


def _validate_command_scope(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in _COMMAND_SCOPES:
        raise TrustReadError(
            "MCP_TRUST_LIST_INVALID_ARGUMENT",
            "commandScope must be one of the supported exact command scopes.",
            field="commandScope",
        )
    return value


def _validate_limit(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 100:
        raise TrustReadError(
            "MCP_TRUST_LIST_LIMIT_EXCEEDED",
            "limit must be an integer from 1 through 100.",
            field="limit",
        )
    return value


def _validate_cursor(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512 or _CONTROL.search(value):
        raise TrustReadError(
            "MCP_TRUST_LIST_CURSOR_INVALID",
            "cursor must be a bounded opaque token returned by trust_list.",
            field="cursor",
        )
    return value


def _map_cache_error(error: TrustCacheError) -> tuple[str, str, str]:
    if error.code == "corrupt":
        return "trust_file_corrupt", "MCP_TRUST_LIST_CORRUPT", "The local trust store is corrupt."
    if error.code == "unsupported-schema":
        return (
            "trust_file_unsupported_schema",
            "MCP_TRUST_LIST_UNSUPPORTED_SCHEMA",
            "The local trust-store schema is unsupported.",
        )
    if error.code == "migration-failed":
        return (
            "migration_failed",
            "MCP_TRUST_LIST_MIGRATION_FAILED",
            "The metadata-only trust-store migration failed closed.",
        )
    return "trust_file_read_failed", "MCP_TRUST_LIST_UNAVAILABLE", "The local trust store is unavailable."


def _cache_event_outcome(event: str) -> str:
    return {
        "migration_started": "started",
        "migration_completed": "completed",
        "migration_failed": "failed",
        "trust_file_missing": "missing",
        "trust_file_empty": "empty",
    }[event]


def _audit_read_error() -> TrustReadError:
    return TrustReadError(
        "MCP_TRUST_LIST_AUDIT_FAILED",
        "The dedicated trust-read audit log failed closed.",
    )
