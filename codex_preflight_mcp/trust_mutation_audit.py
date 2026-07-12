from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO
from uuid import UUID, uuid4

from codex_preflight_core.cache.file_lock import locked_cache_file
from codex_preflight_core.command.scope import CommandScope

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

AUDIT_MAX_RECORD_BYTES = 4096
AUDIT_MAX_SEGMENT_BYTES = 1024 * 1024
AUDIT_MAX_ROTATED_SEGMENTS = 3
AUDIT_MAX_TOTAL_BYTES = 4 * 1024 * 1024
AUDIT_KEY_BYTES = 32

_AUDIT_VERSION = "trust-mutation-audit/v1"
_KEY_VERSION = "trust-mutation-audit-key/v1"
_RESERVATION_BYTES = b'{"version":"trust-mutation-reservation/v1"}\n'
_AUDIT_MAC_DOMAIN = b"codex-preflight/trust-mutation/audit-record/v1\x00"
_STATE_MAC_DOMAIN = b"codex-preflight/trust-mutation/trust-state/v1\x00"
_ANCHOR_MAC_DOMAIN = b"codex-preflight/trust-mutation/chain-anchor/v1\x00"
_SEGMENT_MAC_DOMAIN = b"codex-preflight/trust-mutation/segment/v1\x00"
_ZERO_MAC = "0" * 64
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_HASH_VALUE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_MAC_VALUE = re.compile(r"^[0-9a-f]{64}$")
_EVENTS = {
    "registration_state",
    "request_validation_failed",
    "request_validated",
    "challenge_issued",
    "challenge_rejected",
    "challenge_consumed",
    "identity_resolved",
    "target_not_visible",
    "mutation_prepared",
    "mutation_committed",
    "mutation_noop",
    "mutation_failed",
    "mutation_cancelled",
    "mutation_timed_out",
    "lock_timeout",
    "recovery_committed",
    "recovery_aborted",
    "recovery_failed",
    "success",
    "failure",
}
_TOOLS = {"trust_approve", "trust_revoke"}
_OPERATIONS = {"approve", "revoke"}
_TOOL_OPERATIONS = {"trust_approve": "approve", "trust_revoke": "revoke"}
_SCOPES = {scope.value for scope in CommandScope}
_EVENT_OUTCOMES = {
    "registration_state": {"enabled", "disabled", "failure"},
    "request_validation_failed": {"failure"},
    "request_validated": {"validated"},
    "challenge_issued": {"issued"},
    "challenge_rejected": {"rejected"},
    "challenge_consumed": {"consumed"},
    "identity_resolved": {"resolved"},
    "target_not_visible": {"not-visible"},
    "mutation_prepared": {"pending", "prepared"},
    "mutation_committed": {"success", "committed"},
    "mutation_noop": {"already-approved", "not-found", "noop"},
    "mutation_failed": {"failure"},
    "mutation_cancelled": {"cancelled"},
    "mutation_timed_out": {"timed-out"},
    "lock_timeout": {"failure"},
    "recovery_committed": {"recovery_committed"},
    "recovery_aborted": {"recovery_aborted"},
    "recovery_failed": {"failure"},
    "success": {"success"},
    "failure": {"failure"},
}
_STABLE_ERROR_CODES = {
    "MCP_TRUST_MUTATION_DISABLED",
    "MCP_TRUST_MUTATION_INVALID_ARGUMENT",
    "MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED",
    "MCP_TRUST_MUTATION_CONFIRMATION_INVALID",
    "MCP_TRUST_MUTATION_RATE_LIMITED",
    "MCP_TRUST_MUTATION_IDENTITY_UNRESOLVED",
    "MCP_TRUST_MUTATION_LIMIT_EXCEEDED",
    "MCP_TRUST_MUTATION_TIMEOUT",
    "MCP_TRUST_MUTATION_CANCELLED",
    "MCP_TRUST_MUTATION_TARGET_DRIFT",
    "MCP_TRUST_MUTATION_VERSION_CONFLICT",
    "MCP_TRUST_MUTATION_NOT_FOUND",
    "MCP_TRUST_MUTATION_UNSAFE_STORAGE",
    "MCP_TRUST_MUTATION_CORRUPT",
    "MCP_TRUST_MUTATION_UNSUPPORTED_SCHEMA",
    "MCP_TRUST_MUTATION_LOCK_TIMEOUT",
    "MCP_TRUST_MUTATION_AUDIT_FAILED",
    "MCP_TRUST_MUTATION_PERSISTENCE_FAILED",
    "MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING",
    "MCP_TRUST_MUTATION_RECOVERY_REQUIRED",
    "MCP_TRUST_MUTATION_INTERNAL_ERROR",
}
_COMPLETION_EVENTS = {"mutation_committed", "recovery_committed", "recovery_aborted"}
_RUNTIME_IDENTITY = {
    "transport": "stdio",
    "identityStatus": "unavailable",
    "clientId": None,
    "sessionId": None,
}
_RECORD_FIELDS = {
    "auditKeyId",
    "auditVersion",
    "afterStateDigest",
    "beforeStateDigest",
    "challengeId",
    "entryId",
    "entryVersion",
    "errorCode",
    "event",
    "eventId",
    "operation",
    "operationId",
    "outcome",
    "policyVersion",
    "preparedAuditEventId",
    "previousMac",
    "recordMac",
    "rulesetVersion",
    "runtimeIdentity",
    "scope",
    "targetHash",
    "timestamp",
    "tool",
}


class TrustMutationAuditError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class TrustMutationAuditCommitCleanupError(TrustMutationAuditError):
    pass


class _IntegrityError(RuntimeError):
    pass


class _RecoveryRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditContext:
    tool: str
    operation_id: str
    operation: str
    target_hash: str | None
    entry_id: str | None
    scope: str | None
    policy_version: str | None
    ruleset_version: str | None
    challenge_id: str | None
    outcome: str
    error_code: str | None = None
    entry_version: int | None = None


@dataclass(frozen=True)
class PreparedMutation:
    event_id: str
    operation: str
    entry_id: str
    before_state_digest: str
    after_state_digest: str
    record_mac: str


@dataclass
class _MutationReservation:
    owner: object
    active: bool = True
    prepare_attempted: bool = False
    prepared_event_id: str | None = None
    completed: bool = False


@dataclass(frozen=True)
class _AnchorSnapshot:
    segments: tuple[tuple[str, int, str], ...]
    terminal_mac: str


@dataclass(frozen=True)
class _KeyState:
    key: bytes
    committed: _AnchorSnapshot
    pending: _AnchorSnapshot | None


@dataclass(frozen=True)
class RecoveryResult:
    status: str
    event_id: str | None = None
    prepared_event_id: str | None = None


class TrustMutationAuditLog:
    def __init__(
        self,
        path: Path,
        *,
        key_path: Path,
        clock: Callable[[], float] = time.time,
        event_id_factory: Callable[[], str] | None = None,
        key_factory: Callable[[int], bytes] = secrets.token_bytes,
        max_record_bytes: int = AUDIT_MAX_RECORD_BYTES,
        max_segment_bytes: int = AUDIT_MAX_SEGMENT_BYTES,
        max_rotated_segments: int = AUDIT_MAX_ROTATED_SEGMENTS,
        max_total_bytes: int = AUDIT_MAX_TOTAL_BYTES,
    ) -> None:
        self.path = path
        self.key_path = key_path
        self.clock = clock
        self.event_id_factory = event_id_factory or (lambda: str(uuid4()))
        self.key_factory = key_factory
        self.max_record_bytes = max_record_bytes
        self.max_segment_bytes = max_segment_bytes
        self.max_rotated_segments = max_rotated_segments
        self.max_total_bytes = max_total_bytes

    @property
    def reservation_path(self) -> Path:
        return self.path.with_name("mutation.reserve")

    def record(self, event: str, *, context: AuditContext) -> str:
        result: str | None = None
        failure: TrustMutationAuditError | None = None
        try:
            with self._reservation_locked():
                self._require_no_reservation_marker()
                key = self._load_or_create_key()
                record = self._build_record(event, context=context)
                with self._locked():
                    result, _record_mac = self._append_record_unlocked(record, key)
        except _RecoveryRequired:
            failure = _recovery_required()
        except Exception:
            failure = _audit_failed()
        if failure is not None:
            raise failure
        if result is None:
            raise _audit_failed()
        return result

    def prepare_mutation(
        self,
        *,
        operation: str,
        before_bytes: bytes | None,
        after_bytes: bytes | None,
        entry_id: str,
        context: AuditContext,
        reservation: object | None = None,
    ) -> PreparedMutation:
        result: PreparedMutation | None = None
        failure: TrustMutationAuditError | None = None
        try:
            if reservation is None:
                with self._reservation_locked():
                    self._require_no_reservation_marker()
                    result = self._prepare_mutation(
                        operation=operation,
                        before_bytes=before_bytes,
                        after_bytes=after_bytes,
                        entry_id=entry_id,
                        context=context,
                        reservation=None,
                    )
            else:
                active = self._require_active_reservation(reservation)
                result = self._prepare_mutation(
                    operation=operation,
                    before_bytes=before_bytes,
                    after_bytes=after_bytes,
                    entry_id=entry_id,
                    context=context,
                    reservation=active,
                )
        except _RecoveryRequired:
            failure = _recovery_required()
        except Exception:
            failure = _audit_failed()
        if failure is not None:
            raise failure
        if result is None:
            raise _audit_failed()
        return result

    def commit_mutation(
        self,
        prepared: PreparedMutation,
        *,
        context: AuditContext,
        reservation: object | None = None,
    ) -> str:
        result: str | None = None
        failure: TrustMutationAuditError | None = None
        try:
            if reservation is None:
                with self._reservation_locked():
                    self._require_no_reservation_marker()
                    result = self._commit_mutation(prepared, context=context, reservation=None)
            else:
                active = self._require_active_reservation(reservation)
                result = self._commit_mutation(prepared, context=context, reservation=active)
        except _RecoveryRequired:
            failure = _recovery_required()
        except Exception:
            failure = _audit_failed()
        if failure is not None:
            raise failure
        if result is None:
            raise _audit_failed()
        return result

    def verify_and_recover(self, *, read_store_bytes: Callable[[], bytes | None]) -> RecoveryResult:
        result: RecoveryResult | None = None
        failure: TrustMutationAuditError | None = None
        try:
            with self._reservation_locked():
                key = self._load_or_create_key()
                with self._locked():
                    records, _last_mac = self._verify_chain_unlocked(key)
                unmatched = self._unmatched_prepares(records)
                if not unmatched:
                    result = RecoveryResult("clean")
                else:
                    if len(unmatched) != 1 or records[-1]["eventId"] != unmatched[0]["eventId"]:
                        raise _RecoveryRequired
                    prepared = unmatched[0]
                    before_digest = str(prepared["beforeStateDigest"])
                    after_digest = str(prepared["afterStateDigest"])
                    if hmac.compare_digest(before_digest, after_digest):
                        raise _RecoveryRequired
                    try:
                        current_digest = self._state_digest(read_store_bytes(), key)
                    except Exception:
                        raise _RecoveryRequired from None
                    if hmac.compare_digest(current_digest, after_digest):
                        event = "recovery_committed"
                        status = "recovery_committed"
                    elif hmac.compare_digest(current_digest, before_digest):
                        event = "recovery_aborted"
                        status = "recovery_aborted"
                    else:
                        raise _RecoveryRequired
                    context = self._context_from_record(prepared, outcome=status)
                    recovery = self._build_record(
                        event,
                        context=context,
                        before_state_digest=before_digest,
                        after_state_digest=after_digest,
                        prepared_event_id=str(prepared["eventId"]),
                    )
                    try:
                        with self._locked():
                            current_records, _last_mac = self._verify_chain_unlocked(key)
                            actual = self._require_unmatched_tail(current_records, str(prepared["eventId"]))
                            if actual != prepared:
                                raise _RecoveryRequired
                            event_id, _record_mac = self._append_record_unlocked(recovery, key)
                    except Exception:
                        raise _RecoveryRequired from None
                    result = RecoveryResult(status, event_id, str(prepared["eventId"]))
                self._clear_reservation_marker()
        except _IntegrityError:
            failure = _corrupt()
        except _RecoveryRequired:
            failure = _recovery_required()
        except Exception:
            failure = _audit_failed()
        if failure is not None:
            raise failure
        if result is None:
            raise _recovery_required()
        return result

    @contextmanager
    def mutation_transaction(self) -> Iterator[object]:
        lock = self._reservation_locked()
        entered = False
        try:
            lock.__enter__()
            entered = True
            self._require_no_reservation_marker()
            reservation = _MutationReservation(self)
            self._create_reservation_marker()
        except _RecoveryRequired:
            if entered:
                try:
                    lock.__exit__(None, None, None)
                except Exception:
                    pass
            raise _recovery_required() from None
        except Exception:
            if entered:
                try:
                    lock.__exit__(None, None, None)
                except Exception:
                    pass
            raise _audit_failed() from None

        try:
            yield reservation
        except BaseException:
            try:
                self._finish_reservation(reservation)
            except Exception:
                pass
            finally:
                reservation.active = False
                try:
                    lock.__exit__(None, None, None)
                except Exception:
                    pass
            raise
        else:
            cleanup_failed = False
            try:
                self._finish_reservation(reservation)
            except Exception:
                cleanup_failed = True
            reservation.active = False
            try:
                lock.__exit__(None, None, None)
            except Exception:
                cleanup_failed = True
            if cleanup_failed:
                if reservation.completed:
                    raise _commit_cleanup_failed() from None
                raise _audit_failed() from None

    def _prepare_mutation(
        self,
        *,
        operation: str,
        before_bytes: bytes | None,
        after_bytes: bytes | None,
        entry_id: str,
        context: AuditContext,
        reservation: _MutationReservation | None,
    ) -> PreparedMutation:
        _required_operation(operation)
        _required_uuid(entry_id)
        if operation != context.operation or entry_id != context.entry_id:
            raise ValueError("mutation binding mismatch")
        if reservation is not None:
            reservation.prepare_attempted = True
        key = self._load_or_create_key()
        before_digest = self._state_digest(before_bytes, key)
        after_digest = self._state_digest(after_bytes, key)
        if hmac.compare_digest(before_digest, after_digest):
            raise ValueError("mutation state is unchanged")
        record = self._build_record(
            "mutation_prepared",
            context=context,
            before_state_digest=before_digest,
            after_state_digest=after_digest,
        )
        with self._locked():
            event_id, record_mac = self._append_record_unlocked(record, key)
        if reservation is not None:
            reservation.prepared_event_id = event_id
        return PreparedMutation(event_id, operation, entry_id, before_digest, after_digest, record_mac)

    def _commit_mutation(
        self,
        prepared: PreparedMutation,
        *,
        context: AuditContext,
        reservation: _MutationReservation | None,
    ) -> str:
        self._validate_prepared(prepared, context)
        if reservation is not None and reservation.prepared_event_id != prepared.event_id:
            raise ValueError("prepared mutation does not belong to reservation")
        key = self._load_or_create_key()
        record = self._build_record(
            "mutation_committed",
            context=context,
            before_state_digest=prepared.before_state_digest,
            after_state_digest=prepared.after_state_digest,
            prepared_event_id=prepared.event_id,
        )
        with self._locked():
            records, _last_mac = self._verify_chain_unlocked(key)
            actual = self._require_unmatched_tail(records, prepared.event_id)
            self._require_complete_prepare_binding(actual, prepared, context)
            result, _record_mac = self._append_record_unlocked(record, key)
        if reservation is not None:
            reservation.completed = True
        return result

    def _require_active_reservation(self, reservation: object) -> _MutationReservation:
        if (
            not isinstance(reservation, _MutationReservation)
            or reservation.owner is not self
            or not reservation.active
            or not _lexists(self.reservation_path)
        ):
            raise ValueError("invalid mutation reservation")
        return reservation

    def _create_reservation_marker(self) -> None:
        with _secure_open_file(self.reservation_path, "exclusive") as handle:
            self._write_bytes(handle, _RESERVATION_BYTES)
            self._flush_and_fsync(handle)
        self._fsync_directory()

    def _clear_reservation_marker(self) -> None:
        if _lexists(self.reservation_path):
            _secure_unlink(self.reservation_path)
            self._fsync_directory()

    def _finish_reservation(self, reservation: _MutationReservation) -> None:
        if not reservation.prepare_attempted or reservation.completed:
            self._clear_reservation_marker()

    def _require_no_reservation_marker(self) -> None:
        if _lexists(self.reservation_path):
            raise _RecoveryRequired

    @contextmanager
    def _reservation_locked(self) -> Iterator[None]:
        self._ensure_directory()
        with locked_cache_file(
            self.reservation_path,
            lock_opener=lambda lock_path: _secure_open_file(lock_path, "append"),
        ):
            yield

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._ensure_directory()
        with locked_cache_file(
            self.path,
            lock_opener=lambda lock_path: _secure_open_file(lock_path, "append"),
        ):
            yield

    def _load_or_create_key(self) -> bytes:
        self._ensure_directory()
        if _lexists(self.key_path):
            return self._read_key_state().key
        if self._audit_artifacts_exist():
            raise ValueError("audit key missing for existing chain")
        key = self.key_factory(AUDIT_KEY_BYTES)
        if type(key) is not bytes or len(key) < AUDIT_KEY_BYTES:
            raise ValueError("invalid audit key")
        state = _KeyState(key, _AnchorSnapshot((), _ZERO_MAC), None)
        encoded = _encode_key_state(state)
        created = False
        try:
            with _secure_open_file(self.key_path, "exclusive") as handle:
                created = True
                self._write_bytes(handle, encoded)
                self._flush_and_fsync(handle)
        except FileExistsError:
            return self._read_key_state().key
        except Exception:
            if created:
                _secure_unlink(self.key_path, missing_ok=True)
            raise
        self._fsync_directory()
        return self._read_key_state().key

    def _read_key(self) -> bytes:
        return self._read_key_state().key

    def _read_key_state(self) -> _KeyState:
        with _secure_open_file(self.key_path, "read") as handle:
            encoded = handle.read()
        return _decode_key_state(encoded)

    def _write_key_state(self, state: _KeyState) -> None:
        temp_path = self.key_path.with_name(f"{self.key_path.name}.tmp")
        if _lexists(temp_path):
            _secure_unlink(temp_path)
        try:
            with _secure_open_file(temp_path, "exclusive") as handle:
                self._write_bytes(handle, _encode_key_state(state))
                self._flush_and_fsync(handle)
            _secure_replace(temp_path, self.key_path)
            self._fsync_directory()
        finally:
            if _lexists(temp_path):
                _secure_unlink(temp_path, missing_ok=True)

    def _ensure_directory(self) -> None:
        parent = self.path.parent
        if (
            parent != self.key_path.parent
            or self.path.name != "audit.jsonl"
            or self.key_path.name != "audit.key"
        ):
            raise ValueError("audit paths must share a directory")
        _ensure_owner_only_directory(parent)

    def _validate_regular_private_file(self, path: Path, *, exact_size: int | None) -> None:
        with _secure_open_file(path, "read") as handle:
            info = os.fstat(handle.fileno())
            if exact_size is not None and info.st_size != exact_size:
                raise ValueError("unsafe audit file")

    def _build_record(
        self,
        event: str,
        *,
        context: AuditContext,
        before_state_digest: str | None = None,
        after_state_digest: str | None = None,
        prepared_event_id: str | None = None,
    ) -> dict[str, object]:
        if event not in _EVENTS or not isinstance(context, AuditContext):
            raise ValueError("invalid audit event")
        _required_tool(context.tool)
        _required_uuid(context.operation_id)
        _required_operation(context.operation)
        if _TOOL_OPERATIONS[context.tool] != context.operation:
            raise ValueError("tool and operation mismatch")
        _optional_hash(context.target_hash)
        _optional_uuid(context.entry_id)
        _optional_scope(context.scope)
        _optional_safe(context.policy_version)
        _optional_safe(context.ruleset_version)
        _optional_uuid(context.challenge_id)
        _required_outcome(event, context.outcome)
        _optional_error_code(context.error_code)
        if context.entry_version is not None and (
            not isinstance(context.entry_version, int)
            or isinstance(context.entry_version, bool)
            or context.entry_version != 1
        ):
            raise ValueError("invalid entry version")
        _optional_hash(before_state_digest)
        _optional_hash(after_state_digest)
        _optional_uuid(prepared_event_id)
        event_id = self.event_id_factory()
        _required_uuid(event_id)
        timestamp = datetime.fromtimestamp(float(self.clock()), UTC).isoformat().replace("+00:00", "Z")
        return {
            "auditVersion": _AUDIT_VERSION,
            "eventId": event_id,
            "timestamp": timestamp,
            "event": event,
            "tool": context.tool,
            "operationId": context.operation_id,
            "operation": context.operation,
            "runtimeIdentity": dict(_RUNTIME_IDENTITY),
            "targetHash": context.target_hash,
            "entryId": context.entry_id,
            "scope": context.scope,
            "policyVersion": context.policy_version,
            "rulesetVersion": context.ruleset_version,
            "challengeId": context.challenge_id,
            "outcome": context.outcome,
            "errorCode": context.error_code,
            "entryVersion": context.entry_version,
            "beforeStateDigest": before_state_digest,
            "afterStateDigest": after_state_digest,
            "preparedAuditEventId": prepared_event_id,
        }

    def _append_record_unlocked(self, record: dict[str, object], key: bytes) -> tuple[str, str]:
        _records, previous_mac = self._verify_chain_unlocked(key)
        signed = dict(record)
        signed["auditKeyId"] = self._key_id(key)
        signed["previousMac"] = previous_mac
        signed["recordMac"] = self._record_mac(signed, key)
        line = _canonical_line(signed)
        if len(line) > self.max_record_bytes or len(line) > self.max_segment_bytes:
            raise ValueError("audit record exceeds limit")
        self._ensure_directory()
        current = self._read_segment_data()
        rotating = len(current.get(self.path.name, b"")) + len(line) > self.max_segment_bytes
        projected = self._project_segment_data(current, line, rotating=rotating)
        if sum(len(value) for value in projected.values()) > self.max_total_bytes:
            raise ValueError("audit total exceeds limit")
        expected = self._anchor_snapshot(projected, str(signed["recordMac"]), key)
        state = self._read_key_state()
        if state.key != key or state.pending is not None:
            raise _IntegrityError("audit anchor is not settled")
        reservation: Path | None = None
        if rotating:
            reservation = self._reserve_capacity(len(line))
        try:
            self._write_key_state(_KeyState(key, state.committed, expected))
            if rotating:
                self._rotate_unlocked()
            with _secure_open_file(self.path, "append") as handle:
                self._write_bytes(handle, line)
                self._flush_and_fsync(handle)
            self._fsync_directory()
            self._write_key_state(_KeyState(key, expected, None))
        finally:
            if reservation is not None:
                _secure_unlink(reservation, missing_ok=True)
        return str(signed["eventId"]), str(signed["recordMac"])

    def _verify_chain_unlocked(self, key: bytes) -> tuple[list[dict[str, Any]], str]:
        self._validate_limits()
        segment_data = self._read_segment_data()
        if sum(len(value) for value in segment_data.values()) > self.max_total_bytes:
            raise _IntegrityError("audit total exceeds limit")
        records: list[dict[str, Any]] = []
        previous_mac: str | None = None
        for segment in self._segment_paths():
            data = segment_data.get(segment.name)
            if data is None:
                continue
            if len(data) > self.max_segment_bytes or (data and not data.endswith(b"\n")):
                raise _IntegrityError("invalid audit segment")
            for line in data.splitlines(keepends=True):
                if len(line) > self.max_record_bytes:
                    raise _IntegrityError("audit record exceeds limit")
                try:
                    record = json.loads(line.decode("utf-8", "strict"))
                except (UnicodeError, json.JSONDecodeError) as error:
                    raise _IntegrityError("invalid audit record") from error
                if not isinstance(record, dict) or set(record) != _RECORD_FIELDS or _canonical_line(record) != line:
                    raise _IntegrityError("noncanonical audit record")
                try:
                    self._validate_stored_record(record, key)
                except _IntegrityError:
                    raise
                except (KeyError, TypeError, ValueError) as error:
                    raise _IntegrityError("invalid audit record") from error
                if previous_mac is not None and record["previousMac"] != previous_mac:
                    raise _IntegrityError("broken audit chain")
                expected_mac = self._record_mac(record, key)
                if not hmac.compare_digest(str(record["recordMac"]), expected_mac):
                    raise _IntegrityError("invalid audit mac")
                previous_mac = str(record["recordMac"])
                records.append(record)
        terminal_mac = previous_mac or _ZERO_MAC
        observed = self._anchor_snapshot(segment_data, terminal_mac, key)
        state = self._read_key_state()
        if state.key != key:
            raise _IntegrityError("audit key changed")
        if state.pending is None:
            if not _anchor_matches(observed, state.committed):
                raise _IntegrityError("audit anchor mismatch")
        elif _anchor_matches(observed, state.pending):
            self._write_key_state(_KeyState(key, state.pending, None))
        elif _anchor_matches(observed, state.committed):
            self._write_key_state(_KeyState(key, state.committed, None))
        else:
            raise _IntegrityError("audit anchor transition is ambiguous")
        return records, terminal_mac

    def _read_segment_data(self) -> dict[str, bytes]:
        values: dict[str, bytes] = {}
        for path in self._existing_segments():
            with _secure_open_file(path, "read") as handle:
                values[path.name] = handle.read()
        return values

    def _project_segment_data(
        self,
        current: Mapping[str, bytes],
        line: bytes,
        *,
        rotating: bool,
    ) -> dict[str, bytes]:
        if not rotating:
            projected = dict(current)
            projected[self.path.name] = projected.get(self.path.name, b"") + line
            return projected
        projected: dict[str, bytes] = {self.path.name: line}
        if self.max_rotated_segments == 0:
            return projected
        active = current.get(self.path.name)
        if active is not None:
            projected[f"{self.path.name}.1"] = active
        for index in range(2, self.max_rotated_segments + 1):
            source = current.get(f"{self.path.name}.{index - 1}")
            if source is not None:
                projected[f"{self.path.name}.{index}"] = source
        return projected

    def _anchor_snapshot(
        self,
        segment_data: Mapping[str, bytes],
        terminal_mac: str,
        key: bytes,
    ) -> _AnchorSnapshot:
        segments: list[tuple[str, int, str]] = []
        for path in self._segment_paths():
            data = segment_data.get(path.name)
            if data is None:
                continue
            digest = hmac.new(
                key,
                _SEGMENT_MAC_DOMAIN + path.name.encode("ascii") + b"\x00" + data,
                hashlib.sha256,
            ).hexdigest()
            segments.append((path.name, len(data), digest))
        return _AnchorSnapshot(tuple(segments), terminal_mac)

    def _segment_paths(self) -> list[Path]:
        return [
            self.path.with_name(f"{self.path.name}.{index}")
            for index in range(self.max_rotated_segments, 0, -1)
        ] + [self.path]

    def _validate_stored_record(self, record: Mapping[str, object], key: bytes) -> None:
        if record.get("auditVersion") != _AUDIT_VERSION or record.get("auditKeyId") != self._key_id(key):
            raise _IntegrityError("invalid audit identity")
        if record.get("event") not in _EVENTS or record.get("runtimeIdentity") != _RUNTIME_IDENTITY:
            raise _IntegrityError("invalid audit record")
        event = str(record["event"])
        tool = _required_tool(record.get("tool"))
        operation = _required_operation(record.get("operation"))
        if _TOOL_OPERATIONS[tool] != operation:
            raise _IntegrityError("invalid audit operation")
        _optional_scope(record.get("scope"))
        _required_outcome(event, record.get("outcome"))
        _optional_error_code(record.get("errorCode"))
        _required_uuid(record.get("eventId"))
        _required_uuid(record.get("operationId"))
        _optional_uuid(record.get("entryId"))
        _optional_uuid(record.get("challengeId"))
        _optional_uuid(record.get("preparedAuditEventId"))
        _optional_hash(record.get("targetHash"))
        _optional_hash(record.get("beforeStateDigest"))
        _optional_hash(record.get("afterStateDigest"))
        entry_version = record.get("entryVersion")
        if entry_version is not None and (
            not isinstance(entry_version, int)
            or isinstance(entry_version, bool)
            or entry_version != 1
        ):
            raise _IntegrityError("invalid entry version")
        if not isinstance(record.get("previousMac"), str) or not _MAC_VALUE.fullmatch(str(record["previousMac"])):
            raise _IntegrityError("invalid previous mac")
        if not isinstance(record.get("recordMac"), str) or not _MAC_VALUE.fullmatch(str(record["recordMac"])):
            raise _IntegrityError("invalid record mac")

    def _record_mac(self, record: Mapping[str, object], key: bytes) -> str:
        unsigned = dict(record)
        unsigned.pop("recordMac", None)
        payload = json.dumps(unsigned, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hmac.new(key, _AUDIT_MAC_DOMAIN + payload, hashlib.sha256).hexdigest()

    def _state_digest(self, value: bytes | None, key: bytes) -> str:
        if value is None:
            payload = b"absent\x00"
        elif type(value) is bytes:
            payload = b"present\x00" + value
        else:
            raise TypeError("trust state must be bytes or absent")
        return f"hmac-sha256:{hmac.new(key, _STATE_MAC_DOMAIN + payload, hashlib.sha256).hexdigest()}"

    def _reserve_capacity(self, size: int) -> Path:
        reservation = self.path.parent / "audit.reserve"
        try:
            with _secure_open_file(reservation, "exclusive") as handle:
                self._write_bytes(handle, b"\x00" * size)
                self._flush_and_fsync(handle)
            return reservation
        except Exception:
            _secure_unlink(reservation, missing_ok=True)
            raise

    def _rotate_unlocked(self) -> None:
        if self.max_rotated_segments == 0:
            self._discard_oldest_unlocked()
            return
        oldest = self.path.with_name(f"{self.path.name}.{self.max_rotated_segments}")
        if _lexists(oldest):
            self._discard_oldest_unlocked()
        for index in range(self.max_rotated_segments - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            if _lexists(source):
                _secure_replace(source, self.path.with_name(f"{self.path.name}.{index + 1}"))
        if _lexists(self.path):
            _secure_replace(self.path, self.path.with_name(f"{self.path.name}.1"))
        self._fsync_directory()

    def _discard_oldest_unlocked(self) -> None:
        if self.max_rotated_segments == 0:
            target = self.path
        else:
            target = self.path.with_name(f"{self.path.name}.{self.max_rotated_segments}")
        _secure_unlink(target, missing_ok=True)

    def _existing_segments(self) -> list[Path]:
        candidates = self._segment_paths()
        if _lexists(self.path.parent):
            valid_names = {path.name for path in candidates}
            valid_names.add(f"{self.path.name}.lock")
            for sibling in self.path.parent.iterdir():
                if not sibling.name.startswith(f"{self.path.name}."):
                    continue
                if sibling.name not in valid_names:
                    raise _IntegrityError("unexpected audit segment")
        return [path for path in candidates if _lexists(path)]

    def _audit_artifacts_exist(self) -> bool:
        if _lexists(self.path):
            return True
        if not _lexists(self.path.parent):
            return False
        return any(
            sibling.name.startswith(f"{self.path.name}.")
            and sibling.name != f"{self.path.name}.lock"
            for sibling in self.path.parent.iterdir()
        )

    def _validate_limits(self) -> None:
        if (
            not 0 < self.max_record_bytes <= AUDIT_MAX_RECORD_BYTES
            or not 0 < self.max_segment_bytes <= AUDIT_MAX_SEGMENT_BYTES
            or not 0 <= self.max_rotated_segments <= AUDIT_MAX_ROTATED_SEGMENTS
            or not 0 < self.max_total_bytes <= AUDIT_MAX_TOTAL_BYTES
        ):
            raise ValueError("invalid audit limits")

    def _write_bytes(self, handle: BinaryIO, value: bytes) -> None:
        written = handle.write(value)
        if written != len(value):
            raise OSError("short audit write")

    def _flush_and_fsync(self, handle: BinaryIO) -> None:
        handle.flush()
        os.fsync(handle.fileno())

    def _fsync_directory(self) -> None:
        if os.name == "nt":
            return
        with _secure_open_directory(self.path.parent) as descriptor:
            os.fsync(descriptor)

    def _key_id(self, key: bytes) -> str:
        return hashlib.sha256(key).hexdigest()[:16]

    def _validate_prepared(self, prepared: PreparedMutation, context: AuditContext) -> None:
        if not isinstance(prepared, PreparedMutation):
            raise TypeError("invalid prepared mutation")
        _required_uuid(prepared.event_id)
        _required_uuid(prepared.entry_id)
        _required_operation(prepared.operation)
        _required_hash(prepared.before_state_digest)
        _required_hash(prepared.after_state_digest)
        if not isinstance(prepared.record_mac, str) or not _MAC_VALUE.fullmatch(prepared.record_mac):
            raise ValueError("invalid prepared record mac")
        if hmac.compare_digest(prepared.before_state_digest, prepared.after_state_digest):
            raise ValueError("ambiguous prepared state")
        if prepared.operation != context.operation or prepared.entry_id != context.entry_id:
            raise ValueError("mutation binding mismatch")

    def _require_unmatched_tail(self, records: list[dict[str, Any]], event_id: str) -> dict[str, Any]:
        unmatched = self._unmatched_prepares(records)
        if len(unmatched) != 1 or unmatched[0]["eventId"] != event_id or records[-1]["eventId"] != event_id:
            raise _IntegrityError("prepared mutation is not the unmatched tail")
        return unmatched[0]

    def _require_complete_prepare_binding(
        self,
        actual: Mapping[str, object],
        prepared: PreparedMutation,
        context: AuditContext,
    ) -> None:
        expected_context = {
            "tool": context.tool,
            "operationId": context.operation_id,
            "operation": context.operation,
            "targetHash": context.target_hash,
            "entryId": context.entry_id,
            "scope": context.scope,
            "policyVersion": context.policy_version,
            "rulesetVersion": context.ruleset_version,
            "challengeId": context.challenge_id,
            "entryVersion": context.entry_version,
            "errorCode": context.error_code,
        }
        expected_prepared = {
            "eventId": prepared.event_id,
            "recordMac": prepared.record_mac,
            "operation": prepared.operation,
            "entryId": prepared.entry_id,
            "beforeStateDigest": prepared.before_state_digest,
            "afterStateDigest": prepared.after_state_digest,
        }
        if any(actual.get(name) != value for name, value in expected_context.items()):
            raise _IntegrityError("prepared context binding mismatch")
        if any(actual.get(name) != value for name, value in expected_prepared.items()):
            raise _IntegrityError("prepared record binding mismatch")

    def _unmatched_prepares(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        completed = {
            record["preparedAuditEventId"]
            for record in records
            if record["event"] in _COMPLETION_EVENTS and record["preparedAuditEventId"] is not None
        }
        return [
            record
            for record in records
            if record["event"] == "mutation_prepared" and record["eventId"] not in completed
        ]

    def _context_from_record(self, record: Mapping[str, object], *, outcome: str) -> AuditContext:
        return AuditContext(
            tool=str(record["tool"]),
            operation_id=str(record["operationId"]),
            operation=str(record["operation"]),
            target_hash=_as_optional_str(record["targetHash"]),
            entry_id=_as_optional_str(record["entryId"]),
            scope=_as_optional_str(record["scope"]),
            policy_version=_as_optional_str(record["policyVersion"]),
            ruleset_version=_as_optional_str(record["rulesetVersion"]),
            challenge_id=_as_optional_str(record["challengeId"]),
            outcome=outcome,
            error_code=None,
            entry_version=record["entryVersion"] if isinstance(record["entryVersion"], int) else None,
        )


def _canonical_line(record: Mapping[str, object]) -> bytes:
    return (
        json.dumps(dict(record), ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    )


def _anchor_matches(left: _AnchorSnapshot, right: _AnchorSnapshot) -> bool:
    if len(left.segments) != len(right.segments):
        return False
    if not hmac.compare_digest(left.terminal_mac, right.terminal_mac):
        return False
    return all(
        left_name == right_name
        and left_size == right_size
        and hmac.compare_digest(left_digest, right_digest)
        for (left_name, left_size, left_digest), (right_name, right_size, right_digest) in zip(
            left.segments, right.segments, strict=True
        )
    )


def _snapshot_payload(snapshot: _AnchorSnapshot) -> dict[str, object]:
    return {
        "segments": [
            {"name": name, "size": size, "digest": digest}
            for name, size, digest in snapshot.segments
        ],
        "terminalMac": snapshot.terminal_mac,
    }


def _parse_snapshot(value: object) -> _AnchorSnapshot:
    if not isinstance(value, dict) or set(value) != {"segments", "terminalMac"}:
        raise ValueError("invalid audit anchor")
    terminal_mac = value["terminalMac"]
    segments = value["segments"]
    if not isinstance(terminal_mac, str) or not _MAC_VALUE.fullmatch(terminal_mac):
        raise ValueError("invalid audit anchor")
    if not isinstance(segments, list) or len(segments) > AUDIT_MAX_ROTATED_SEGMENTS + 1:
        raise ValueError("invalid audit anchor")
    parsed: list[tuple[str, int, str]] = []
    valid_names = {"audit.jsonl", "audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.3"}
    for segment in segments:
        if not isinstance(segment, dict) or set(segment) != {"name", "size", "digest"}:
            raise ValueError("invalid audit anchor")
        name = segment["name"]
        size = segment["size"]
        digest = segment["digest"]
        if (
            not isinstance(name, str)
            or name not in valid_names
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= AUDIT_MAX_SEGMENT_BYTES
            or not isinstance(digest, str)
            or not _MAC_VALUE.fullmatch(digest)
        ):
            raise ValueError("invalid audit anchor")
        parsed.append((name, size, digest))
    if len({name for name, _size, _digest in parsed}) != len(parsed):
        raise ValueError("invalid audit anchor")
    return _AnchorSnapshot(tuple(parsed), terminal_mac)


def _encode_key_state(state: _KeyState) -> bytes:
    key_value = base64.urlsafe_b64encode(state.key).rstrip(b"=").decode("ascii")
    payload: dict[str, object] = {
        "version": _KEY_VERSION,
        "key": key_value,
        "keyId": hashlib.sha256(state.key).hexdigest()[:16],
        "committed": _snapshot_payload(state.committed),
        "pending": _snapshot_payload(state.pending) if state.pending is not None else None,
    }
    canonical = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload["anchorMac"] = hmac.new(state.key, _ANCHOR_MAC_DOMAIN + canonical, hashlib.sha256).hexdigest()
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _decode_key_state(encoded: bytes) -> _KeyState:
    if len(encoded) > AUDIT_MAX_RECORD_BYTES:
        raise ValueError("invalid audit key state")
    try:
        value = json.loads(encoded.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid audit key state") from error
    fields = {"version", "key", "keyId", "committed", "pending", "anchorMac"}
    if not isinstance(value, dict) or set(value) != fields or value.get("version") != _KEY_VERSION:
        raise ValueError("invalid audit key state")
    key_value = value["key"]
    if not isinstance(key_value, str) or not key_value.isascii():
        raise ValueError("invalid audit key state")
    try:
        key = base64.urlsafe_b64decode(key_value + "=" * (-len(key_value) % 4))
    except ValueError as error:
        raise ValueError("invalid audit key state") from error
    if (
        len(key) < AUDIT_KEY_BYTES
        or base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii") != key_value
        or value.get("keyId") != hashlib.sha256(key).hexdigest()[:16]
    ):
        raise ValueError("invalid audit key state")
    supplied_mac = value["anchorMac"]
    if not isinstance(supplied_mac, str) or not _MAC_VALUE.fullmatch(supplied_mac):
        raise ValueError("invalid audit key state")
    unsigned = dict(value)
    unsigned.pop("anchorMac")
    canonical = json.dumps(unsigned, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    expected_mac = hmac.new(key, _ANCHOR_MAC_DOMAIN + canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise ValueError("invalid audit key state")
    committed = _parse_snapshot(value["committed"])
    pending = _parse_snapshot(value["pending"]) if value["pending"] is not None else None
    return _KeyState(key, committed, pending)


class _SecureFile:
    def __init__(self, path: Path, handle: BinaryIO) -> None:
        self.path = path
        self.name = str(path)
        self._handle = handle

    def __getattr__(self, name: str) -> Any:
        return getattr(self._handle, name)

    def __enter__(self) -> _SecureFile:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        verification_error: Exception | None = None
        try:
            _verify_path_matches_handle(self.path, self._handle, directory=False)
        except Exception as error:
            verification_error = error
        finally:
            self._handle.close()
        if verification_error is not None:
            raise verification_error


def _secure_open_file(path: Path, mode: str) -> _SecureFile:
    if mode not in {"read", "append", "exclusive"}:
        raise ValueError("invalid secure open mode")
    with _hold_ancestor_chain(path.parent) as parent_descriptor:
        if os.name == "nt":
            handle = _windows_open_file(path, mode)
        else:
            flags = os.O_CLOEXEC | os.O_NOFOLLOW
            python_mode = "rb"
            if mode == "read":
                flags |= os.O_RDONLY
            elif mode == "append":
                flags |= os.O_RDWR | os.O_APPEND | os.O_CREAT
                python_mode = "a+b"
            else:
                flags |= os.O_RDWR | os.O_CREAT | os.O_EXCL
                python_mode = "w+b"
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
            try:
                handle = os.fdopen(descriptor, python_mode)
            except Exception:
                os.close(descriptor)
                raise
    wrapped = _SecureFile(path, handle)
    try:
        _enforce_and_verify_owner_only(wrapped, directory=False)
        _verify_path_matches_handle(path, wrapped, directory=False)
    except Exception:
        handle.close()
        raise
    return wrapped


@contextmanager
def _secure_open_directory(path: Path) -> Iterator[int]:
    with _hold_ancestor_chain(path.parent) as parent_descriptor:
        if os.name == "nt":
            descriptor = _windows_open_directory(path)
        else:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
    try:
        _enforce_and_verify_owner_only(descriptor, directory=True)
        _verify_path_matches_fd(path, descriptor, directory=True)
        yield descriptor
        _verify_path_matches_fd(path, descriptor, directory=True)
    finally:
        os.close(descriptor)


def _ensure_owner_only_directory(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while not _lexists(cursor):
        missing.append(cursor)
        if cursor == cursor.parent:
            raise ValueError("invalid audit directory")
        cursor = cursor.parent
    _validate_ancestor_chain(cursor)
    for directory in reversed(missing):
        with _hold_ancestor_chain(directory.parent) as parent_descriptor:
            if os.name == "nt":
                _windows_create_directory(directory)
            else:
                os.mkdir(directory.name, 0o700, dir_fd=parent_descriptor)
        with _secure_open_directory(directory):
            pass
    with _secure_open_directory(path):
        pass


def _validate_ancestor_chain(path: Path) -> None:
    with _hold_ancestor_chain(path):
        pass


@contextmanager
def _hold_ancestor_chain(path: Path) -> Iterator[int]:
    absolute = path.absolute()
    descriptors: list[int] = []
    try:
        if os.name == "nt":
            ancestors = list(reversed(absolute.parents)) + [absolute]
            for ancestor in ancestors:
                if not _lexists(ancestor):
                    continue
                info = ancestor.lstat()
                if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
                    raise ValueError("unsafe audit ancestor")
                descriptor = _windows_open_directory(ancestor)
                _verify_path_matches_fd(ancestor, descriptor, directory=True)
                descriptors.append(descriptor)
        else:
            parts = absolute.parts
            if not parts:
                raise ValueError("invalid audit ancestor")
            descriptor = os.open(
                parts[0],
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            descriptors.append(descriptor)
            for name in parts[1:]:
                parent_descriptor = descriptors[-1]
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_descriptor,
                )
                opened = os.fstat(descriptor)
                named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or not stat.S_ISDIR(named.st_mode)
                    or stat.S_ISLNK(named.st_mode)
                    or opened.st_dev != named.st_dev
                    or opened.st_ino != named.st_ino
                ):
                    os.close(descriptor)
                    raise ValueError("unsafe audit ancestor")
                descriptors.append(descriptor)
        if not descriptors:
            raise ValueError("invalid audit ancestor")
        yield descriptors[-1]
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _verify_path_matches_handle(path: Path, handle: object, *, directory: bool) -> None:
    _verify_path_matches_fd(path, handle.fileno(), directory=directory)  # type: ignore[attr-defined]


def _verify_path_matches_fd(path: Path, descriptor: int, *, directory: bool) -> None:
    opened = os.fstat(descriptor)
    named = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(opened.st_mode)
        or not expected_type(named.st_mode)
        or stat.S_ISLNK(named.st_mode)
        or _is_reparse(opened)
        or _is_reparse(named)
        or opened.st_dev != named.st_dev
        or opened.st_ino != named.st_ino
        or (not directory and opened.st_nlink != 1)
    ):
        raise ValueError("unsafe audit storage")


def _enforce_and_verify_owner_only(handle: object, *, directory: bool) -> None:
    descriptor = handle if isinstance(handle, int) else handle.fileno()  # type: ignore[attr-defined]
    info = os.fstat(descriptor)
    if os.name == "nt":
        _windows_verify_owner_only(descriptor)
        return
    required = 0o700 if directory else 0o600
    if (
        info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != required
        or (not directory and info.st_nlink != 1)
    ):
        raise ValueError("unsafe audit permissions")


def _paths_are_owner_only(paths: list[Path]) -> bool:
    try:
        for path in paths:
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                with _secure_open_directory(path):
                    pass
            else:
                with _secure_open_file(path, "read"):
                    pass
    except Exception:
        return False
    return True


def _secure_replace(source: Path, destination: Path) -> None:
    if source.parent != destination.parent:
        raise ValueError("audit replacement must remain in its namespace")
    with _secure_open_file(source, "read"):
        pass
    if _lexists(destination):
        with _secure_open_file(destination, "read"):
            pass
    if os.name == "nt":
        _windows_replace(source, destination)
    else:
        with _hold_ancestor_chain(source.parent) as parent_descriptor:
            os.replace(
                source.name,
                destination.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
    with _secure_open_file(destination, "read"):
        pass


def _secure_unlink(path: Path, *, missing_ok: bool = False) -> None:
    if not _lexists(path):
        if missing_ok:
            return
        raise FileNotFoundError(path)
    with _secure_open_file(path, "read"):
        pass
    if os.name == "nt":
        _windows_unlink(path)
    else:
        with _hold_ancestor_chain(path.parent) as parent_descriptor:
            os.unlink(path.name, dir_fd=parent_descriptor)


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


if os.name == "nt":
    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _WRITE_OWNER = 0x00080000
    _READ_CONTROL = 0x00020000
    _FILE_READ_ATTRIBUTES = 0x0080
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _OPEN_ALWAYS = 4
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _SE_FILE_OBJECT = 1
    _ACL_SIZE_INFORMATION_CLASS = 2
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _INHERITED_ACE = 0x10
    _SE_DACL_PROTECTED = 0x1000
    _MOVEFILE_REPLACE_EXISTING = 0x1
    _MOVEFILE_WRITE_THROUGH = 0x8
    _ERROR_ALREADY_EXISTS = 183

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", ctypes.c_ushort),
        ]

    _KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
    _KERNEL32.LocalFree.argtypes = [ctypes.c_void_p]
    _KERNEL32.LocalFree.restype = ctypes.c_void_p
    _KERNEL32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _KERNEL32.CreateFileW.restype = wintypes.HANDLE
    _KERNEL32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SECURITY_ATTRIBUTES)]
    _KERNEL32.CreateDirectoryW.restype = wintypes.BOOL
    _KERNEL32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _KERNEL32.MoveFileExW.restype = wintypes.BOOL
    _KERNEL32.DeleteFileW.argtypes = [wintypes.LPCWSTR]
    _KERNEL32.DeleteFileW.restype = wintypes.BOOL

    _ADVAPI32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _ADVAPI32.OpenProcessToken.restype = wintypes.BOOL
    _ADVAPI32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _ADVAPI32.GetTokenInformation.restype = wintypes.BOOL
    _ADVAPI32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _ADVAPI32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _ADVAPI32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    _ADVAPI32.ConvertStringSidToSidW.restype = wintypes.BOOL
    _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _ADVAPI32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _ADVAPI32.GetSecurityInfo.restype = wintypes.DWORD
    _ADVAPI32.SetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    _ADVAPI32.SetSecurityInfo.restype = wintypes.DWORD
    _ADVAPI32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _ADVAPI32.EqualSid.restype = wintypes.BOOL
    _ADVAPI32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    _ADVAPI32.GetAclInformation.restype = wintypes.BOOL
    _ADVAPI32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _ADVAPI32.GetAce.restype = wintypes.BOOL
    _ADVAPI32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ushort),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _ADVAPI32.GetSecurityDescriptorControl.restype = wintypes.BOOL


def _windows_path(path: Path) -> str:
    value = str(path.absolute())
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    if not value.startswith("\\\\?\\"):
        return "\\\\?\\" + value
    return value


def _windows_error() -> OSError:
    return ctypes.WinError(ctypes.get_last_error())  # type: ignore[name-defined]


def _windows_current_sid_string() -> str:
    token = wintypes.HANDLE()  # type: ignore[name-defined]
    if not _ADVAPI32.OpenProcessToken(_KERNEL32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):  # type: ignore[name-defined]
        raise _windows_error()
    try:
        needed = wintypes.DWORD()  # type: ignore[name-defined]
        _ADVAPI32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))  # type: ignore[name-defined]
        if needed.value == 0:
            raise _windows_error()
        buffer = ctypes.create_string_buffer(needed.value)  # type: ignore[name-defined]
        if not _ADVAPI32.GetTokenInformation(  # type: ignore[name-defined]
            token,
            _TOKEN_USER,
            buffer,
            needed,
            ctypes.byref(needed),
        ):
            raise _windows_error()
        sid = ctypes.c_void_p.from_buffer(buffer).value  # type: ignore[name-defined]
        sid_text = wintypes.LPWSTR()  # type: ignore[name-defined]
        if not _ADVAPI32.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):  # type: ignore[name-defined]
            raise _windows_error()
        try:
            return sid_text.value
        finally:
            _KERNEL32.LocalFree(sid_text)
    finally:
        _KERNEL32.CloseHandle(token)


@contextmanager
def _windows_security_attributes() -> Iterator[object]:
    sid = _windows_current_sid_string()
    descriptor = ctypes.c_void_p()  # type: ignore[name-defined]
    sddl = f"D:P(A;;FA;;;{sid})"
    if not _ADVAPI32.ConvertStringSecurityDescriptorToSecurityDescriptorW(  # type: ignore[name-defined]
        sddl,
        1,
        ctypes.byref(descriptor),
        None,
    ):
        raise _windows_error()
    attributes = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), descriptor, False)  # type: ignore[name-defined]
    try:
        yield attributes
    finally:
        _KERNEL32.LocalFree(descriptor)


def _windows_open_file(path: Path, mode: str) -> BinaryIO:
    creation = {"read": _OPEN_EXISTING, "append": _OPEN_ALWAYS, "exclusive": _CREATE_NEW}[mode]
    desired = _GENERIC_READ | _READ_CONTROL
    flags = os.O_BINARY | os.O_RDONLY
    python_mode = "rb"
    if mode != "read":
        desired |= _GENERIC_WRITE | _WRITE_OWNER
        flags = os.O_BINARY | os.O_RDWR
        python_mode = "a+b" if mode == "append" else "w+b"
    with _windows_security_attributes() as attributes:
        ctypes.set_last_error(0)
        handle = _KERNEL32.CreateFileW(
            _windows_path(path),
            desired,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            ctypes.byref(attributes),  # type: ignore[name-defined,arg-type]
            creation,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        create_error = ctypes.get_last_error()
    if handle == _INVALID_HANDLE_VALUE:
        error = _windows_error()
        if getattr(error, "winerror", None) in {80, 183}:
            raise FileExistsError(path)
        raise error
    created = mode == "exclusive" or (mode == "append" and create_error != _ERROR_ALREADY_EXISTS)
    try:
        if created:
            _windows_set_current_owner_handle(handle)
        descriptor = msvcrt.open_osfhandle(handle, flags | os.O_NOINHERIT)  # type: ignore[name-defined]
    except Exception:
        _KERNEL32.CloseHandle(handle)
        raise
    try:
        raw = os.fdopen(descriptor, python_mode)
    except Exception:
        os.close(descriptor)
        raise
    try:
        if mode == "append":
            raw.seek(0, os.SEEK_END)
        return raw
    except Exception:
        raw.close()
        raise


def _windows_open_directory(path: Path, *, write_owner: bool = False) -> int:
    desired = _FILE_READ_ATTRIBUTES | _READ_CONTROL
    if write_owner:
        desired |= _WRITE_OWNER
    handle = _KERNEL32.CreateFileW(
        _windows_path(path),
        desired,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise _windows_error()
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_NOINHERIT)  # type: ignore[name-defined]
    except Exception:
        _KERNEL32.CloseHandle(handle)
        raise


def _windows_create_directory(path: Path) -> None:
    with _windows_security_attributes() as attributes:
        if not _KERNEL32.CreateDirectoryW(_windows_path(path), ctypes.byref(attributes)):  # type: ignore[name-defined,arg-type]
            raise _windows_error()
    descriptor = _windows_open_directory(path, write_owner=True)
    try:
        _windows_set_current_owner_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _windows_set_current_owner_descriptor(descriptor: int) -> None:
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))  # type: ignore[name-defined]
    _windows_set_current_owner_handle(handle)


def _windows_set_current_owner_handle(handle: object) -> None:
    current_sid = ctypes.c_void_p()  # type: ignore[name-defined]
    if not _ADVAPI32.ConvertStringSidToSidW(  # type: ignore[name-defined]
        _windows_current_sid_string(), ctypes.byref(current_sid)
    ):
        raise _windows_error()
    try:
        result = _ADVAPI32.SetSecurityInfo(  # type: ignore[name-defined]
            handle,
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION,
            current_sid,
            None,
            None,
            None,
        )
        if result != 0:
            raise OSError(result, "failed to set audit owner")
    finally:
        _KERNEL32.LocalFree(current_sid)


def _windows_verify_owner_only(descriptor: int) -> None:
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))  # type: ignore[name-defined]
    owner = ctypes.c_void_p()  # type: ignore[name-defined]
    dacl = ctypes.c_void_p()  # type: ignore[name-defined]
    security_descriptor = ctypes.c_void_p()  # type: ignore[name-defined]
    result = _ADVAPI32.GetSecurityInfo(
        handle,
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),  # type: ignore[name-defined]
        None,
        ctypes.byref(dacl),  # type: ignore[name-defined]
        None,
        ctypes.byref(security_descriptor),  # type: ignore[name-defined]
    )
    if result != 0 or not owner.value or not dacl.value or not security_descriptor.value:
        if security_descriptor.value:
            _KERNEL32.LocalFree(security_descriptor)
        raise ValueError("owner-only ACL could not be verified")
    current_sid = ctypes.c_void_p()  # type: ignore[name-defined]
    if not _ADVAPI32.ConvertStringSidToSidW(  # type: ignore[name-defined]
        _windows_current_sid_string(), ctypes.byref(current_sid)
    ):
        _KERNEL32.LocalFree(security_descriptor)
        raise _windows_error()
    try:
        if not _ADVAPI32.EqualSid(owner, current_sid):
            raise ValueError("unsafe audit owner")
        control = ctypes.c_ushort()  # type: ignore[name-defined]
        revision = wintypes.DWORD()  # type: ignore[name-defined]
        if not _ADVAPI32.GetSecurityDescriptorControl(  # type: ignore[name-defined]
            security_descriptor, ctypes.byref(control), ctypes.byref(revision)
        ) or not control.value & _SE_DACL_PROTECTED:
            raise ValueError("audit DACL is inherited")
        info = _ACL_SIZE_INFORMATION()
        if not _ADVAPI32.GetAclInformation(
            dacl,
            ctypes.byref(info),  # type: ignore[name-defined]
            ctypes.sizeof(info),  # type: ignore[name-defined]
            _ACL_SIZE_INFORMATION_CLASS,
        ) or info.AceCount != 1:
            raise ValueError("audit DACL is not owner-only")
        ace = ctypes.c_void_p()  # type: ignore[name-defined]
        if not _ADVAPI32.GetAce(dacl, 0, ctypes.byref(ace)):  # type: ignore[name-defined]
            raise _windows_error()
        header = ctypes.cast(ace, ctypes.POINTER(_ACE_HEADER)).contents  # type: ignore[name-defined]
        sid_address = ace.value + ctypes.sizeof(_ACE_HEADER) + ctypes.sizeof(wintypes.DWORD)  # type: ignore[name-defined]
        if (
            header.AceType != _ACCESS_ALLOWED_ACE_TYPE
            or header.AceFlags & _INHERITED_ACE
            or not _ADVAPI32.EqualSid(ctypes.c_void_p(sid_address), current_sid)  # type: ignore[name-defined]
        ):
            raise ValueError("audit DACL is not owner-only")
    finally:
        _KERNEL32.LocalFree(current_sid)
        _KERNEL32.LocalFree(security_descriptor)


def _windows_replace(source: Path, destination: Path) -> None:
    if not _KERNEL32.MoveFileExW(
        _windows_path(source),
        _windows_path(destination),
        _MOVEFILE_REPLACE_EXISTING | _MOVEFILE_WRITE_THROUGH,
    ):
        raise _windows_error()


def _windows_unlink(path: Path) -> None:
    if not _KERNEL32.DeleteFileW(_windows_path(path)):
        raise _windows_error()


def _required_safe(value: object) -> str:
    if not isinstance(value, str) or not _SAFE_VALUE.fullmatch(value):
        raise ValueError("invalid audit value")
    return value


def _optional_safe(value: object) -> str | None:
    if value is None:
        return None
    return _required_safe(value)


def _required_tool(value: object) -> str:
    if not isinstance(value, str) or value not in _TOOLS:
        raise ValueError("invalid audit tool")
    return value


def _required_operation(value: object) -> str:
    if not isinstance(value, str) or value not in _OPERATIONS:
        raise ValueError("invalid audit operation")
    return value


def _optional_scope(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in _SCOPES:
        raise ValueError("invalid audit scope")
    return value


def _required_outcome(event: str, value: object) -> str:
    if not isinstance(value, str) or value not in _EVENT_OUTCOMES[event]:
        raise ValueError("invalid audit outcome")
    return value


def _optional_error_code(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in _STABLE_ERROR_CODES:
        raise ValueError("invalid audit error code")
    return value


def _required_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid audit identifier")
    parsed = UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("invalid audit identifier")
    return value


def _optional_uuid(value: object) -> str | None:
    if value is None:
        return None
    return _required_uuid(value)


def _required_hash(value: object) -> str:
    if not isinstance(value, str) or not _HASH_VALUE.fullmatch(value):
        raise ValueError("invalid audit hash")
    return value


def _optional_hash(value: object) -> str | None:
    if value is None:
        return None
    return _required_hash(value)


def _as_optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _owned_by_current_user(info: os.stat_result) -> bool:
    return not hasattr(os, "getuid") or info.st_uid == os.getuid()


def _audit_failed() -> TrustMutationAuditError:
    return TrustMutationAuditError(
        "MCP_TRUST_MUTATION_AUDIT_FAILED",
        "The trust mutation audit operation failed closed.",
    )


def _commit_cleanup_failed() -> TrustMutationAuditCommitCleanupError:
    return TrustMutationAuditCommitCleanupError(
        "MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING",
        "The committed trust mutation requires cleanup recovery.",
    )


def _corrupt() -> TrustMutationAuditError:
    return TrustMutationAuditError(
        "MCP_TRUST_MUTATION_CORRUPT",
        "The trust mutation audit chain is invalid.",
    )


def _recovery_required() -> TrustMutationAuditError:
    return TrustMutationAuditError(
        "MCP_TRUST_MUTATION_RECOVERY_REQUIRED",
        "Trust mutation recovery requires known-good local state.",
    )
