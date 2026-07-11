from __future__ import annotations

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

AUDIT_MAX_RECORD_BYTES = 4096
AUDIT_MAX_SEGMENT_BYTES = 1024 * 1024
AUDIT_MAX_ROTATED_SEGMENTS = 3
AUDIT_MAX_TOTAL_BYTES = 4 * 1024 * 1024
AUDIT_KEY_BYTES = 32

_AUDIT_VERSION = "trust-mutation-audit/v1"
_AUDIT_MAC_DOMAIN = b"codex-preflight/trust-mutation/audit-record/v1\x00"
_STATE_MAC_DOMAIN = b"codex-preflight/trust-mutation/trust-state/v1\x00"
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


class _IntegrityError(RuntimeError):
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

    def record(self, event: str, *, context: AuditContext) -> str:
        try:
            key = self._load_or_create_key()
            record = self._build_record(event, context=context)
            with self._locked():
                return self._append_record_unlocked(record, key)
        except TrustMutationAuditError:
            raise
        except Exception as error:
            raise _audit_failed() from error

    def prepare_mutation(
        self,
        *,
        operation: str,
        before_bytes: bytes | None,
        after_bytes: bytes | None,
        entry_id: str,
        context: AuditContext,
    ) -> PreparedMutation:
        try:
            _required_safe(operation)
            _required_uuid(entry_id)
            if operation != context.operation or entry_id != context.entry_id:
                raise ValueError("mutation binding mismatch")
            key = self._load_or_create_key()
            before_digest = self._state_digest(before_bytes, key)
            after_digest = self._state_digest(after_bytes, key)
            record = self._build_record(
                "mutation_prepared",
                context=context,
                before_state_digest=before_digest,
                after_state_digest=after_digest,
            )
            with self._locked():
                event_id = self._append_record_unlocked(record, key)
            return PreparedMutation(event_id, operation, entry_id, before_digest, after_digest)
        except TrustMutationAuditError:
            raise
        except Exception as error:
            raise _audit_failed() from error

    def commit_mutation(self, prepared: PreparedMutation, *, context: AuditContext) -> str:
        try:
            self._validate_prepared(prepared, context)
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
                self._require_unmatched_tail(records, prepared.event_id)
                return self._append_record_unlocked(record, key)
        except TrustMutationAuditError:
            raise
        except Exception as error:
            raise _audit_failed() from error

    def verify_and_recover(self, *, read_store_bytes: Callable[[], bytes | None]) -> RecoveryResult:
        try:
            key = self._load_or_create_key()
        except Exception as error:
            raise _audit_failed() from error
        try:
            with self._locked():
                records, _last_mac = self._verify_chain_unlocked(key)
                unmatched = self._unmatched_prepares(records)
                if not unmatched:
                    return RecoveryResult("clean")
                if len(unmatched) != 1 or records[-1]["eventId"] != unmatched[0]["eventId"]:
                    raise _recovery_required()
                prepared = unmatched[0]
                try:
                    current = read_store_bytes()
                    current_digest = self._state_digest(current, key)
                except Exception as error:
                    raise _recovery_required() from error
                if hmac.compare_digest(current_digest, str(prepared["afterStateDigest"])):
                    event = "recovery_committed"
                    status = "recovery_committed"
                elif hmac.compare_digest(current_digest, str(prepared["beforeStateDigest"])):
                    event = "recovery_aborted"
                    status = "recovery_aborted"
                else:
                    raise _recovery_required()
                context = self._context_from_record(prepared, outcome=status)
                recovery = self._build_record(
                    event,
                    context=context,
                    before_state_digest=str(prepared["beforeStateDigest"]),
                    after_state_digest=str(prepared["afterStateDigest"]),
                    prepared_event_id=str(prepared["eventId"]),
                )
                try:
                    event_id = self._append_record_unlocked(recovery, key)
                except Exception as error:
                    raise _recovery_required() from error
                return RecoveryResult(status, event_id, str(prepared["eventId"]))
        except TrustMutationAuditError:
            raise
        except _IntegrityError as error:
            raise _corrupt() from error
        except Exception as error:
            raise _recovery_required() from error

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._ensure_directory()
        lock_path = self.path.with_suffix(f"{self.path.suffix}.lock")
        if lock_path.exists() or lock_path.is_symlink():
            self._validate_regular_private_file(lock_path, exact_size=None)
        with locked_cache_file(self.path):
            if os.name != "nt":
                os.chmod(lock_path, 0o600)
            self._validate_regular_private_file(lock_path, exact_size=None)
            yield

    def _load_or_create_key(self) -> bytes:
        self._ensure_directory()
        if self.key_path.exists() or self.key_path.is_symlink():
            return self._read_key()
        if self._audit_artifacts_exist():
            raise ValueError("audit key missing for existing chain")
        key = self.key_factory(AUDIT_KEY_BYTES)
        if type(key) is not bytes or len(key) < AUDIT_KEY_BYTES:
            raise ValueError("invalid audit key")
        try:
            with self.key_path.open("xb") as handle:
                if os.name != "nt":
                    os.chmod(self.key_path, 0o600)
                self._write_bytes(handle, key)
                self._flush_and_fsync(handle)
        except FileExistsError:
            return self._read_key()
        except Exception:
            try:
                self.key_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        self._fsync_directory()
        return self._read_key()

    def _read_key(self) -> bytes:
        self._validate_regular_private_file(self.key_path, exact_size=None)
        key = self.key_path.read_bytes()
        if len(key) < AUDIT_KEY_BYTES:
            raise ValueError("invalid audit key")
        return key

    def _ensure_directory(self) -> None:
        parent = self.path.parent
        if parent != self.key_path.parent:
            raise ValueError("audit paths must share a directory")
        created = not parent.exists() and not parent.is_symlink()
        if not created:
            info = parent.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or parent.is_symlink()
                or _is_reparse(info)
                or not _owned_by_current_user(info)
                or (os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077)
            ):
                raise ValueError("unsafe audit directory")
        else:
            parent.mkdir(parents=True)
        if os.name != "nt":
            os.chmod(parent, 0o700)

    def _validate_regular_private_file(self, path: Path, *, exact_size: int | None) -> None:
        info = path.lstat()
        if (
            path.is_symlink()
            or _is_reparse(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not _owned_by_current_user(info)
            or (exact_size is not None and info.st_size != exact_size)
        ):
            raise ValueError("unsafe audit file")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("unsafe audit permissions")

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
        _required_safe(context.tool)
        _required_uuid(context.operation_id)
        _required_safe(context.operation)
        _optional_hash(context.target_hash)
        _optional_uuid(context.entry_id)
        _optional_safe(context.scope)
        _optional_safe(context.policy_version)
        _optional_safe(context.ruleset_version)
        _optional_uuid(context.challenge_id)
        _required_safe(context.outcome)
        _optional_safe(context.error_code)
        if context.entry_version is not None and (
            not isinstance(context.entry_version, int)
            or isinstance(context.entry_version, bool)
            or context.entry_version < 1
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

    def _append_record_unlocked(self, record: dict[str, object], key: bytes) -> str:
        _records, previous_mac = self._verify_chain_unlocked(key)
        signed = dict(record)
        signed["auditKeyId"] = self._key_id(key)
        signed["previousMac"] = previous_mac
        signed["recordMac"] = self._record_mac(signed, key)
        line = _canonical_line(signed)
        if len(line) > self.max_record_bytes or len(line) > self.max_segment_bytes:
            raise ValueError("audit record exceeds limit")
        self._ensure_directory()
        current_size = self.path.stat().st_size if self.path.exists() else 0
        if current_size + len(line) > self.max_segment_bytes:
            segments = self._existing_segments()
            projected_total = sum(segment.stat().st_size for segment in segments) + len(line)
            oldest = self.path.with_name(f"{self.path.name}.{self.max_rotated_segments}")
            if self.max_rotated_segments == 0 and self.path.exists():
                projected_total -= self.path.stat().st_size
            elif oldest.exists():
                projected_total -= oldest.stat().st_size
            if projected_total > self.max_total_bytes:
                raise ValueError("audit total exceeds limit")
            reservation = self._reserve_capacity(len(line))
            try:
                self._rotate_unlocked()
            finally:
                reservation.unlink(missing_ok=True)
        total = sum(segment.stat().st_size for segment in self._existing_segments())
        if total + len(line) > self.max_total_bytes:
            raise ValueError("audit total exceeds limit")
        if self.path.exists():
            self._validate_regular_private_file(self.path, exact_size=None)
        with self.path.open("ab") as handle:
            if os.name != "nt":
                os.chmod(self.path, 0o600)
            self._write_bytes(handle, line)
            self._flush_and_fsync(handle)
        self._fsync_directory()
        return str(signed["eventId"])

    def _verify_chain_unlocked(self, key: bytes) -> tuple[list[dict[str, Any]], str]:
        self._validate_limits()
        segments = self._existing_segments()
        if len(segments) > self.max_rotated_segments + 1:
            raise _IntegrityError("too many audit segments")
        total = sum(segment.stat().st_size for segment in segments)
        if total > self.max_total_bytes:
            raise _IntegrityError("audit total exceeds limit")
        records: list[dict[str, Any]] = []
        previous_mac: str | None = None
        for segment in segments:
            self._validate_regular_private_file(segment, exact_size=None)
            data = segment.read_bytes()
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
                self._validate_stored_record(record, key)
                if previous_mac is not None and record["previousMac"] != previous_mac:
                    raise _IntegrityError("broken audit chain")
                expected = self._record_mac(record, key)
                if not hmac.compare_digest(str(record["recordMac"]), expected):
                    raise _IntegrityError("invalid audit mac")
                previous_mac = str(record["recordMac"])
                records.append(record)
        return records, previous_mac or _ZERO_MAC

    def _validate_stored_record(self, record: Mapping[str, object], key: bytes) -> None:
        if record.get("auditVersion") != _AUDIT_VERSION or record.get("auditKeyId") != self._key_id(key):
            raise _IntegrityError("invalid audit identity")
        if record.get("event") not in _EVENTS or record.get("runtimeIdentity") != _RUNTIME_IDENTITY:
            raise _IntegrityError("invalid audit record")
        _required_uuid(record.get("eventId"))
        _required_uuid(record.get("operationId"))
        _optional_uuid(record.get("entryId"))
        _optional_uuid(record.get("challengeId"))
        _optional_uuid(record.get("preparedAuditEventId"))
        _optional_hash(record.get("targetHash"))
        _optional_hash(record.get("beforeStateDigest"))
        _optional_hash(record.get("afterStateDigest"))
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
            with reservation.open("xb") as handle:
                if os.name != "nt":
                    os.chmod(reservation, 0o600)
                self._write_bytes(handle, b"\x00" * size)
                self._flush_and_fsync(handle)
            return reservation
        except Exception:
            reservation.unlink(missing_ok=True)
            raise

    def _rotate_unlocked(self) -> None:
        if self.max_rotated_segments == 0:
            self._discard_oldest_unlocked()
            return
        oldest = self.path.with_name(f"{self.path.name}.{self.max_rotated_segments}")
        if oldest.exists() or oldest.is_symlink():
            self._discard_oldest_unlocked()
        for index in range(self.max_rotated_segments - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            if source.exists():
                os.replace(source, self.path.with_name(f"{self.path.name}.{index + 1}"))
        if self.path.exists():
            os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))
        self._fsync_directory()

    def _discard_oldest_unlocked(self) -> None:
        if self.max_rotated_segments == 0:
            target = self.path
        else:
            target = self.path.with_name(f"{self.path.name}.{self.max_rotated_segments}")
        target.unlink(missing_ok=True)

    def _existing_segments(self) -> list[Path]:
        candidates = [
            self.path.with_name(f"{self.path.name}.{index}")
            for index in range(self.max_rotated_segments, 0, -1)
        ] + [self.path]
        if self.path.parent.exists():
            valid_names = {path.name for path in candidates}
            valid_names.add(f"{self.path.name}.lock")
            for sibling in self.path.parent.glob(f"{self.path.name}.*"):
                if sibling.name not in valid_names:
                    raise _IntegrityError("unexpected audit segment")
        return [path for path in candidates if path.exists() or path.is_symlink()]

    def _audit_artifacts_exist(self) -> bool:
        if self.path.exists() or self.path.is_symlink():
            return True
        if not self.path.parent.exists():
            return False
        return any(
            sibling.name != f"{self.path.name}.lock"
            for sibling in self.path.parent.glob(f"{self.path.name}.*")
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
        descriptor = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _key_id(self, key: bytes) -> str:
        return hashlib.sha256(key).hexdigest()[:16]

    def _validate_prepared(self, prepared: PreparedMutation, context: AuditContext) -> None:
        if not isinstance(prepared, PreparedMutation):
            raise TypeError("invalid prepared mutation")
        _required_uuid(prepared.event_id)
        _required_uuid(prepared.entry_id)
        _required_safe(prepared.operation)
        _required_hash(prepared.before_state_digest)
        _required_hash(prepared.after_state_digest)
        if prepared.operation != context.operation or prepared.entry_id != context.entry_id:
            raise ValueError("mutation binding mismatch")

    def _require_unmatched_tail(self, records: list[dict[str, Any]], event_id: str) -> None:
        unmatched = self._unmatched_prepares(records)
        if len(unmatched) != 1 or unmatched[0]["eventId"] != event_id or records[-1]["eventId"] != event_id:
            raise _IntegrityError("prepared mutation is not the unmatched tail")

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


def _required_safe(value: object) -> str:
    if not isinstance(value, str) or not _SAFE_VALUE.fullmatch(value):
        raise ValueError("invalid audit value")
    return value


def _optional_safe(value: object) -> str | None:
    if value is None:
        return None
    return _required_safe(value)


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
