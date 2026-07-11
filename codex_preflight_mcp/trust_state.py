from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from codex_preflight_core.cache.file_lock import locked_cache_file

TRUST_CURSOR_MAX_BYTES = 512
TRUST_CURSOR_EXPIRY_SECONDS = 300
TRUST_AUDIT_MAX_RECORD_BYTES = 4096
TRUST_AUDIT_MAX_SEGMENT_BYTES = 1024 * 1024
TRUST_AUDIT_MAX_ROTATED_SEGMENTS = 3

_CURSOR_FIELDS = {
    "t",
    "v",
    "r",
    "s",
    "l",
    "d",
    "o",
    "i",
    "e",
    "n",
}
_AUDIT_EVENTS = {
    "registration_state",
    "request_validation_failed",
    "request_validated",
    "migration_started",
    "migration_completed",
    "migration_failed",
    "trust_file_missing",
    "trust_file_empty",
    "trust_file_read_failed",
    "trust_file_corrupt",
    "trust_file_unsupported_schema",
    "lock_timeout",
    "cursor_issued",
    "cursor_rejected",
    "filter_applied",
    "page_returned",
    "success",
    "failure",
}
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class TrustReadStateError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def privacy_hash(value: str, key: bytes) -> str:
    return f"hmac-sha256:{hmac.new(key, value.encode('utf-8'), hashlib.sha256).hexdigest()}"


class TrustCursorManager:
    def __init__(
        self,
        *,
        secret: bytes | None = None,
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        self._secret = secret or secrets.token_bytes(32)
        self._clock = clock
        self._nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(16))

    def issue(
        self,
        *,
        repo_id_hash: str | None,
        command_scope: str | None,
        limit: int,
        snapshot_digest: str,
        offset: int,
    ) -> str:
        issued_at = int(self._clock())
        payload = {
            "t": "trust_list",
            "v": "trust-list/v1",
            "r": repo_id_hash,
            "s": command_scope,
            "l": limit,
            "d": snapshot_digest,
            "o": offset,
            "i": issued_at,
            "e": issued_at + TRUST_CURSOR_EXPIRY_SECONDS,
            "n": self._nonce_factory(),
        }
        encoded = _encode_json(payload)
        signature = _encode_bytes(hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest())
        token = f"{encoded}.{signature}"
        if len(token.encode("utf-8")) > TRUST_CURSOR_MAX_BYTES:
            raise _cursor_error()
        return token

    def consume(
        self,
        token: object,
        *,
        repo_id_hash: str | None,
        command_scope: str | None,
        limit: int,
        snapshot_digest: str,
    ) -> int:
        try:
            if (
                not isinstance(token, str)
                or not token
                or len(token.encode("utf-8")) > TRUST_CURSOR_MAX_BYTES
                or _CONTROL.search(token)
            ):
                raise ValueError("invalid cursor")
            encoded, signature = token.split(".", 1)
            expected = _encode_bytes(hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest())
            if not hmac.compare_digest(signature, expected):
                raise ValueError("invalid signature")
            payload = json.loads(_decode_bytes(encoded).decode("utf-8", "strict"))
            if not isinstance(payload, dict) or set(payload) != _CURSOR_FIELDS:
                raise ValueError("invalid payload")
            if (
                payload["t"] != "trust_list"
                or payload["v"] != "trust-list/v1"
                or payload["r"] != repo_id_hash
                or payload["s"] != command_scope
                or payload["l"] != limit
                or payload["d"] != snapshot_digest
                or not isinstance(payload["o"], int)
                or isinstance(payload["o"], bool)
                or payload["o"] < 1
                or not isinstance(payload["i"], int)
                or not isinstance(payload["e"], int)
                or payload["e"] - payload["i"] != TRUST_CURSOR_EXPIRY_SECONDS
                or self._clock() >= payload["e"]
                or not isinstance(payload["n"], str)
                or not payload["n"]
            ):
                raise ValueError("cursor binding mismatch")
            return payload["o"]
        except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise _cursor_error() from error


class TrustReadAuditLog:
    def __init__(
        self,
        path: Path,
        *,
        privacy_key: bytes,
        clock: Callable[[], float] = time.time,
        event_id_factory: Callable[[], str] | None = None,
        max_record_bytes: int = TRUST_AUDIT_MAX_RECORD_BYTES,
        max_segment_bytes: int = TRUST_AUDIT_MAX_SEGMENT_BYTES,
        max_rotated_segments: int = TRUST_AUDIT_MAX_ROTATED_SEGMENTS,
    ) -> None:
        self.path = path
        self.privacy_key = privacy_key
        self.clock = clock
        self.event_id_factory = event_id_factory or (lambda: str(uuid4()))
        self.max_record_bytes = max_record_bytes
        self.max_segment_bytes = max_segment_bytes
        self.max_rotated_segments = max_rotated_segments

    def record(
        self,
        event: str,
        *,
        repo_id: str | None = None,
        command_scope: str | None = None,
        result_count: int | None = None,
        cursor_status: str | None = None,
        migration_status: str | None = None,
        outcome: str,
        error_code: str | None = None,
        runtime_identity: Mapping[str, object],
    ) -> str:
        try:
            record = self._build_record(
                event,
                repo_id=repo_id,
                command_scope=command_scope,
                result_count=result_count,
                cursor_status=cursor_status,
                migration_status=migration_status,
                outcome=outcome,
                error_code=error_code,
                runtime_identity=runtime_identity,
            )
            line = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
            if len(line) > self.max_record_bytes or len(line) > self.max_segment_bytes:
                raise ValueError("audit record too large")
            with locked_cache_file(self.path):
                current_size = self.path.stat().st_size if self.path.exists() else 0
                if current_size + len(line) > self.max_segment_bytes:
                    self._rotate_unlocked()
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("ab") as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
            return str(record["eventId"])
        except TrustReadStateError:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise _audit_error() from error

    def _build_record(self, event: str, **values: object) -> dict[str, Any]:
        if event not in _AUDIT_EVENTS:
            raise ValueError("unsupported audit event")
        event_id = values.get("event_id") or self.event_id_factory()
        if not isinstance(event_id, str) or not event_id or len(event_id.encode("utf-8")) > 128:
            raise ValueError("invalid event id")
        repo_id = values.get("repo_id")
        if repo_id is not None and not isinstance(repo_id, str):
            raise ValueError("invalid repo id")
        command_scope = _optional_safe(values.get("command_scope"))
        cursor_status = _optional_safe(values.get("cursor_status"))
        migration_status = _optional_safe(values.get("migration_status"))
        outcome = _required_safe(values.get("outcome"))
        error_code = _optional_safe(values.get("error_code"))
        result_count = values.get("result_count")
        if result_count is not None and (
            not isinstance(result_count, int) or isinstance(result_count, bool) or result_count < 0
        ):
            raise ValueError("invalid result count")
        runtime_identity = values.get("runtime_identity")
        if not isinstance(runtime_identity, Mapping) or dict(runtime_identity) != {
            "transport": "stdio",
            "identityStatus": "unavailable",
            "clientId": None,
            "sessionId": None,
        }:
            raise ValueError("invalid runtime identity")
        return {
            "eventId": event_id,
            "timestamp": datetime.fromtimestamp(self.clock(), UTC).isoformat(),
            "tool": "trust_list",
            "operation": "trust-list",
            "schemaVersion": "trust-list/v1",
            "event": event,
            "repoIdHash": privacy_hash(repo_id, self.privacy_key) if isinstance(repo_id, str) else None,
            "commandScope": command_scope,
            "resultCount": result_count,
            "cursorStatus": cursor_status,
            "migrationStatus": migration_status,
            "outcome": outcome,
            "errorCode": error_code,
            "runtimeIdentity": dict(runtime_identity),
        }

    def _rotate_unlocked(self) -> None:
        if self.max_rotated_segments < 0:
            raise ValueError("invalid audit rotation")
        if self.max_rotated_segments == 0:
            self.path.unlink(missing_ok=True)
            return
        oldest = self.path.with_name(f"{self.path.name}.{self.max_rotated_segments}")
        oldest.unlink(missing_ok=True)
        for index in range(self.max_rotated_segments - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            if source.exists():
                os.replace(source, self.path.with_name(f"{self.path.name}.{index + 1}"))
        if self.path.exists():
            os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))


def _encode_json(payload: dict[str, object]) -> str:
    return _encode_bytes(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_bytes(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _optional_safe(value: object) -> str | None:
    if value is None:
        return None
    return _required_safe(value)


def _required_safe(value: object) -> str:
    if not isinstance(value, str) or not _SAFE_VALUE.fullmatch(value):
        raise ValueError("invalid audit value")
    return value


def _cursor_error() -> TrustReadStateError:
    return TrustReadStateError(
        "MCP_TRUST_LIST_CURSOR_INVALID",
        "The trust-list cursor is invalid, expired, restart-invalid, or bound to another snapshot.",
    )


def _audit_error() -> TrustReadStateError:
    return TrustReadStateError(
        "MCP_TRUST_LIST_AUDIT_FAILED",
        "The dedicated trust-read audit log failed closed.",
    )
