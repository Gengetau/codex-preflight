from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codex_preflight_core.cache.atomic_json import write_json_atomic
from codex_preflight_core.cache.file_lock import locked_cache_file
from codex_preflight_core.preflight import POLICY_VERSION, REPORT_FORMAT_VERSION, RULESET_VERSION

HOST_POLICY_VERSION = "github-public-v1"
RESOURCE_LIMIT_PROFILE = "remote-bounded-v1"
REMOTE_CACHE_TTL_SECONDS = 60 * 60
REMOTE_CACHE_MAX_ENTRIES = 64
REMOTE_CACHE_MAX_REPORT_BYTES = 1024 * 1024
REMOTE_CACHE_MAX_TOTAL_BYTES = 8 * 1024 * 1024
REMOTE_AUDIT_MAX_BYTES = 1024 * 1024
REMOTE_AUDIT_MAX_SEGMENTS = 3

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SAFE_OUTCOME = re.compile(r"^[a-z0-9-]{1,64}$")
_AUDIT_EVENTS = {
    "challenge_issue",
    "confirmation_consume",
    "operation_start",
    "ref_resolution",
    "acquisition_complete",
    "scan_complete",
    "cache_result",
    "cache_write",
    "timeout",
    "cancellation",
    "limit_breach",
    "cleanup",
    "success",
    "failure",
}
_RESOURCE_USAGE_FIELDS = {
    "gitBytes",
    "materializedBytes",
    "materializedFiles",
    "skippedLfsPointers",
    "skippedSubmodules",
    "skippedSymlinks",
    "totalMilliseconds",
}


class RemoteStateError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def build_remote_cache_key(canonical_url: str, resolved_commit: str) -> dict[str, str]:
    commit = resolved_commit.lower()
    if not _COMMIT.fullmatch(commit):
        raise RemoteStateError("MCP_REMOTE_CACHE_FAILED", "The remote cache identity was invalid.")
    return {
        "sourceType": "remote",
        "canonicalUrlHash": _hash(canonical_url),
        "resolvedCommit": commit,
        "rulesetVersion": RULESET_VERSION,
        "policyVersion": POLICY_VERSION,
        "reportFormatVersion": REPORT_FORMAT_VERSION,
        "resourceLimitProfile": RESOURCE_LIMIT_PROFILE,
        "hostPolicyVersion": HOST_POLICY_VERSION,
    }


class RemoteScanCache:
    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        ttl_seconds: int = REMOTE_CACHE_TTL_SECONDS,
        max_entries: int = REMOTE_CACHE_MAX_ENTRIES,
        max_report_bytes: int = REMOTE_CACHE_MAX_REPORT_BYTES,
        max_total_bytes: int = REMOTE_CACHE_MAX_TOTAL_BYTES,
    ) -> None:
        self.path = path
        self.clock = clock
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.max_report_bytes = max_report_bytes
        self.max_total_bytes = max_total_bytes

    def get(self, key: dict[str, str]) -> dict[str, Any] | None:
        try:
            with locked_cache_file(self.path):
                entries = self._load_unlocked()
                active = self._active(entries)
                if len(active) != len(entries):
                    self._write_unlocked(active)
                for entry in reversed(active):
                    if entry["key"] == key:
                        return _json_copy(entry["report"])
                return None
        except RemoteStateError:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise _cache_error() from error

    def store(self, key: dict[str, str], report: dict[str, Any]) -> None:
        try:
            encoded_report = json.dumps(report, separators=(",", ":"), sort_keys=True).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise _cache_error() from error
        if len(encoded_report) > self.max_report_bytes:
            raise _cache_error()
        copied_report = json.loads(encoded_report)
        now = self.clock()
        entry = {
            "key": dict(key),
            "createdAt": now,
            "expiresAt": now + self.ttl_seconds,
            "report": copied_report,
        }
        try:
            with locked_cache_file(self.path):
                entries = [item for item in self._active(self._load_unlocked()) if item["key"] != key]
                entries.append(entry)
                entries = entries[-self.max_entries :]
                while entries and _encoded_size(entries) > self.max_total_bytes:
                    entries.pop(0)
                if not entries or entries[-1] != entry:
                    raise _cache_error()
                self._write_unlocked(entries)
        except RemoteStateError:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise _cache_error() from error

    def _active(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = self.clock()
        return [entry for entry in entries if entry["expiresAt"] > now]

    def _load_unlocked(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        if self.path.stat().st_size > self.max_total_bytes:
            raise _cache_error()
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise _cache_error()
        for entry in payload:
            if not _valid_cache_entry(entry):
                raise _cache_error()
        return payload

    def _write_unlocked(self, entries: list[dict[str, Any]]) -> None:
        if _encoded_size(entries) > self.max_total_bytes:
            raise _cache_error()
        write_json_atomic(self.path, entries)
        if self.path.stat().st_size > self.max_total_bytes:
            raise _cache_error()


class RemoteAuditLog:
    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        max_bytes: int = REMOTE_AUDIT_MAX_BYTES,
        max_segments: int = REMOTE_AUDIT_MAX_SEGMENTS,
    ) -> None:
        self.path = path
        self.clock = clock
        self.max_bytes = max_bytes
        self.max_segments = max_segments

    def record(
        self,
        event: str,
        *,
        challenge_id: str,
        operation_id: str | None = None,
        canonical_url: str | None = None,
        requested_ref: str | None = None,
        resolved_commit: str | None = None,
        outcome: str | None = None,
        error_code: str | None = None,
        cleanup_status: str | None = None,
        cache_status: str | None = None,
        resource_usage: Mapping[str, object] | None = None,
    ) -> None:
        record = self._build_record(
            event,
            challenge_id=challenge_id,
            operation_id=operation_id,
            canonical_url=canonical_url,
            requested_ref=requested_ref,
            resolved_commit=resolved_commit,
            outcome=outcome,
            error_code=error_code,
            cleanup_status=cleanup_status,
            cache_status=cache_status,
            resource_usage=resource_usage,
        )
        line = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        if len(line) > self.max_bytes:
            raise _audit_error()
        try:
            with locked_cache_file(self.path):
                current_size = self.path.stat().st_size if self.path.exists() else 0
                if current_size + len(line) > self.max_bytes:
                    self._rotate_unlocked()
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("ab") as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
        except RemoteStateError:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise _audit_error() from error

    def _build_record(self, event: str, **values: object) -> dict[str, Any]:
        if event not in _AUDIT_EVENTS:
            raise _audit_error()
        challenge_id = _identifier(values.get("challenge_id"))
        operation_id = _identifier(values.get("operation_id"), optional=True)
        resolved_commit = values.get("resolved_commit")
        if resolved_commit is not None and (
            not isinstance(resolved_commit, str) or not _COMMIT.fullmatch(resolved_commit.lower())
        ):
            raise _audit_error()
        record: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(self.clock(), UTC).isoformat(),
            "event": event,
            "operationId": operation_id,
            "challengeId": challenge_id,
            "canonicalUrlHash": _optional_hash(values.get("canonical_url")),
            "requestedRefHash": _optional_hash(values.get("requested_ref")),
            "resolvedCommit": resolved_commit.lower() if isinstance(resolved_commit, str) else None,
            "hostPolicyVersion": HOST_POLICY_VERSION,
            "resourceLimitProfile": RESOURCE_LIMIT_PROFILE,
            "outcome": _outcome(values.get("outcome")),
            "errorCode": _error_code(values.get("error_code")),
            "cleanupStatus": _outcome(values.get("cleanup_status")),
            "cacheStatus": _outcome(values.get("cache_status")),
            "resourceUsage": _resource_usage(values.get("resource_usage")),
        }
        return record

    def _rotate_unlocked(self) -> None:
        if self.max_segments < 1:
            raise _audit_error()
        oldest = self.path.with_name(f"{self.path.name}.{self.max_segments - 1}")
        if oldest.exists():
            oldest.unlink()
        for index in range(self.max_segments - 2, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            if source.exists():
                source.replace(self.path.with_name(f"{self.path.name}.{index + 1}"))
        if self.path.exists():
            if self.max_segments == 1:
                self.path.unlink()
            else:
                self.path.replace(self.path.with_name(f"{self.path.name}.1"))


def _valid_cache_entry(entry: object) -> bool:
    if not isinstance(entry, dict) or set(entry) != {"key", "createdAt", "expiresAt", "report"}:
        return False
    key = entry.get("key")
    report = entry.get("report")
    return (
        isinstance(key, dict)
        and all(isinstance(name, str) and isinstance(value, str) for name, value in key.items())
        and isinstance(entry.get("createdAt"), (int, float))
        and isinstance(entry.get("expiresAt"), (int, float))
        and isinstance(report, dict)
    )


def _encoded_size(value: object) -> int:
    return len(json.dumps(value, indent=2).encode("utf-8"))


def _json_copy(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value, separators=(",", ":"), sort_keys=True))


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _optional_hash(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise _audit_error()
    return _hash(value)


def _identifier(value: object, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _SAFE_IDENTIFIER.fullmatch(value):
        raise _audit_error()
    return value


def _outcome(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _SAFE_OUTCOME.fullmatch(value):
        raise _audit_error()
    return value


def _error_code(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"MCP_REMOTE_[A-Z_]{1,64}", value):
        raise _audit_error()
    return value


def _resource_usage(value: object) -> dict[str, int]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise _audit_error()
    return {
        name: amount
        for name, amount in value.items()
        if name in _RESOURCE_USAGE_FIELDS and isinstance(amount, int) and not isinstance(amount, bool) and amount >= 0
    }


def _cache_error() -> RemoteStateError:
    return RemoteStateError("MCP_REMOTE_CACHE_FAILED", "The dedicated remote scan cache failed closed.")


def _audit_error() -> RemoteStateError:
    return RemoteStateError("MCP_REMOTE_AUDIT_FAILED", "The redacted remote audit log failed closed.")
