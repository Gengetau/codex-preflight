from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from codex_preflight_core.cache.atomic_json import write_json_atomic
from codex_preflight_core.cache.file_lock import locked_cache_file

TRUST_CACHE_MAX_BYTES = 1024 * 1024
TRUST_CACHE_MAX_MIGRATION_BACKUPS = 3
TRUST_CACHE_ENTRY_VERSION = 1
TRUST_CACHE_SCHEMA = "trust-cache-array-v2"
TRUST_CACHE_MIGRATION_VERSION = "v0.3.3-trust-read-foundation"

_APPROVAL_FIELDS = {
    "repoId",
    "path",
    "remoteUrl",
    "headCommit",
    "criticalFingerprint",
    "commandScope",
    "approvedCommand",
    "decision",
    "approvedAt",
    "expiresAt",
    "approvedBy",
    "policyVersion",
    "rulesetVersion",
}
_METADATA_FIELDS = {"entryId", "entryVersion", "provenance"}
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
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class TrustCacheError(OSError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class TrustCache:
    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], datetime] | None = None,
        entry_id_factory: Callable[[], str] | None = None,
        max_bytes: int = TRUST_CACHE_MAX_BYTES,
    ) -> None:
        self.path = path
        self.clock = clock or (lambda: datetime.now(UTC))
        self.entry_id_factory = entry_id_factory or (lambda: str(uuid4()))
        self.max_bytes = max_bytes

    def list(self, *, event_hook: Callable[[str], None] | None = None) -> list[dict[str, Any]]:
        with locked_cache_file(self.path):
            entries = self._read_all_unlocked(event_hook=event_hook)
            now = self._now()
            return [deepcopy(entry) for entry in entries if _timestamp(entry["expiresAt"]) > now]

    def approve(
        self,
        *,
        repo_id: str,
        path: Path,
        remote_url: str | None,
        head_commit: str | None,
        critical_fingerprint: str,
        command_scope: str,
        approved_command: str,
        expires_at: datetime,
        policy_version: str = "default-v1",
        ruleset_version: str = "2026.07.02",
    ) -> None:
        with locked_cache_file(self.path):
            entries = self._read_all_unlocked()
            now = self._now()
            entries = [entry for entry in entries if _timestamp(entry["expiresAt"]) > now]
            created_at = now.isoformat()
            entry = {
                "repoId": repo_id,
                "path": str(path),
                "remoteUrl": remote_url,
                "headCommit": head_commit,
                "criticalFingerprint": critical_fingerprint,
                "commandScope": command_scope,
                "approvedCommand": approved_command,
                "decision": "USER_APPROVED",
                "approvedAt": created_at,
                "expiresAt": expires_at.isoformat(),
                "approvedBy": "local-user",
                "policyVersion": policy_version,
                "rulesetVersion": ruleset_version,
                "entryId": self.entry_id_factory(),
                "entryVersion": TRUST_CACHE_ENTRY_VERSION,
                "provenance": {
                    "schema": TRUST_CACHE_SCHEMA,
                    "source": "cli-trust-approve",
                    "migrationVersion": TRUST_CACHE_MIGRATION_VERSION,
                    "createdAt": created_at,
                },
            }
            _validate_entry(entry, migrated=False)
            entries.append(entry)
            self._write_unlocked(entries)

    def match(
        self,
        *,
        repo_id: str,
        head_commit: str | None,
        critical_fingerprint: str,
        command_scope: str,
        policy_version: str = "default-v1",
        ruleset_version: str = "2026.07.02",
    ) -> dict[str, Any] | None:
        for entry in self.list():
            if (
                entry["repoId"] == repo_id
                and entry["headCommit"] == head_commit
                and entry["criticalFingerprint"] == critical_fingerprint
                and entry["commandScope"] == command_scope
                and entry["policyVersion"] == policy_version
                and entry["rulesetVersion"] == ruleset_version
            ):
                return entry
        return None

    def revoke_identity(self, repo_id: str, command_scope: str | None = None) -> int:
        with locked_cache_file(self.path):
            entries = self._read_all_unlocked()
            now = self._now()
            live_entries = [entry for entry in entries if _timestamp(entry["expiresAt"]) > now]
            kept = [
                entry
                for entry in live_entries
                if not (
                    entry["repoId"] == repo_id
                    and (command_scope is None or entry["commandScope"] == command_scope)
                )
            ]
            removed = len(live_entries) - len(kept)
            self._write_unlocked(kept)
            return removed

    def _read_all_unlocked(self, *, event_hook: Callable[[str], None] | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            _notify(event_hook, "trust_file_missing")
            return []
        try:
            size = self.path.stat().st_size
            if size > self.max_bytes:
                raise TrustCacheError("unavailable", "The local trust store exceeds its read limit.")
            raw = self.path.read_bytes()
        except TrustCacheError:
            raise
        except OSError as error:
            raise TrustCacheError("unavailable", "The local trust store could not be read safely.") from error
        if len(raw) > self.max_bytes:
            raise TrustCacheError("unavailable", "The local trust store exceeds its read limit.")
        try:
            payload = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise TrustCacheError("corrupt", "The local trust store is corrupt.") from error
        if not isinstance(payload, list):
            raise TrustCacheError("unsupported-schema", "The local trust store schema is unsupported.")
        if not payload:
            _notify(event_hook, "trust_file_empty")

        entries: list[dict[str, Any]] = []
        legacy_indexes: list[int] = []
        for index, value in enumerate(payload):
            if not isinstance(value, dict):
                raise TrustCacheError("corrupt", "The local trust store contains an invalid entry.")
            entry = deepcopy(value)
            metadata_names = _METADATA_FIELDS.intersection(entry)
            if not metadata_names:
                _validate_entry(entry, migrated=None)
                legacy_indexes.append(index)
            elif metadata_names != _METADATA_FIELDS:
                if entry.get("entryVersion") not in {None, TRUST_CACHE_ENTRY_VERSION}:
                    raise TrustCacheError("unsupported-schema", "The trust entry version is unsupported.")
                raise TrustCacheError("corrupt", "The local trust store contains partial metadata.")
            else:
                _validate_entry(entry, migrated=False)
            entries.append(entry)

        _validate_unique_entry_ids(entries)
        if legacy_indexes:
            _notify(event_hook, "migration_started")
            try:
                entries = self._migrate_unlocked(entries, legacy_indexes, raw)
            except BaseException:
                _notify(event_hook, "migration_failed")
                raise
            _notify(event_hook, "migration_completed")
        return entries

    def _migrate_unlocked(
        self,
        entries: list[dict[str, Any]],
        legacy_indexes: list[int],
        original: bytes,
    ) -> list[dict[str, Any]]:
        self._create_backup_unlocked(original)
        migrated_at = self._now().isoformat()
        try:
            for index in legacy_indexes:
                entries[index]["entryId"] = self.entry_id_factory()
                entries[index]["entryVersion"] = TRUST_CACHE_ENTRY_VERSION
                entries[index]["provenance"] = {
                    "schema": TRUST_CACHE_SCHEMA,
                    "source": "legacy-migration",
                    "migrationVersion": TRUST_CACHE_MIGRATION_VERSION,
                    "migratedAt": migrated_at,
                }
                _validate_entry(entries[index], migrated=True)
            _validate_unique_entry_ids(entries)
            self._write_unlocked(entries)
        except Exception as error:
            raise TrustCacheError("migration-failed", "The trust metadata migration failed closed.") from error
        self._prune_backups_unlocked()
        return entries

    def _create_backup_unlocked(self, original: bytes) -> None:
        timestamp = self._now().strftime("%Y%m%dT%H%M%S%fZ")
        backup = self.path.with_name(
            f"{self.path.name}.v0.3.3-migration.{timestamp}.{uuid4().hex[:16]}.bak"
        )
        try:
            with backup.open("xb") as handle:
                handle.write(original)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(backup, stat.S_IMODE(self.path.stat().st_mode))
        except OSError as error:
            try:
                backup.unlink(missing_ok=True)
            except OSError:
                pass
            raise TrustCacheError("migration-failed", "The trust metadata backup failed closed.") from error

    def _prune_backups_unlocked(self) -> None:
        backups = sorted(self.path.parent.glob(f"{self.path.name}.v0.3.3-migration.*.bak"))
        try:
            for backup in backups[:-TRUST_CACHE_MAX_MIGRATION_BACKUPS]:
                backup.unlink()
        except OSError as error:
            raise TrustCacheError("migration-failed", "Trust migration backup retention failed closed.") from error

    def _write_unlocked(self, entries: list[dict[str, Any]]) -> None:
        try:
            encoded = json.dumps(entries, indent=2).replace("\n", os.linesep).encode("utf-8")
            if len(encoded) > self.max_bytes:
                raise TrustCacheError("unavailable", "The local trust store exceeds its size limit.")
            write_json_atomic(self.path, entries)
            if self.path.stat().st_size > self.max_bytes:
                raise TrustCacheError("unavailable", "The local trust store exceeds its size limit.")
        except TrustCacheError:
            raise
        except OSError as error:
            raise TrustCacheError("unavailable", "The local trust store could not be written safely.") from error

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None:
            raise TrustCacheError("corrupt", "The trust cache clock must be timezone aware.")
        return value.astimezone(UTC)


def _validate_entry(entry: dict[str, Any], *, migrated: bool | None) -> None:
    expected = _APPROVAL_FIELDS if migrated is None else _APPROVAL_FIELDS | _METADATA_FIELDS
    if set(entry) != expected:
        code = "unsupported-schema" if set(entry) - expected else "corrupt"
        raise TrustCacheError(code, "The local trust store entry schema is invalid.")
    for name in (
        "repoId",
        "path",
        "approvedCommand",
        "decision",
        "approvedBy",
        "policyVersion",
        "rulesetVersion",
    ):
        _bounded_string(entry.get(name))
    remote_url = entry.get("remoteUrl")
    if remote_url is not None:
        _bounded_string(remote_url)
    if entry["decision"] != "USER_APPROVED" or entry["approvedBy"] != "local-user":
        raise TrustCacheError("corrupt", "The local trust store approval metadata is invalid.")
    head_commit = entry.get("headCommit")
    if head_commit is not None and (not isinstance(head_commit, str) or not _COMMIT.fullmatch(head_commit)):
        raise TrustCacheError("corrupt", "The local trust store commit identity is invalid.")
    fingerprint = entry.get("criticalFingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise TrustCacheError("corrupt", "The local trust store fingerprint is invalid.")
    if entry.get("commandScope") not in _COMMAND_SCOPES:
        raise TrustCacheError("corrupt", "The local trust store command scope is invalid.")
    _timestamp(entry.get("approvedAt"))
    _timestamp(entry.get("expiresAt"))

    if migrated is None:
        return
    if entry.get("entryVersion") != TRUST_CACHE_ENTRY_VERSION:
        raise TrustCacheError("unsupported-schema", "The trust entry version is unsupported.")
    entry_id = entry.get("entryId")
    if not isinstance(entry_id, str):
        raise TrustCacheError("corrupt", "The trust entry identifier is invalid.")
    try:
        parsed_id = UUID(entry_id)
    except (ValueError, AttributeError) as error:
        raise TrustCacheError("corrupt", "The trust entry identifier is invalid.") from error
    if parsed_id.version != 4 or str(parsed_id) != entry_id:
        raise TrustCacheError("corrupt", "The trust entry identifier is invalid.")
    provenance = entry.get("provenance")
    if not isinstance(provenance, dict):
        raise TrustCacheError("corrupt", "The trust entry provenance is invalid.")
    source = provenance.get("source")
    timestamp_name = "migratedAt" if source == "legacy-migration" else "createdAt"
    if source not in {"legacy-migration", "cli-trust-approve"} or set(provenance) != {
        "schema",
        "source",
        "migrationVersion",
        timestamp_name,
    }:
        raise TrustCacheError("corrupt", "The trust entry provenance is invalid.")
    if (
        provenance["schema"] != TRUST_CACHE_SCHEMA
        or provenance["migrationVersion"] != TRUST_CACHE_MIGRATION_VERSION
    ):
        raise TrustCacheError("unsupported-schema", "The trust entry provenance schema is unsupported.")
    _timestamp(provenance[timestamp_name])


def _bounded_string(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or _CONTROL.search(value)
    ):
        raise TrustCacheError("corrupt", "The local trust store contains an invalid string field.")
    return value


def _timestamp(value: object) -> datetime:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 4096
        or _CONTROL.search(value)
        or not _RFC3339.fullmatch(value)
    ):
        raise TrustCacheError("corrupt", "The local trust store timestamp is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise TrustCacheError("corrupt", "The local trust store timestamp is invalid.") from error
    if parsed.tzinfo is None:
        raise TrustCacheError("corrupt", "The local trust store timestamp is invalid.")
    return parsed.astimezone(UTC)


def _validate_unique_entry_ids(entries: list[dict[str, Any]]) -> None:
    entry_ids = [entry["entryId"] for entry in entries if "entryId" in entry]
    if len(entry_ids) != len(set(entry_ids)):
        raise TrustCacheError("corrupt", "The local trust store contains duplicate entry identifiers.")


def _notify(event_hook: Callable[[str], None] | None, event: str) -> None:
    if event_hook is not None:
        event_hook(event)
