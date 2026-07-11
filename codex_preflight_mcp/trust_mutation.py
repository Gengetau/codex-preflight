from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from codex_preflight_core.cache.file_lock import (
    CacheLockTimeoutError,
    UnsafeCacheStorageError,
    locked_cache_file,
    validate_private_cache_storage,
)
from codex_preflight_core.cache.paths import (
    trust_cache_path,
    trust_mutation_audit_key_path,
    trust_mutation_audit_path,
)
from codex_preflight_core.cache.trust_cache import (
    TrustCache,
    TrustCacheError,
    TrustCacheMutationCommitError,
    TrustCacheMutationPlan,
    TrustCacheMutationPrepared,
    TrustCacheMutationResult,
    TrustCacheMutationWriteError,
)
from codex_preflight_core.command.classifier import classify_command
from codex_preflight_core.preflight import POLICY_VERSION, RULESET_VERSION
from codex_preflight_core.repo.fingerprint import CriticalFingerprintError, compute_critical_fingerprint
from codex_preflight_core.repo.identity import RepoIdentity, RepoIdentityError, resolve_repo_identity
from codex_preflight_mcp.trust_mutation_audit import (
    AuditContext,
    PreparedMutation,
    TrustMutationAuditError,
    TrustMutationAuditLog,
)
from codex_preflight_mcp.trust_mutation_confirmation import (
    ConsumedMutationChallenge,
    TrustMutationChallenge,
    TrustMutationConfirmationError,
    TrustMutationConfirmationManager,
)
from codex_preflight_mcp.trust_read import _public_entry
from codex_preflight_mcp.trust_state import privacy_hash

CONFIRMATION_SCHEMA_VERSION = "trust-mutation-confirmation/v1"
TRUST_APPROVE_SCHEMA_VERSION = "trust-approve/v1"
TRUST_REVOKE_SCHEMA_VERSION = "trust-revoke/v1"
TRUST_MUTATION_TIMEOUT_SECONDS = 30.0
TRUST_MUTATION_MAX_FILES = 4096
TRUST_MUTATION_MAX_FILE_BYTES = 8 * 1024 * 1024
TRUST_MUTATION_MAX_TOTAL_BYTES = 64 * 1024 * 1024

RUNTIME_IDENTITY = {
    "transport": "stdio",
    "identityStatus": "unavailable",
    "clientId": None,
    "sessionId": None,
}
MUTATION_SAFETY = {
    "plannedCommandExecuted": False,
    "repositoryCodeExecuted": False,
    "networkAccessed": False,
    "remoteConfirmationUsed": False,
    "trustConsumed": False,
    "mcpPreflightUsesTrust": False,
    "rawRepoIdReturned": False,
    "rawPathReturned": False,
    "rawRemoteUrlReturned": False,
    "approvedCommandReturned": False,
    "reasonReturned": False,
}

MISSING = object()
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SUPPORTED_SCOPES = {
    "dependency_install",
    "script_execution",
    "build",
    "test",
    "docker",
    "network_shell",
    "mcp_server_start",
    "unknown_shell",
}


class TrustMutationError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        field: str | None = None,
        retryable: bool = False,
        remediation: str | None = None,
        safety_boundary: str | None = None,
        context: Mapping[str, object] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.field = field
        self.retryable = retryable
        self.remediation = remediation
        self.safety_boundary = safety_boundary
        self.context = dict(context) if context is not None else {"runtimeIdentity": dict(RUNTIME_IDENTITY)}
        super().__init__(message)


class _TargetDrift(RuntimeError):
    pass


class TrustMutationService:
    def __init__(
        self,
        *,
        cache: TrustCache | None = None,
        audit: TrustMutationAuditLog | object | None = None,
        confirmation: TrustMutationConfirmationManager | None = None,
        privacy_key: bytes | None = None,
        identity_resolver: Callable[..., RepoIdentity] = resolve_repo_identity,
        fingerprinter: Callable[..., str] = compute_critical_fingerprint,
        policy_version: str | Callable[[], str] = POLICY_VERSION,
        ruleset_version: str | Callable[[], str] = RULESET_VERSION,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        cancellation_check: Callable[[], bool] | None = None,
        entry_id_factory: Callable[[], str] | None = None,
        operation_id_factory: Callable[[], str] | None = None,
        prepared_event_id_factory: Callable[[], str] | None = None,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.cache = cache
        self.audit = audit
        self.confirmation = confirmation
        self.privacy_key = privacy_key
        self.identity_resolver = identity_resolver
        self.fingerprinter = fingerprinter
        self.policy_version = policy_version
        self.ruleset_version = ruleset_version
        self.clock = clock
        self.monotonic = monotonic
        self.cancellation_check = cancellation_check
        self.entry_id_factory = entry_id_factory or (lambda: str(uuid4()))
        self.operation_id_factory = operation_id_factory or (lambda: str(uuid4()))
        self.prepared_event_id_factory = prepared_event_id_factory or (lambda: str(uuid4()))
        self._healthy = True
        self._audit_reservation_lock = threading.RLock()
        if enabled and (cache is None or audit is None or confirmation is None or privacy_key is None):
            raise ValueError("enabled trust mutation service requires local dependencies")
        if privacy_key is not None and (type(privacy_key) is not bytes or len(privacy_key) < 32):
            raise ValueError("privacy_key must contain at least 32 bytes")

    def record_registration_state(self) -> str:
        self._ensure_active()
        operation_id = self._new_uuid(self.operation_id_factory)
        return self._record(
            "registration_state",
            self._audit_context("approve", operation_id, outcome="enabled"),
        )

    def recover_startup(self) -> object:
        self._ensure_enabled()
        assert self.cache is not None
        assert self.audit is not None

        def read_store_bytes() -> bytes | None:
            assert self.cache is not None
            with locked_cache_file(self.cache.path, private_storage=True):
                return self.cache._read_store_bytes_unlocked()

        try:
            with self._audit_reservation_lock:
                result = self.audit.verify_and_recover(  # type: ignore[union-attr]
                    read_store_bytes=read_store_bytes,
                )
        except CacheLockTimeoutError as error:
            self._healthy = False
            raise self._error(
                "MCP_TRUST_MUTATION_LOCK_TIMEOUT",
                "The local trust-store lock timed out.",
            ) from error
        except TrustMutationAuditError as error:
            self._healthy = False
            raise self._audit_error(error) from None
        except Exception:
            self._healthy = False
            raise self._error(
                "MCP_TRUST_MUTATION_RECOVERY_REQUIRED",
                "Trust mutation recovery requires known-good local state.",
            ) from None
        self._healthy = True
        return result

    def approve(
        self,
        *,
        cwd: object = MISSING,
        command: object = MISSING,
        expires_at: object = MISSING,
        reason: object = MISSING,
        confirmation_token: object = MISSING,
        **extras: object,
    ) -> dict[str, object]:
        self._ensure_active()
        if confirmation_token is MISSING:
            self._issue_approval(cwd, command, expires_at, reason, extras)
        return self._run_confirmed(
            lambda: self._confirm_approval(cwd, command, expires_at, reason, confirmation_token, extras)
        )

    def revoke(
        self,
        *,
        trust_entry_id: object = MISSING,
        expected_version: object = MISSING,
        reason: object = MISSING,
        confirmation_token: object = MISSING,
        **extras: object,
    ) -> dict[str, object]:
        self._ensure_active()
        if confirmation_token is MISSING:
            self._issue_revoke(trust_entry_id, expected_version, reason, extras)
        return self._run_confirmed(
            lambda: self._confirm_revoke(trust_entry_id, expected_version, reason, confirmation_token, extras)
        )

    def _run_confirmed(self, callback: Callable[[], dict[str, object]]) -> dict[str, object]:
        result: dict[str, object] | None = None
        failure: TrustMutationError | None = None
        try:
            result = callback()
        except TrustMutationError as error:
            failure = error
        except Exception:
            failure = self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation could not be completed.",
                retryable=True,
            )
        if failure is not None:
            failure.__cause__ = None
            failure.__context__ = None
            failure.__suppress_context__ = True
            failure.__traceback__ = None
            raise failure
        if result is None:
            raise self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation could not be completed.",
                retryable=True,
            )
        return result

    def _issue_approval(
        self,
        cwd: object,
        command: object,
        expires_at: object,
        reason: object,
        extras: Mapping[str, object],
    ) -> None:
        operation_id = self._new_uuid(self.operation_id_factory)
        try:
            request = self._validate_approval_request(cwd, command, expires_at, reason, extras, self._wall_time())
        except TrustMutationError as error:
            self._record_validation_failure("approve", operation_id, error)
            raise
        self._record("request_validated", self._audit_context("approve", operation_id, outcome="validated"))
        deadline = self._deadline()
        try:
            target = self._derive_approval_target(request, deadline=deadline, include_store=True)
        except TrustMutationError as error:
            self._record_terminal_failure("approve", operation_id, error)
            raise
        self._record(
            "identity_resolved",
            self._audit_context("approve", operation_id, target=target, outcome="resolved"),
        )
        entry_id = self._new_uuid(self.entry_id_factory)
        prepared_event_id = self._new_uuid(self.prepared_event_id_factory)
        binding = self._approval_binding(request, target, operation_id, entry_id, prepared_event_id)
        display = self._approval_display(request, target)
        try:
            assert self.confirmation is not None
            challenge = self.confirmation.issue("approve", binding, display, proposed_entry_id=entry_id)
        except TrustMutationConfirmationError as error:
            mapped = self._confirmation_issue_error(error)
            self._record(
                "challenge_rejected",
                self._audit_context(
                    "approve",
                    operation_id,
                    target=target,
                    entry_id=entry_id,
                    outcome="rejected",
                    error_code=mapped.code,
                ),
            )
            raise mapped from None
        confirmation = self._challenge_context(challenge)
        self._record(
            "challenge_issued",
            self._audit_context(
                "approve",
                operation_id,
                target=target,
                entry_id=entry_id,
                challenge_id=str(confirmation["challengeId"]),
                outcome="issued",
            ),
        )
        raise self._error(
            "MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED",
            "Human confirmation is required for this exact trust mutation.",
            field="confirmationToken",
            remediation=(
                "Present the fixed confirmation display to a human, then retry once with the returned "
                "confirmationToken only if the human approves it."
            ),
            safety_boundary="No trust approval or revocation has occurred.",
            context={"confirmation": confirmation},
        )

    def _issue_revoke(
        self,
        trust_entry_id: object,
        expected_version: object,
        reason: object,
        extras: Mapping[str, object],
    ) -> None:
        operation_id = self._new_uuid(self.operation_id_factory)
        try:
            request = self._validate_revoke_request(trust_entry_id, expected_version, reason, extras)
        except TrustMutationError as error:
            self._record_validation_failure("revoke", operation_id, error)
            raise
        self._record("request_validated", self._audit_context("revoke", operation_id, outcome="validated"))
        deadline = self._deadline()
        try:
            target = self._derive_revoke_target(request, deadline=deadline)
        except TrustMutationError as error:
            if error.code == "MCP_TRUST_MUTATION_NOT_FOUND":
                self._record(
                    "target_not_visible",
                    self._audit_context(
                        "revoke",
                        operation_id,
                        entry_id=request["entryId"],
                        outcome="not-visible",
                        error_code=error.code,
                    ),
                )
            else:
                self._record_terminal_failure("revoke", operation_id, error, entry_id=request["entryId"])
            raise
        binding = self._revoke_binding(request, target, operation_id)
        display = {
            "template": "revoke-exact-trust-entry/v1",
            "repositoryContentTrust": "untrusted",
            "trustEntry": _public_entry(target["entry"], self._privacy_key()),
            "expectedVersion": 1,
            "reason": request["reason"],
        }
        try:
            assert self.confirmation is not None
            challenge = self.confirmation.issue(
                "revoke",
                binding,
                display,
                proposed_entry_id=request["entryId"],
            )
        except TrustMutationConfirmationError as error:
            mapped = self._confirmation_issue_error(error)
            self._record(
                "challenge_rejected",
                self._audit_context(
                    "revoke",
                    operation_id,
                    target=target,
                    entry_id=request["entryId"],
                    outcome="rejected",
                    error_code=mapped.code,
                ),
            )
            raise mapped from None
        confirmation = self._challenge_context(challenge)
        self._record(
            "challenge_issued",
            self._audit_context(
                "revoke",
                operation_id,
                target=target,
                entry_id=request["entryId"],
                challenge_id=str(confirmation["challengeId"]),
                outcome="issued",
            ),
        )
        raise self._error(
            "MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED",
            "Human confirmation is required for this exact trust mutation.",
            field="confirmationToken",
            remediation=(
                "Present the fixed confirmation display to a human, then retry once with the returned "
                "confirmationToken only if the human approves it."
            ),
            safety_boundary="No trust approval or revocation has occurred.",
            context={"confirmation": confirmation},
        )

    def _confirm_approval(
        self,
        cwd: object,
        command: object,
        expires_at: object,
        reason: object,
        token: object,
        extras: Mapping[str, object],
    ) -> dict[str, object]:
        consumed, binding, operation_id = self._consume("approve", token)
        try:
            request = self._validate_approval_request(cwd, command, expires_at, reason, extras, consumed.issued_at)
        except TrustMutationError as error:
            self._record_validation_failure("approve", operation_id, error, consumed=consumed, binding=binding)
            raise
        deadline = self._deadline()
        try:
            target = self._derive_approval_target(request, deadline=deadline, include_store=True)
            expected = self._approval_binding(
                request,
                target,
                operation_id,
                self._bound_uuid(binding, "entryId"),
                self._bound_uuid(binding, "preparedAuditEventId"),
            )
            if not _same_binding(binding, expected):
                raise _TargetDrift
        except _TargetDrift:
            error = self._error(
                "MCP_TRUST_MUTATION_TARGET_DRIFT",
                "The approved trust target changed before mutation.",
            )
            self._record_terminal_failure("approve", operation_id, error, consumed=consumed, binding=binding)
            raise error from None
        except TrustMutationError as error:
            self._record_terminal_failure("approve", operation_id, error, consumed=consumed, binding=binding)
            raise

        entry_id = self._bound_uuid(binding, "entryId")
        prepared_event_id = self._bound_uuid(binding, "preparedAuditEventId")
        challenge_id = _canonical_challenge_id(consumed.challenge_id)
        context = self._audit_context(
            "approve",
            operation_id,
            target=target,
            entry_id=entry_id,
            challenge_id=challenge_id,
            outcome="pending",
        )

        def revalidate(before_bytes: bytes | None) -> None:
            revalidated = self._derive_approval_target(request, deadline=deadline, include_store=False)
            if self._target_binding(revalidated) != self._target_binding(target):
                raise _TargetDrift
            if _store_digest(before_bytes) != target["storeDigest"]:
                raise _TargetDrift

        def prepare(plan: TrustCacheMutationPlan) -> TrustCacheMutationPrepared:
            if plan.planned_event_id != prepared_event_id:
                raise _TargetDrift
            prepared = self._prepare_audit(
                operation="approve",
                plan=plan,
                entry_id=entry_id,
                context=context,
                expected_event_id=prepared_event_id,
                reservation=audit_reservation,
            )
            return TrustCacheMutationPrepared(prepared.event_id, prepared)

        def commit(prepared: TrustCacheMutationPrepared) -> str:
            if not isinstance(prepared.state, PreparedMutation):
                raise TrustMutationAuditError(
                    "MCP_TRUST_MUTATION_AUDIT_FAILED",
                    "The trust mutation audit operation failed closed.",
                )
            return self._commit_audit(prepared.state, context=context, reservation=audit_reservation)

        try:
            assert self.cache is not None
            with self._audit_reservation_lock:
                with self._audit_transaction() as audit_reservation:
                    result = self.cache.approve_mcp(
                        repo_id=target["repoId"],
                        path=target["root"],
                        remote_url=target["remoteUrl"],
                        head_commit=target["headCommit"],
                        critical_fingerprint=target["criticalFingerprint"],
                        command_scope=target["commandScope"],
                        approved_command=request["command"],
                        expires_at=request["expiresAt"],
                        policy_version=target["policyVersion"],
                        ruleset_version=target["rulesetVersion"],
                        entry_id=entry_id,
                        approved_at=_utc_timestamp(consumed.issued_at),
                        approval_reason=request["reason"],
                        mutation_audit_event_id=prepared_event_id,
                        prepare=prepare,
                        commit=commit,
                        private_storage=True,
                        revalidate=revalidate,
                    )
        except TrustCacheMutationCommitError as error:
            self._mark_unhealthy()
            raise self._committed_pending_error(error.result) from None
        except TrustCacheMutationWriteError as error:
            self._mark_unhealthy()
            raise self._cache_error(error) from None
        except _TargetDrift:
            error = self._error(
                "MCP_TRUST_MUTATION_TARGET_DRIFT",
                "The approved trust target changed before mutation.",
            )
            self._record_terminal_failure("approve", operation_id, error, consumed=consumed, binding=binding)
            raise error from None
        except TrustMutationAuditError as error:
            mapped = self._audit_error(error)
            self._record_terminal_failure("approve", operation_id, mapped, consumed=consumed, binding=binding)
            raise mapped from None
        except (CacheLockTimeoutError, TrustCacheError, OSError) as error:
            mapped = self._cache_error(error)
            self._record_terminal_failure("approve", operation_id, mapped, consumed=consumed, binding=binding)
            raise mapped from None
        except Exception:
            mapped = self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation could not be completed.",
                retryable=True,
            )
            self._record_terminal_failure("approve", operation_id, mapped, consumed=consumed, binding=binding)
            raise mapped from None
        return self._approval_result(result, consumed)

    def _confirm_revoke(
        self,
        trust_entry_id: object,
        expected_version: object,
        reason: object,
        token: object,
        extras: Mapping[str, object],
    ) -> dict[str, object]:
        consumed, binding, operation_id = self._consume("revoke", token)
        try:
            request = self._validate_revoke_request(trust_entry_id, expected_version, reason, extras)
        except TrustMutationError as error:
            self._record_validation_failure("revoke", operation_id, error, consumed=consumed, binding=binding)
            raise
        deadline = self._deadline()
        try:
            target = self._derive_revoke_target(request, deadline=deadline)
        except TrustMutationError as error:
            if error.code == "MCP_TRUST_MUTATION_NOT_FOUND":
                self._record(
                    "mutation_noop",
                    self._audit_context(
                        "revoke",
                        operation_id,
                        entry_id=request["entryId"],
                        challenge_id=_canonical_challenge_id(consumed.challenge_id),
                        outcome="not-found",
                        error_code=error.code,
                    ),
                )
            else:
                self._record_terminal_failure("revoke", operation_id, error, consumed=consumed, binding=binding)
            raise
        expected = self._revoke_binding(request, target, operation_id)
        if not _same_binding(binding, expected):
            error = self._error(
                "MCP_TRUST_MUTATION_TARGET_DRIFT",
                "The approved trust target changed before mutation.",
            )
            self._record_terminal_failure("revoke", operation_id, error, consumed=consumed, binding=binding)
            raise error from None
        expected_entry = _thaw(binding.get("expectedEntry"))
        if not isinstance(expected_entry, dict):
            error = self._error(
                "MCP_TRUST_MUTATION_CONFIRMATION_INVALID",
                "The trust mutation confirmation token is invalid.",
            )
            self._record_terminal_failure("revoke", operation_id, error, consumed=consumed, binding=binding)
            raise error
        entry_id = self._bound_uuid(binding, "entryId")
        challenge_id = _canonical_challenge_id(consumed.challenge_id)
        context = self._audit_context(
            "revoke",
            operation_id,
            target=target,
            entry_id=entry_id,
            challenge_id=challenge_id,
            outcome="pending",
        )

        def prepare(plan: TrustCacheMutationPlan) -> TrustCacheMutationPrepared:
            if _store_digest(plan.before_bytes) != target["storeDigest"]:
                raise _TargetDrift
            prepared = self._prepare_audit(
                operation="revoke",
                plan=plan,
                entry_id=entry_id,
                context=context,
                expected_event_id=None,
                reservation=audit_reservation,
            )
            return TrustCacheMutationPrepared(prepared.event_id, prepared)

        def commit(prepared: TrustCacheMutationPrepared) -> str:
            if not isinstance(prepared.state, PreparedMutation):
                raise TrustMutationAuditError(
                    "MCP_TRUST_MUTATION_AUDIT_FAILED",
                    "The trust mutation audit operation failed closed.",
                )
            return self._commit_audit(prepared.state, context=context, reservation=audit_reservation)

        try:
            assert self.cache is not None
            with self._audit_reservation_lock:
                with self._audit_transaction() as audit_reservation:
                    result = self.cache.revoke_entry_id(
                        entry_id,
                        expected_version=1,
                        expected_entry=expected_entry,
                        prepare=prepare,
                        commit=commit,
                        private_storage=True,
                    )
        except TrustCacheMutationCommitError as error:
            self._mark_unhealthy()
            raise self._committed_pending_error(error.result) from None
        except TrustCacheMutationWriteError as error:
            self._mark_unhealthy()
            raise self._cache_error(error) from None
        except _TargetDrift:
            error = self._error(
                "MCP_TRUST_MUTATION_TARGET_DRIFT",
                "The approved trust target changed before mutation.",
            )
            self._record_terminal_failure("revoke", operation_id, error, consumed=consumed, binding=binding)
            raise error from None
        except TrustMutationAuditError as error:
            mapped = self._audit_error(error)
            self._record_terminal_failure("revoke", operation_id, mapped, consumed=consumed, binding=binding)
            raise mapped from None
        except (CacheLockTimeoutError, TrustCacheError, OSError) as error:
            mapped = self._cache_error(error)
            self._record_terminal_failure("revoke", operation_id, mapped, consumed=consumed, binding=binding)
            raise mapped from None
        except Exception:
            mapped = self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation could not be completed.",
                retryable=True,
            )
            self._record_terminal_failure("revoke", operation_id, mapped, consumed=consumed, binding=binding)
            raise mapped from None
        if result.outcome == "not-found":
            error = self._error(
                "MCP_TRUST_MUTATION_NOT_FOUND",
                "The requested trust entry is not available.",
            )
            self._record(
                "mutation_noop",
                self._audit_context(
                    "revoke",
                    operation_id,
                    target=target,
                    entry_id=entry_id,
                    challenge_id=challenge_id,
                    outcome="not-found",
                    error_code=error.code,
                ),
            )
            raise error
        if result.outcome == "version-conflict":
            error = self._error(
                "MCP_TRUST_MUTATION_VERSION_CONFLICT",
                "The requested trust entry changed before mutation.",
            )
            self._record_terminal_failure("revoke", operation_id, error, consumed=consumed, binding=binding)
            raise error
        return self._revoke_result(result, consumed)

    def _consume(
        self,
        expected_operation: str,
        token: object,
    ) -> tuple[ConsumedMutationChallenge, dict[str, object], str]:
        try:
            assert self.confirmation is not None
            consumed = self.confirmation.authenticate_and_consume(token)
        except TrustMutationConfirmationError:
            raise self._error(
                "MCP_TRUST_MUTATION_CONFIRMATION_INVALID",
                "The trust mutation confirmation token is invalid.",
            ) from None
        binding = _thaw(consumed.binding)
        if not isinstance(binding, dict):
            raise self._error(
                "MCP_TRUST_MUTATION_CONFIRMATION_INVALID",
                "The trust mutation confirmation token is invalid.",
            )
        try:
            operation_id = self._bound_uuid(binding, "operationId")
            operation = str(binding["operation"])
            tool = str(binding["tool"])
        except (KeyError, TypeError, TrustMutationError):
            raise self._error(
                "MCP_TRUST_MUTATION_CONFIRMATION_INVALID",
                "The trust mutation confirmation token is invalid.",
            ) from None
        actual_tool = "trust_approve" if consumed.operation == "approve" else "trust_revoke"
        target = self._bound_target(binding)
        self._record(
            "challenge_consumed",
            self._audit_context(
                consumed.operation,
                operation_id,
                target=target,
                entry_id=consumed.proposed_entry_id,
                challenge_id=_canonical_challenge_id(consumed.challenge_id),
                outcome="consumed",
            ),
        )
        if consumed.operation != expected_operation or operation != expected_operation or tool != actual_tool:
            error = self._error(
                "MCP_TRUST_MUTATION_CONFIRMATION_INVALID",
                "The trust mutation confirmation token is invalid.",
            )
            self._record_terminal_failure(consumed.operation, operation_id, error, consumed=consumed, binding=binding)
            raise error
        return consumed, binding, operation_id

    def _validate_approval_request(
        self,
        cwd: object,
        command: object,
        expires_at: object,
        reason: object,
        extras: Mapping[str, object],
        issued_at: float,
    ) -> dict[str, object]:
        if extras:
            raise self._error(
                "MCP_TRUST_MUTATION_INVALID_ARGUMENT",
                "trust_approve received an unsupported argument.",
                field=next(iter(extras)),
            )
        canonical_cwd = self._validate_cwd(cwd)
        command_value = _bounded_text(command, maximum=4096, field="command", allow_empty=False)
        reason_value = _bounded_text(reason, maximum=512, field="reason", allow_empty=False)
        expires_value = _bounded_text(expires_at, maximum=4096, field="expiresAt", allow_empty=False)
        if not _RFC3339_Z.fullmatch(expires_value):
            raise self._invalid_argument("expiresAt")
        try:
            expires = datetime.fromisoformat(expires_value.replace("Z", "+00:00"))
        except ValueError:
            raise self._invalid_argument("expiresAt") from None
        if expires.tzinfo is None:
            raise self._invalid_argument("expiresAt")
        issue_time = datetime.fromtimestamp(issued_at, UTC)
        expires_utc = expires.astimezone(UTC)
        if expires_utc <= issue_time or expires_utc - issue_time > timedelta(days=30):
            raise self._invalid_argument("expiresAt")
        return {
            "cwd": canonical_cwd,
            "command": command_value,
            "expiresAt": expires_value,
            "reason": reason_value,
        }

    def _validate_revoke_request(
        self,
        trust_entry_id: object,
        expected_version: object,
        reason: object,
        extras: Mapping[str, object],
    ) -> dict[str, object]:
        if extras:
            raise self._error(
                "MCP_TRUST_MUTATION_INVALID_ARGUMENT",
                "trust_revoke received an unsupported argument.",
                field=next(iter(extras)),
            )
        try:
            entry_id = _canonical_uuid(trust_entry_id)
        except ValueError:
            raise self._invalid_argument("trustEntryId") from None
        if type(expected_version) is not int or expected_version != 1:
            raise self._invalid_argument("expectedVersion")
        reason_value = _bounded_text(reason, maximum=512, field="reason", allow_empty=False)
        return {"entryId": entry_id, "reason": reason_value}

    def _validate_cwd(self, value: object) -> Path:
        text = _bounded_text(value, maximum=4096, field="cwd", allow_empty=False)
        if (
            "://" in text
            or text.startswith("git@")
            or text.lower().startswith("git clone")
            or _is_nonlocal_windows_path(text)
        ):
            raise self._invalid_argument("cwd")
        try:
            path = Path(text)
            absolute = path.absolute()
            _assert_no_reparse_ancestors(absolute)
            resolved = absolute.resolve(strict=True)
            if not resolved.is_dir():
                raise ValueError("not a local directory")
        except (OSError, RuntimeError, ValueError):
            raise self._invalid_argument("cwd") from None
        return resolved

    def _derive_approval_target(
        self,
        request: Mapping[str, object],
        *,
        deadline: float,
        include_store: bool,
    ) -> dict[str, object]:
        self._check_target(deadline)
        self._ensure_storage_safe()
        cwd = request["cwd"]
        command = request["command"]
        if not isinstance(cwd, Path) or not isinstance(command, str):
            raise self._error("MCP_TRUST_MUTATION_INTERNAL_ERROR", "The trust target is unavailable.")
        try:
            identity = self.identity_resolver(
                cwd,
                deadline=deadline,
                cancellation_check=self.cancellation_check,
                monotonic=self.monotonic,
            )
        except RepoIdentityError as error:
            raise self._identity_error(error) from None
        except Exception:
            raise self._error(
                "MCP_TRUST_MUTATION_IDENTITY_UNRESOLVED",
                "The local trust target identity could not be resolved safely.",
            ) from None
        self._check_target(deadline)
        if not isinstance(identity, RepoIdentity):
            raise self._error(
                "MCP_TRUST_MUTATION_IDENTITY_UNRESOLVED",
                "The local trust target identity could not be resolved safely.",
        )
        try:
            root = identity.path.absolute()
            _assert_no_reparse_ancestors(root)
            root = root.resolve(strict=True)
            if not root.is_dir():
                raise ValueError("missing root")
            repo_id = identity.repo_id
            remote_url = identity.remote_url
            if not isinstance(repo_id, str) or _utf8_length(repo_id) is None or _CONTROL.search(repo_id):
                raise ValueError("invalid repo id")
            if remote_url is not None and (
                not isinstance(remote_url, str) or _utf8_length(remote_url) is None or _CONTROL.search(remote_url)
            ):
                raise ValueError("invalid remote url")
            head_commit = identity.head_commit
            if head_commit is not None and (not isinstance(head_commit, str) or not _COMMIT.fullmatch(head_commit)):
                raise ValueError("invalid head")
        except (OSError, RuntimeError, ValueError):
            raise self._error(
                "MCP_TRUST_MUTATION_IDENTITY_UNRESOLVED",
                "The local trust target identity could not be resolved safely.",
            ) from None
        try:
            fingerprint = self.fingerprinter(
                root,
                command,
                max_files=TRUST_MUTATION_MAX_FILES,
                max_file_bytes=TRUST_MUTATION_MAX_FILE_BYTES,
                max_total_bytes=TRUST_MUTATION_MAX_TOTAL_BYTES,
                deadline=deadline,
                cancellation_check=self.cancellation_check,
                monotonic=self.monotonic,
                strict_safety=True,
            )
        except CriticalFingerprintError as error:
            raise self._fingerprint_error(error) from None
        except Exception:
            raise self._error(
                "MCP_TRUST_MUTATION_IDENTITY_UNRESOLVED",
                "The local trust target identity could not be resolved safely.",
            ) from None
        self._check_target(deadline)
        if not isinstance(fingerprint, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint):
            raise self._error(
                "MCP_TRUST_MUTATION_IDENTITY_UNRESOLVED",
                "The local trust target identity could not be resolved safely.",
            )
        scope = classify_command(command).scope.value
        if scope not in _SUPPORTED_SCOPES:
            raise self._invalid_argument("command")
        policy_version = self._current_version(self.policy_version)
        ruleset_version = self._current_version(self.ruleset_version)
        target: dict[str, object] = {
            "cwd": cwd,
            "root": root,
            "repoId": repo_id,
            "remoteUrl": remote_url,
            "headCommit": head_commit,
            "criticalFingerprint": fingerprint,
            "commandScope": scope,
            "policyVersion": policy_version,
            "rulesetVersion": ruleset_version,
            "targetHash": privacy_hash(repo_id, self._privacy_key()),
        }
        if include_store:
            _entries, raw = self._read_snapshot(deadline)
            target["storeDigest"] = _store_digest(raw)
        return target

    def _derive_revoke_target(self, request: Mapping[str, object], *, deadline: float) -> dict[str, object]:
        self._check_target(deadline)
        self._ensure_storage_safe()
        entries, raw = self._read_snapshot(deadline)
        entry_id = request["entryId"]
        if not isinstance(entry_id, str):
            raise self._error("MCP_TRUST_MUTATION_INTERNAL_ERROR", "The trust target is unavailable.")
        now = datetime.fromtimestamp(self._wall_time(), UTC)
        entry = next(
            (
                candidate
                for candidate in entries
                if candidate.get("entryId") == entry_id and _entry_is_live(candidate, now)
            ),
            None,
        )
        if entry is None:
            raise self._error(
                "MCP_TRUST_MUTATION_NOT_FOUND",
                "The requested trust entry is not available.",
            )
        repo_id = entry.get("repoId")
        if not isinstance(repo_id, str):
            raise self._error("MCP_TRUST_MUTATION_CORRUPT", "The local trust store is corrupt.")
        return {
            "entry": entry,
            "entryDigest": _value_digest(entry),
            "storeDigest": _store_digest(raw),
            "targetHash": privacy_hash(repo_id, self._privacy_key()),
            "commandScope": entry.get("commandScope"),
            "policyVersion": entry.get("policyVersion"),
            "rulesetVersion": entry.get("rulesetVersion"),
        }

    def _read_snapshot(self, deadline: float) -> tuple[list[dict[str, Any]], bytes | None]:
        self._check_target(deadline)
        assert self.cache is not None
        try:
            with locked_cache_file(self.cache.path, private_storage=True):
                snapshot = self.cache._read_snapshot_unlocked()
                entries = [_thaw(entry) for entry in snapshot.entries]
                raw = snapshot.raw_bytes
        except CacheLockTimeoutError as error:
            raise self._error(
                "MCP_TRUST_MUTATION_LOCK_TIMEOUT",
                "The local trust-store lock timed out.",
            ) from error
        except TrustCacheError as error:
            raise self._cache_error(error) from None
        except OSError as error:
            raise self._error(
                "MCP_TRUST_MUTATION_PERSISTENCE_FAILED",
                "The local trust store is unavailable.",
            ) from error
        self._check_target(deadline)
        return entries, raw

    def _approval_binding(
        self,
        request: Mapping[str, object],
        target: Mapping[str, object],
        operation_id: str,
        entry_id: str,
        prepared_event_id: str,
    ) -> dict[str, object]:
        return {
            "schemaVersion": CONFIRMATION_SCHEMA_VERSION,
            "tool": "trust_approve",
            "operation": "approve",
            "operationId": operation_id,
            "entryId": entry_id,
            "preparedAuditEventId": prepared_event_id,
            "request": {
                "cwdDigest": _value_digest(str(request["cwd"])),
                "commandDigest": _value_digest(request["command"]),
                "expiresAt": request["expiresAt"],
                "reasonDigest": _value_digest(request["reason"]),
            },
            "target": self._target_binding(target),
            "storeDigest": target["storeDigest"],
        }

    def _revoke_binding(
        self,
        request: Mapping[str, object],
        target: Mapping[str, object],
        operation_id: str,
    ) -> dict[str, object]:
        return {
            "schemaVersion": CONFIRMATION_SCHEMA_VERSION,
            "tool": "trust_revoke",
            "operation": "revoke",
            "operationId": operation_id,
            "entryId": request["entryId"],
            "expectedVersion": 1,
            "reasonDigest": _value_digest(request["reason"]),
            "entryDigest": target["entryDigest"],
            "expectedEntry": target["entry"],
            "storeDigest": target["storeDigest"],
            "target": self._target_binding(target),
        }

    def _target_binding(self, target: Mapping[str, object]) -> dict[str, object]:
        result = {
            "targetHash": target.get("targetHash"),
            "commandScope": target.get("commandScope"),
            "policyVersion": target.get("policyVersion"),
            "rulesetVersion": target.get("rulesetVersion"),
        }
        if "repoId" in target:
            result.update(
                {
                    "cwdDigest": _value_digest(str(target["cwd"])),
                    "rootDigest": _value_digest(str(target["root"])),
                    "repoIdDigest": _value_digest(target["repoId"]),
                    "remoteUrlDigest": _value_digest(target["remoteUrl"]),
                    "headCommit": target["headCommit"],
                    "criticalFingerprint": target["criticalFingerprint"],
                }
            )
        else:
            result["entryDigest"] = target.get("entryDigest")
        return result

    def _approval_display(self, request: Mapping[str, object], target: Mapping[str, object]) -> dict[str, object]:
        return {
            "template": "approve-exact-local-trust/v1",
            "repositoryContentTrust": "untrusted",
            "cwd": str(request["cwd"]),
            "command": request["command"],
            "reason": request["reason"],
            "approvalExpiresAt": request["expiresAt"],
            "repoIdHash": target["targetHash"],
            "headCommit": target["headCommit"],
            "criticalFingerprint": target["criticalFingerprint"],
            "commandScope": target["commandScope"],
            "policyVersion": target["policyVersion"],
            "rulesetVersion": target["rulesetVersion"],
            "matchingSemantics": "identity-head-fingerprint-scope-policy-ruleset",
        }

    def _prepare_audit(
        self,
        *,
        operation: str,
        plan: TrustCacheMutationPlan,
        entry_id: str,
        context: AuditContext,
        expected_event_id: str | None,
        reservation: object | None,
    ) -> PreparedMutation:
        assert self.audit is not None
        try:
            with self._reserve_audit_event_id(expected_event_id):
                arguments = {
                    "operation": operation,
                    "before_bytes": plan.before_bytes,
                    "after_bytes": plan.after_bytes,
                    "entry_id": entry_id,
                    "context": context,
                }
                if reservation is not None:
                    arguments["reservation"] = reservation
                prepared = self.audit.prepare_mutation(**arguments)  # type: ignore[union-attr]
        except TrustMutationAuditError:
            raise
        except Exception:
            raise TrustMutationAuditError(
                "MCP_TRUST_MUTATION_AUDIT_FAILED",
                "The trust mutation audit operation failed closed.",
            ) from None
        if not isinstance(prepared, PreparedMutation) or (
            expected_event_id is not None and prepared.event_id != expected_event_id
        ):
            raise TrustMutationAuditError(
                "MCP_TRUST_MUTATION_AUDIT_FAILED",
                "The trust mutation audit operation failed closed.",
            )
        return prepared

    def _commit_audit(
        self,
        prepared: PreparedMutation,
        *,
        context: AuditContext,
        reservation: object | None,
    ) -> str:
        assert self.audit is not None
        committed_context = AuditContext(
            tool=context.tool,
            operation_id=context.operation_id,
            operation=context.operation,
            target_hash=context.target_hash,
            entry_id=context.entry_id,
            scope=context.scope,
            policy_version=context.policy_version,
            ruleset_version=context.ruleset_version,
            challenge_id=context.challenge_id,
            outcome="committed",
            error_code=context.error_code,
            entry_version=context.entry_version,
        )
        try:
            if reservation is None:
                return self.audit.commit_mutation(prepared, context=committed_context)  # type: ignore[union-attr]
            return self.audit.commit_mutation(  # type: ignore[union-attr]
                prepared,
                context=committed_context,
                reservation=reservation,
            )
        except TrustMutationAuditError:
            raise
        except Exception:
            raise TrustMutationAuditError(
                "MCP_TRUST_MUTATION_AUDIT_FAILED",
                "The trust mutation audit operation failed closed.",
            ) from None

    @contextmanager
    def _audit_transaction(self):
        assert self.audit is not None
        transaction = getattr(self.audit, "mutation_transaction", None)
        if not callable(transaction):
            yield None
            return
        with transaction() as reservation:
            yield reservation

    @contextmanager
    def _reserve_audit_event_id(self, event_id: str | None):
        if event_id is None or self.audit is None or not hasattr(self.audit, "event_id_factory"):
            yield
            return
        audit = self.audit
        original = audit.event_id_factory  # type: ignore[attr-defined]
        if not callable(original):
            yield
            return
        used = False

        def factory() -> str:
            nonlocal used
            if not used:
                used = True
                return event_id
            return original()

        audit.event_id_factory = factory  # type: ignore[attr-defined]
        try:
            yield
        finally:
            audit.event_id_factory = original  # type: ignore[attr-defined]

    def _approval_result(
        self,
        result: TrustCacheMutationResult,
        consumed: ConsumedMutationChallenge,
    ) -> dict[str, object]:
        if result.outcome == "already-approved":
            assert result.entry is not None
            audit_event_id = self._record(
                "mutation_noop",
                self._audit_context(
                    "approve",
                    self._bound_uuid(_thaw(consumed.binding), "operationId"),
                    entry_id=result.entry["entryId"],
                    challenge_id=_canonical_challenge_id(consumed.challenge_id),
                    outcome="already-approved",
                ),
            )
        else:
            assert result.entry is not None
            assert result.final_event_id is not None
            audit_event_id = result.final_event_id
        entry = result.entry
        return {
            "mcpSchemaVersion": "1.0",
            "tool": "trust_approve",
            "schemaVersion": TRUST_APPROVE_SCHEMA_VERSION,
            "sourceType": "trust-cache",
            "outcome": result.outcome,
            "mutationApplied": result.applied,
            "entry": {
                "entryId": entry["entryId"],
                "entryVersion": 1,
                "repoIdHash": privacy_hash(entry["repoId"], self._privacy_key()),
                "repoIdRedacted": True,
                "headCommit": entry["headCommit"],
                "criticalFingerprint": entry["criticalFingerprint"],
                "commandScope": entry["commandScope"],
                "policyVersion": entry["policyVersion"],
                "rulesetVersion": entry["rulesetVersion"],
                "expiresAt": entry["expiresAt"],
            },
            "confirmation": {"challengeId": _canonical_challenge_id(consumed.challenge_id), "consumed": True},
            "runtimeIdentity": dict(RUNTIME_IDENTITY),
            "auditEventId": audit_event_id,
            "safety": dict(MUTATION_SAFETY),
        }

    def _revoke_result(
        self,
        result: TrustCacheMutationResult,
        consumed: ConsumedMutationChallenge,
    ) -> dict[str, object]:
        if result.outcome != "revoked" or result.entry is None or result.final_event_id is None:
            raise self._error("MCP_TRUST_MUTATION_INTERNAL_ERROR", "The trust mutation could not be completed.")
        return {
            "mcpSchemaVersion": "1.0",
            "tool": "trust_revoke",
            "schemaVersion": TRUST_REVOKE_SCHEMA_VERSION,
            "sourceType": "trust-cache",
            "outcome": "revoked",
            "mutationApplied": True,
            "entry": {"entryId": result.entry["entryId"], "entryVersion": 1},
            "confirmation": {"challengeId": _canonical_challenge_id(consumed.challenge_id), "consumed": True},
            "runtimeIdentity": dict(RUNTIME_IDENTITY),
            "auditEventId": result.final_event_id,
            "safety": dict(MUTATION_SAFETY),
        }

    def _committed_pending_error(self, result: TrustCacheMutationResult) -> TrustMutationError:
        entry = result.entry
        prepared_event_id = result.prepared_event_id
        if entry is None or prepared_event_id is None:
            return self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation entered an indeterminate state.",
            )
        return self._error(
            "MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING",
            "The trust mutation committed, but its audit completion is pending recovery.",
            context={
                "committed": True,
                "operation": "approve-or-revoke",
                "entryId": entry["entryId"],
                "preparedAuditEventId": prepared_event_id,
            },
        )

    def _challenge_context(self, challenge: TrustMutationChallenge) -> dict[str, object]:
        return {
            "schemaVersion": CONFIRMATION_SCHEMA_VERSION,
            "challengeId": _canonical_challenge_id(challenge.challenge_id),
            "confirmationToken": challenge.token,
            "operation": "approve" if challenge.display.get("template") == "approve-exact-local-trust/v1" else "revoke",
            "issuedAt": _utc_timestamp(challenge.issued_at),
            "expiresAt": _utc_timestamp(challenge.expires_at),
            "display": _thaw(challenge.display),
        }

    def _record_validation_failure(
        self,
        operation: str,
        operation_id: str,
        error: TrustMutationError,
        *,
        consumed: ConsumedMutationChallenge | None = None,
        binding: Mapping[str, object] | None = None,
    ) -> None:
        self._record(
            "request_validation_failed",
            self._audit_context(
                operation,
                operation_id,
                target=self._bound_target(binding),
                entry_id=consumed.proposed_entry_id if consumed is not None else None,
                challenge_id=_canonical_challenge_id(consumed.challenge_id) if consumed is not None else None,
                outcome="failure",
                error_code=error.code,
            ),
        )

    def _record_terminal_failure(
        self,
        operation: str,
        operation_id: str,
        error: TrustMutationError,
        *,
        target: Mapping[str, object] | None = None,
        entry_id: str | None = None,
        consumed: ConsumedMutationChallenge | None = None,
        binding: Mapping[str, object] | None = None,
    ) -> None:
        if error.code == "MCP_TRUST_MUTATION_CANCELLED":
            event, outcome = "mutation_cancelled", "cancelled"
        elif error.code == "MCP_TRUST_MUTATION_TIMEOUT":
            event, outcome = "mutation_timed_out", "timed-out"
        elif error.code == "MCP_TRUST_MUTATION_LOCK_TIMEOUT":
            event, outcome = "lock_timeout", "failure"
        else:
            event, outcome = "mutation_failed", "failure"
        self._record(
            event,
            self._audit_context(
                operation,
                operation_id,
                target=target or self._bound_target(binding),
                entry_id=entry_id or (consumed.proposed_entry_id if consumed is not None else None),
                challenge_id=_canonical_challenge_id(consumed.challenge_id) if consumed is not None else None,
                outcome=outcome,
                error_code=error.code,
            ),
        )

    def _record(self, event: str, context: AuditContext) -> str:
        assert self.audit is not None
        try:
            with self._audit_reservation_lock:
                return self.audit.record(event, context=context)  # type: ignore[union-attr]
        except TrustMutationAuditError as error:
            raise self._audit_error(error) from None
        except Exception:
            raise self._error(
                "MCP_TRUST_MUTATION_AUDIT_FAILED",
                "The trust mutation audit operation failed closed.",
            ) from None

    def _audit_context(
        self,
        operation: str,
        operation_id: str,
        *,
        target: Mapping[str, object] | None = None,
        entry_id: str | None = None,
        challenge_id: str | None = None,
        outcome: str,
        error_code: str | None = None,
    ) -> AuditContext:
        tool = "trust_approve" if operation == "approve" else "trust_revoke"
        target_hash = target.get("targetHash") if target is not None else None
        scope = target.get("commandScope") if target is not None else None
        policy = target.get("policyVersion") if target is not None else None
        ruleset = target.get("rulesetVersion") if target is not None else None
        return AuditContext(
            tool=tool,
            operation_id=operation_id,
            operation=operation,
            target_hash=target_hash if isinstance(target_hash, str) else None,
            entry_id=entry_id,
            scope=scope if isinstance(scope, str) else None,
            policy_version=policy if isinstance(policy, str) else None,
            ruleset_version=ruleset if isinstance(ruleset, str) else None,
            challenge_id=challenge_id,
            outcome=outcome,
            error_code=error_code,
            entry_version=1 if entry_id is not None else None,
        )

    def _bound_target(self, binding: Mapping[str, object] | None) -> dict[str, object] | None:
        if binding is None:
            return None
        target = _thaw(binding.get("target"))
        return target if isinstance(target, dict) else None

    def _bound_uuid(self, binding: Mapping[str, object], name: str) -> str:
        try:
            return _canonical_uuid(binding[name])
        except (KeyError, ValueError):
            raise self._error(
                "MCP_TRUST_MUTATION_CONFIRMATION_INVALID",
                "The trust mutation confirmation token is invalid.",
            ) from None

    def _deadline(self) -> float:
        try:
            value = self.monotonic()
        except Exception:
            raise self._error("MCP_TRUST_MUTATION_TIMEOUT", "The target operation timed out.") from None
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise self._error("MCP_TRUST_MUTATION_TIMEOUT", "The target operation timed out.")
        return float(value) + TRUST_MUTATION_TIMEOUT_SECONDS

    def _check_target(self, deadline: float) -> None:
        if self.cancellation_check is not None:
            try:
                if self.cancellation_check():
                    raise self._error("MCP_TRUST_MUTATION_CANCELLED", "The target operation was cancelled.")
            except TrustMutationError:
                raise
            except Exception:
                raise self._error("MCP_TRUST_MUTATION_CANCELLED", "The target operation was cancelled.") from None
        try:
            value = self.monotonic()
        except Exception:
            raise self._error("MCP_TRUST_MUTATION_TIMEOUT", "The target operation timed out.") from None
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value >= deadline
        ):
            raise self._error("MCP_TRUST_MUTATION_TIMEOUT", "The target operation timed out.")

    def _ensure_storage_safe(self) -> None:
        assert self.cache is not None
        try:
            validate_private_cache_storage(self.cache.path)
        except (UnsafeCacheStorageError, OSError, RuntimeError):
            raise self._error(
                "MCP_TRUST_MUTATION_UNSAFE_STORAGE",
                "The local trust mutation storage is unsafe.",
            ) from None

    def _current_version(self, value: str | Callable[[], str]) -> str:
        try:
            resolved = value() if callable(value) else value
        except Exception:
            raise self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation could not be completed.",
            ) from None
        try:
            return _bounded_text(resolved, maximum=128, field="version", allow_empty=False)
        except TrustMutationError:
            raise self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation could not be completed.",
            ) from None

    def _fingerprint_error(self, error: CriticalFingerprintError) -> TrustMutationError:
        if error.code == "limit-exceeded":
            return self._error("MCP_TRUST_MUTATION_LIMIT_EXCEEDED", "The local target exceeds its safety budget.")
        if error.code == "timeout":
            return self._error("MCP_TRUST_MUTATION_TIMEOUT", "The target operation timed out.")
        if error.code == "cancelled":
            return self._error("MCP_TRUST_MUTATION_CANCELLED", "The target operation was cancelled.")
        return self._error(
            "MCP_TRUST_MUTATION_IDENTITY_UNRESOLVED",
            "The local trust target identity could not be resolved safely.",
        )

    def _identity_error(self, error: RepoIdentityError) -> TrustMutationError:
        if error.code == "timeout":
            return self._error("MCP_TRUST_MUTATION_TIMEOUT", "The target operation timed out.")
        if error.code == "cancelled":
            return self._error("MCP_TRUST_MUTATION_CANCELLED", "The target operation was cancelled.")
        return self._error(
            "MCP_TRUST_MUTATION_IDENTITY_UNRESOLVED",
            "The local trust target identity could not be resolved safely.",
        )

    def _cache_error(self, error: BaseException) -> TrustMutationError:
        if isinstance(error, CacheLockTimeoutError):
            return self._error("MCP_TRUST_MUTATION_LOCK_TIMEOUT", "The local trust-store lock timed out.")
        if isinstance(error, TrustCacheError):
            if error.code == "corrupt":
                return self._error("MCP_TRUST_MUTATION_CORRUPT", "The local trust store is corrupt.")
            if error.code == "unsupported-schema":
                return self._error(
                    "MCP_TRUST_MUTATION_UNSUPPORTED_SCHEMA",
                    "The local trust store schema is unsupported.",
                )
            if error.code == "migration-failed":
                return self._error(
                    "MCP_TRUST_MUTATION_PERSISTENCE_FAILED",
                    "The local trust-store migration failed closed.",
                )
        return self._error("MCP_TRUST_MUTATION_PERSISTENCE_FAILED", "The local trust store is unavailable.")

    def _audit_error(self, error: TrustMutationAuditError) -> TrustMutationError:
        code = error.code
        if code not in {
            "MCP_TRUST_MUTATION_AUDIT_FAILED",
            "MCP_TRUST_MUTATION_CORRUPT",
            "MCP_TRUST_MUTATION_RECOVERY_REQUIRED",
        }:
            code = "MCP_TRUST_MUTATION_AUDIT_FAILED"
        messages = {
            "MCP_TRUST_MUTATION_AUDIT_FAILED": "The trust mutation audit operation failed closed.",
            "MCP_TRUST_MUTATION_CORRUPT": "The trust mutation audit chain is invalid.",
            "MCP_TRUST_MUTATION_RECOVERY_REQUIRED": "Trust mutation recovery requires known-good local state.",
        }
        return self._error(code, messages[code])

    def _confirmation_issue_error(self, error: TrustMutationConfirmationError) -> TrustMutationError:
        if error.code in {
            "MCP_TRUST_MUTATION_CONFIRMATION_CAPACITY",
            "MCP_TRUST_MUTATION_CONFIRMATION_RATE_LIMITED",
        }:
            return self._error(
                "MCP_TRUST_MUTATION_RATE_LIMITED",
                "Trust mutation confirmation issuance is temporarily limited.",
            )
        return self._error(
            "MCP_TRUST_MUTATION_CONFIRMATION_INVALID",
            "The trust mutation confirmation token is invalid.",
        )

    def _invalid_argument(self, field: str) -> TrustMutationError:
        return self._error(
            "MCP_TRUST_MUTATION_INVALID_ARGUMENT",
            "The trust mutation request contains an invalid argument.",
            field=field,
        )

    def _error(
        self,
        code: str,
        message: str,
        *,
        field: str | None = None,
        retryable: bool = False,
        remediation: str | None = None,
        safety_boundary: str | None = None,
        context: Mapping[str, object] | None = None,
    ) -> TrustMutationError:
        values: dict[str, object] = {"runtimeIdentity": dict(RUNTIME_IDENTITY)}
        if context:
            values.update(context)
        return TrustMutationError(
            code,
            message,
            field=field,
            retryable=retryable,
            remediation=remediation,
            safety_boundary=safety_boundary,
            context=values,
        )

    def _ensure_enabled(self) -> None:
        if not self.enabled:
            raise self._error(
                "MCP_TRUST_MUTATION_DISABLED",
                "Trust mutation is disabled for this process.",
            )

    def _ensure_active(self) -> None:
        self._ensure_enabled()
        if not self._healthy:
            raise self._error(
                "MCP_TRUST_MUTATION_RECOVERY_REQUIRED",
                "Trust mutation recovery is required before further mutations.",
            )

    def _mark_unhealthy(self) -> None:
        self._healthy = False
        if self.confirmation is not None:
            try:
                self.confirmation.invalidate_all()
            except Exception:
                pass

    def _wall_time(self) -> float:
        try:
            value = self.clock()
        except Exception:
            raise self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation could not be completed.",
            ) from None
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation could not be completed.",
            )
        return float(value)

    def _privacy_key(self) -> bytes:
        if self.privacy_key is None:
            raise self._error("MCP_TRUST_MUTATION_INTERNAL_ERROR", "The trust mutation could not be completed.")
        return self.privacy_key

    def _new_uuid(self, factory: Callable[[], str]) -> str:
        try:
            return _canonical_uuid(factory())
        except (ValueError, TypeError):
            raise self._error(
                "MCP_TRUST_MUTATION_INTERNAL_ERROR",
                "The trust mutation could not be completed.",
            ) from None


def trust_mutation_enabled() -> bool:
    return os.environ.get("CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION") == "1"


def default_trust_mutation_service() -> TrustMutationService:
    if not trust_mutation_enabled():
        return TrustMutationService(enabled=False)
    from codex_preflight_mcp.trust_read import _PROCESS_PRIVACY_KEY

    service = TrustMutationService(
        cache=TrustCache(trust_cache_path()),
        audit=TrustMutationAuditLog(
            trust_mutation_audit_path(),
            key_path=trust_mutation_audit_key_path(),
        ),
        confirmation=TrustMutationConfirmationManager(),
        privacy_key=_PROCESS_PRIVACY_KEY,
    )
    service.recover_startup()
    return service


def _bounded_text(value: object, *, maximum: int, field: str, allow_empty: bool) -> str:
    if value is MISSING:
        raise TrustMutationError(
            "MCP_TRUST_MUTATION_INVALID_ARGUMENT",
            "The trust mutation request contains an invalid argument.",
            field=field,
        )
    length = _utf8_length(value) if isinstance(value, str) else None
    if (
        not isinstance(value, str)
        or length is None
        or length > maximum
        or _CONTROL.search(value)
        or (not allow_empty and not value)
    ):
        raise TrustMutationError(
            "MCP_TRUST_MUTATION_INVALID_ARGUMENT",
            "The trust mutation request contains an invalid argument.",
            field=field,
        )
    return value


def _utf8_length(value: str) -> int | None:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _canonical_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid UUID")
    parsed = UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("invalid UUID")
    return value


def _canonical_challenge_id(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid challenge UUID")
    parsed = UUID(value)
    if parsed.version != 4:
        raise ValueError("invalid challenge UUID")
    return str(parsed)


def _utc_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")


def _value_digest(value: object) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        encoded = b"<invalid>"
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _store_digest(value: object) -> str:
    if value is None:
        encoded = b"codex-preflight/trust-store/absent/v1\x00"
    elif isinstance(value, bytes):
        encoded = b"codex-preflight/trust-store/present/v1\x00" + value
    else:
        encoded = b"codex-preflight/trust-store/invalid/v1\x00"
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _same_binding(left: Mapping[str, object], right: Mapping[str, object]) -> bool:
    try:
        left_value = json.dumps(_thaw(left), ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
        right_value = json.dumps(_thaw(right), ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        return False
    return hmac.compare_digest(left_value, right_value)


def _thaw(value: object) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    if isinstance(value, list):
        return [_thaw(item) for item in value]
    return value


def _entry_is_live(entry: Mapping[str, object], now: datetime) -> bool:
    expires_at = entry.get("expiresAt")
    if not isinstance(expires_at, str):
        return False
    try:
        return datetime.fromisoformat(expires_at.replace("Z", "+00:00")).astimezone(UTC) > now
    except ValueError:
        return False


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _assert_no_reparse_ancestors(path: Path) -> None:
    absolute = path.absolute()
    parts = absolute.parts
    if not parts:
        raise OSError("invalid local path")
    candidate = Path(parts[0])
    info = candidate.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise OSError("unsafe reparse path")
    for part in parts[1:]:
        candidate /= part
        info = candidate.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise OSError("unsafe reparse path")


def _is_nonlocal_windows_path(value: str) -> bool:
    windows_path = value.replace("/", "\\")
    if windows_path.startswith("\\\\") or windows_path.startswith("\\??\\"):
        return True
    if not re.match(r"^[A-Za-z]:", windows_path):
        return False
    try:
        return _windows_drive_type(f"{windows_path[0]}:\\") == 4
    except (OSError, ValueError):
        return True


def _windows_drive_type(root: str) -> int:
    if os.name != "nt":
        return 0
    import ctypes

    get_drive_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
    get_drive_type.argtypes = [ctypes.c_wchar_p]
    get_drive_type.restype = ctypes.c_uint
    return int(get_drive_type(root))
