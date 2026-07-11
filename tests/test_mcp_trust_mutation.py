from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from codex_preflight_core.cache import trust_cache as trust_cache_module
from codex_preflight_core.cache.trust_cache import TrustCache
from codex_preflight_core.repo.identity import RepoIdentity
from codex_preflight_mcp.trust_mutation_audit import (
    PreparedMutation,
    RecoveryResult,
    TrustMutationAuditLog,
)
from codex_preflight_mcp.trust_mutation_confirmation import TrustMutationConfirmationManager
from codex_preflight_mcp.trust_state import privacy_hash

NOW = 1_783_814_400.0  # 2026-07-12T00:00:00Z
HEAD = "a" * 40
FINGERPRINT = f"sha256:{'b' * 64}"
EXPIRES_AT = "2026-07-22T00:00:00Z"


class Clock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class RecordingAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, object]] = []
        self.prepare_contexts: list[object] = []
        self.commit_contexts: list[object] = []
        self.prepare_calls = 0
        self.commit_calls = 0
        self.fail_commit = False
        self.recovery_calls = 0
        self.event_id_factory: Callable[[], str] = lambda: str(uuid4())

    def record(self, event: str, *, context: object) -> str:
        self.events.append((event, context))
        return self.event_id_factory()

    def prepare_mutation(
        self,
        *,
        operation: str,
        before_bytes: bytes | None,
        after_bytes: bytes | None,
        entry_id: str,
        context: object,
    ) -> PreparedMutation:
        self.prepare_calls += 1
        self.prepare_contexts.append(context)
        self.events.append(("mutation_prepared", context))
        return PreparedMutation(
            self.event_id_factory(),
            operation,
            entry_id,
            f"hmac-sha256:{'1' * 64}",
            f"hmac-sha256:{'2' * 64}",
            "3" * 64,
        )

    def commit_mutation(self, prepared: PreparedMutation, *, context: object) -> str:
        self.commit_calls += 1
        self.commit_contexts.append(context)
        self.events.append(("mutation_committed", context))
        if self.fail_commit:
            raise RuntimeError("private audit failure")
        return self.event_id_factory()

    def verify_and_recover(self, *, read_store_bytes: Callable[[], bytes | None]) -> RecoveryResult:
        self.recovery_calls += 1
        read_store_bytes()
        return RecoveryResult("clean")


def _service(
    tmp_path: Path,
    *,
    state: dict[str, object] | None = None,
    audit: RecordingAudit | None = None,
    cancel_check: Callable[[], bool] | None = None,
    monotonic: Callable[[], float] | None = None,
):
    from codex_preflight_mcp.trust_mutation import TrustMutationService

    root = tmp_path / "repo"
    root.mkdir(parents=True)
    (root / "README.md").write_text("local repository\n", encoding="utf-8")
    clock = Clock()
    values = state if state is not None else {}
    values.setdefault("fingerprint", FINGERPRINT)
    values.setdefault("policy", "default-v1")
    values.setdefault("ruleset", "2026.07.08")
    cache = TrustCache(
        tmp_path / "state" / "trust.json",
        clock=lambda: datetime.fromtimestamp(clock(), UTC),
    )
    confirmation = TrustMutationConfirmationManager(secret=b"c" * 32, clock=clock)
    recording_audit = audit or RecordingAudit()

    def identity_resolver(path: Path, **kwargs: object) -> RepoIdentity:
        values["identity_call"] = (path, kwargs)
        return RepoIdentity(path.resolve(), None, HEAD, None, "high")

    def fingerprinter(path: Path, command: str | None = None, **kwargs: object) -> str:
        values["fingerprint_call"] = (path, command, kwargs)
        return str(values["fingerprint"])

    service = TrustMutationService(
        cache=cache,
        audit=recording_audit,
        confirmation=confirmation,
        privacy_key=b"p" * 32,
        identity_resolver=identity_resolver,
        fingerprinter=fingerprinter,
        policy_version=lambda: str(values["policy"]),
        ruleset_version=lambda: str(values["ruleset"]),
        clock=clock,
        monotonic=monotonic or (lambda: 0.0),
        cancellation_check=cancel_check,
    )
    return service, cache, root, values, recording_audit


def _approval_challenge(service: object, root: Path, **overrides: object) -> dict[str, object]:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    values: dict[str, object] = {
        "cwd": str(root),
        "command": "python private_script.py",
        "expires_at": EXPIRES_AT,
        "reason": "Human review of local test target.",
    }
    values.update(overrides)
    with pytest.raises(TrustMutationError) as caught:
        service.approve(**values)  # type: ignore[attr-defined]
    assert caught.value.code == "MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED"
    assert caught.value.field == "confirmationToken"
    assert caught.value.retryable is False
    assert caught.value.context["runtimeIdentity"] == {
        "transport": "stdio",
        "identityStatus": "unavailable",
        "clientId": None,
        "sessionId": None,
    }
    return caught.value.context["confirmation"]


def _confirm_approval(service: object, root: Path, token: str, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "cwd": str(root),
        "command": "python private_script.py",
        "expires_at": EXPIRES_AT,
        "reason": "Human review of local test target.",
        "confirmation_token": token,
    }
    values.update(overrides)
    return service.approve(**values)  # type: ignore[attr-defined]


def _approved_entry(service: object, root: Path) -> dict[str, object]:
    challenge = _approval_challenge(service, root)
    return _confirm_approval(service, root, str(challenge["confirmationToken"]))["entry"]


def _real_audit(tmp_path: Path) -> TrustMutationAuditLog:
    return TrustMutationAuditLog(
        tmp_path / "audit" / "audit.jsonl",
        key_path=tmp_path / "audit" / "audit.key",
        key_factory=lambda size: b"k" * size,
        clock=lambda: NOW,
    )


def _audit_events(audit: TrustMutationAuditLog) -> list[str]:
    return [
        str(json.loads(line)["event"])
        for line in audit.path.read_text(encoding="utf-8").splitlines()
    ]


def test_approval_first_call_is_only_a_fixed_human_challenge(tmp_path: Path) -> None:
    service, cache, root, values, audit = _service(tmp_path)

    challenge = _approval_challenge(service, root)

    assert not cache.path.exists()
    assert set(challenge) == {
        "schemaVersion",
        "challengeId",
        "confirmationToken",
        "operation",
        "issuedAt",
        "expiresAt",
        "display",
    }
    assert UUID(str(challenge["challengeId"])).version == 4
    assert challenge["operation"] == "approve"
    assert challenge["issuedAt"] == "2026-07-12T00:00:00Z"
    assert challenge["expiresAt"] == "2026-07-12T00:05:00Z"
    display = challenge["display"]
    assert set(display) == {
        "template",
        "repositoryContentTrust",
        "cwd",
        "command",
        "reason",
        "approvalExpiresAt",
        "repoIdHash",
        "headCommit",
        "criticalFingerprint",
        "commandScope",
        "policyVersion",
        "rulesetVersion",
        "matchingSemantics",
    }
    assert display == {
        "template": "approve-exact-local-trust/v1",
        "repositoryContentTrust": "untrusted",
        "cwd": str(root.resolve()),
        "command": "python private_script.py",
        "reason": "Human review of local test target.",
        "approvalExpiresAt": EXPIRES_AT,
        "repoIdHash": privacy_hash(str(root.resolve()), b"p" * 32),
        "headCommit": HEAD,
        "criticalFingerprint": FINGERPRINT,
        "commandScope": "script_execution",
        "policyVersion": "default-v1",
        "rulesetVersion": "2026.07.08",
        "matchingSemantics": "identity-head-fingerprint-scope-policy-ruleset",
    }
    assert values["fingerprint_call"][2] == {
        "max_files": 4096,
        "max_file_bytes": 8 * 1024 * 1024,
        "max_total_bytes": 64 * 1024 * 1024,
        "deadline": 30.0,
        "cancellation_check": None,
        "monotonic": service.monotonic,
        "strict_safety": True,
    }
    assert [event for event, _context in audit.events] == [
        "request_validated",
        "identity_resolved",
        "challenge_issued",
    ]


@pytest.mark.parametrize(
    "overrides",
    [
        {"cwd": ""},
        {"cwd": "https://example.test/repository"},
        {"cwd": "bad\ud800path"},
        {"command": ""},
        {"command": "x\x00y"},
        {"command": "x\ud800"},
        {"reason": ""},
        {"reason": "x\x85y"},
        {"reason": "x\ud800"},
        {"reason": "x" * 513},
        {"expires_at": "2026-07-22T00:00:00+00:00"},
        {"expires_at": "2026-08-12T00:00:00Z"},
    ],
)
def test_approval_validation_rejects_bounds_controls_and_surrogates(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, cache, root, _values, audit = _service(tmp_path)
    arguments = {
        "cwd": str(root),
        "command": "python private_script.py",
        "expires_at": EXPIRES_AT,
        "reason": "reviewed",
    }
    arguments.update(overrides)

    with pytest.raises(TrustMutationError) as caught:
        service.approve(**arguments)

    assert caught.value.code == "MCP_TRUST_MUTATION_INVALID_ARGUMENT"
    assert caught.value.context == {
        "runtimeIdentity": {
            "transport": "stdio",
            "identityStatus": "unavailable",
            "clientId": None,
            "sessionId": None,
        }
    }
    assert not cache.path.exists()
    assert [event for event, _context in audit.events] == ["request_validation_failed"]


@pytest.mark.parametrize(
    ("cwd", "drive_type"),
    [
        (r"\\server\share\repo", 3),
        (r"\\?\C:\repo", 3),
        (r"\\.\C:\repo", 3),
        (r"\??\C:\repo", 3),
        (r"Z:\repo", 4),
    ],
)
def test_nonlocal_windows_paths_are_rejected_before_filesystem_git_or_network_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cwd: str,
    drive_type: int,
) -> None:
    from codex_preflight_mcp import trust_mutation as mutation_module
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, cache, _root, _values, audit = _service(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("nonlocal cwd reached a filesystem, Git, target, or network dependency")

    monkeypatch.setattr(mutation_module, "_windows_drive_type", lambda _root: drive_type, raising=False)
    monkeypatch.setattr(mutation_module, "Path", forbidden)
    monkeypatch.setattr(service, "identity_resolver", forbidden)
    monkeypatch.setattr(service, "fingerprinter", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    with pytest.raises(TrustMutationError) as caught:
        service.approve(
            cwd=cwd,
            command="python private_script.py",
            expires_at=EXPIRES_AT,
            reason="reviewed",
        )

    assert caught.value.code == "MCP_TRUST_MUTATION_INVALID_ARGUMENT"
    assert caught.value.field == "cwd"
    assert cache.path.name == "trust.json"
    assert [event for event, _context in audit.events] == ["request_validation_failed"]


@pytest.mark.skipif(os.name != "nt", reason="Windows UNC symlink fixture")
def test_nested_local_symlink_to_unc_is_rejected_before_target_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, _cache, _root, _values, audit = _service(tmp_path)
    local = tmp_path / "local"
    local.mkdir()
    link = local / "remote-link"
    try:
        link.symlink_to(r"\\192.0.2.1\unreachable-share", target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    requested = link / "repo"
    path_type = type(requested)
    real_exists = path_type.exists
    real_is_dir = path_type.is_dir
    real_resolve = path_type.resolve

    def forbid_target_access(path: Path, *args: object, **kwargs: object):
        if path == requested or link in path.parents:
            raise AssertionError("cwd validation followed the nested UNC reparse target")
        operation = kwargs.pop("operation")
        if operation == "exists":
            return real_exists(path, *args, **kwargs)
        if operation == "is_dir":
            return real_is_dir(path, *args, **kwargs)
        return real_resolve(path, *args, **kwargs)

    monkeypatch.setattr(
        path_type,
        "exists",
        lambda path, *args, **kwargs: forbid_target_access(path, *args, operation="exists", **kwargs),
    )
    monkeypatch.setattr(
        path_type,
        "is_dir",
        lambda path, *args, **kwargs: forbid_target_access(path, *args, operation="is_dir", **kwargs),
    )
    monkeypatch.setattr(
        path_type,
        "resolve",
        lambda path, *args, **kwargs: forbid_target_access(path, *args, operation="resolve", **kwargs),
    )

    with pytest.raises(TrustMutationError) as caught:
        service.approve(
            cwd=str(requested),
            command="python private_script.py",
            expires_at=EXPIRES_AT,
            reason="reviewed",
        )

    assert caught.value.code == "MCP_TRUST_MUTATION_INVALID_ARGUMENT"
    assert caught.value.field == "cwd"
    assert [event for event, _context in audit.events] == ["request_validation_failed"]


def test_authentic_token_is_consumed_before_retry_envelope_validation(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, _cache, root, _values, audit = _service(tmp_path)
    challenge = _approval_challenge(service, root)
    token = str(challenge["confirmationToken"])

    with pytest.raises(TrustMutationError) as malformed_retry:
        service.approve(
            cwd=None,
            command="python private_script.py",
            expires_at=EXPIRES_AT,
            reason="reviewed",
            confirmation_token=token,
            unexpected="not allowed",
        )
    assert malformed_retry.value.code == "MCP_TRUST_MUTATION_INVALID_ARGUMENT"

    with pytest.raises(TrustMutationError) as replay:
        _confirm_approval(service, root, token)
    assert replay.value.code == "MCP_TRUST_MUTATION_CONFIRMATION_INVALID"
    assert [event for event, _context in audit.events].count("challenge_consumed") == 1


def test_confirmed_approval_uses_exact_private_provenance_and_redacted_success(tmp_path: Path) -> None:
    service, cache, root, _values, audit = _service(tmp_path)
    entry = _approved_entry(service, root)

    result = cache.list()[0]
    assert result["entryId"] == entry["entryId"]
    assert result["approvedCommand"] == "python private_script.py"
    assert result["provenance"] == {
        "schema": "trust-cache-array-v2",
        "source": "mcp-trust-approve",
        "migrationVersion": "v0.3.4-trust-mutation",
        "createdAt": "2026-07-12T00:00:00Z",
        "approvalReason": "Human review of local test target.",
        "mutationAuditEventId": result["provenance"]["mutationAuditEventId"],
    }
    assert UUID(result["entryId"]).version == 4
    assert UUID(result["provenance"]["mutationAuditEventId"]).version == 4

    response = _confirm_approval  # keeps the response assertion local to the public contract below
    challenge = _approval_challenge(service, root, reason="another review")
    duplicate = response(service, root, str(challenge["confirmationToken"]), reason="another review")
    assert set(duplicate) == {
        "mcpSchemaVersion",
        "tool",
        "schemaVersion",
        "sourceType",
        "outcome",
        "mutationApplied",
        "entry",
        "confirmation",
        "runtimeIdentity",
        "auditEventId",
        "safety",
    }
    assert duplicate["outcome"] == "already-approved"
    assert duplicate["mutationApplied"] is False
    assert duplicate["entry"]["entryId"] == entry["entryId"]
    serialized = json.dumps(duplicate, sort_keys=True)
    assert "private_script.py" not in serialized
    assert "Human review" not in serialized
    assert str(root) not in serialized
    assert duplicate["safety"] == {
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
    assert audit.prepare_calls == 1
    assert audit.commit_calls == 1
    assert audit.prepare_contexts[0].outcome == "pending"
    assert audit.commit_contexts[0].outcome == "committed"


def test_confirmed_target_and_store_drift_consume_the_token(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, cache, root, state, audit = _service(tmp_path)
    target = _approval_challenge(service, root)
    state["fingerprint"] = f"sha256:{'c' * 64}"

    with pytest.raises(TrustMutationError) as target_drift:
        _confirm_approval(service, root, str(target["confirmationToken"]))
    assert target_drift.value.code == "MCP_TRUST_MUTATION_TARGET_DRIFT"

    state["fingerprint"] = FINGERPRINT
    store = _approval_challenge(service, root)
    cache.approve(
        repo_id="another-local-repository",
        path=root,
        remote_url=None,
        head_commit=HEAD,
        critical_fingerprint=FINGERPRINT,
        command_scope="test",
        approved_command="pytest",
        expires_at=datetime(2026, 7, 22, tzinfo=UTC),
        ruleset_version="2026.07.08",
    )
    with pytest.raises(TrustMutationError) as store_drift:
        _confirm_approval(service, root, str(store["confirmationToken"]))
    assert store_drift.value.code == "MCP_TRUST_MUTATION_TARGET_DRIFT"
    assert [event for event, _context in audit.events].count("challenge_consumed") == 2


def test_duplicate_approval_revalidates_target_under_lock_before_matching(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, _cache, root, _state, audit = _service(tmp_path)
    _approved_entry(service, root)
    duplicate = _approval_challenge(service, root, reason="review duplicate")
    calls = 0

    def drift_inside_lock(_path: Path, _command: str | None = None, **_kwargs: object) -> str:
        nonlocal calls
        calls += 1
        return FINGERPRINT if calls == 1 else f"sha256:{'c' * 64}"

    service.fingerprinter = drift_inside_lock
    prepare_calls = audit.prepare_calls

    with pytest.raises(TrustMutationError) as caught:
        _confirm_approval(
            service,
            root,
            str(duplicate["confirmationToken"]),
            reason="review duplicate",
        )

    assert caught.value.code == "MCP_TRUST_MUTATION_TARGET_DRIFT"
    assert calls == 2
    assert audit.prepare_calls == prepare_calls


def test_revoke_binds_the_complete_private_entry_and_keeps_the_display_redacted(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, cache, root, _values, _audit = _service(tmp_path)
    entry = _approved_entry(service, root)
    with pytest.raises(TrustMutationError) as challenge_error:
        service.revoke(
            trust_entry_id=entry["entryId"],
            expected_version=1,
            reason="Remove this exact entry.",
        )
    challenge = challenge_error.value.context["confirmation"]
    display = challenge["display"]
    assert set(display) == {
        "template",
        "repositoryContentTrust",
        "trustEntry",
        "expectedVersion",
        "reason",
    }
    serialized_display = json.dumps(display, sort_keys=True)
    assert "private_script.py" not in serialized_display
    assert "Human review" not in serialized_display
    assert str(root) not in serialized_display

    stored = json.loads(cache.path.read_text(encoding="utf-8"))
    stored[0]["provenance"]["approvalReason"] = "Different private reason."
    cache.path.write_text(json.dumps(stored), encoding="utf-8")
    with pytest.raises(TrustMutationError) as changed_private_entry:
        service.revoke(
            trust_entry_id=entry["entryId"],
            expected_version=1,
            reason="Remove this exact entry.",
            confirmation_token=challenge["confirmationToken"],
        )
    assert changed_private_entry.value.code == "MCP_TRUST_MUTATION_TARGET_DRIFT"


def test_revoke_has_common_not_found_and_exact_one_entry_semantics(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, cache, root, _values, audit = _service(tmp_path)
    entry = _approved_entry(service, root)
    with pytest.raises(TrustMutationError) as challenge_error:
        service.revoke(trust_entry_id=entry["entryId"], expected_version=1, reason="remove")
    challenge = challenge_error.value.context["confirmation"]
    result = service.revoke(
        trust_entry_id=entry["entryId"],
        expected_version=1,
        reason="remove",
        confirmation_token=challenge["confirmationToken"],
    )
    assert result["outcome"] == "revoked"
    assert result["mutationApplied"] is True
    assert result["entry"] == {"entryId": entry["entryId"], "entryVersion": 1}
    assert cache.list() == []

    with pytest.raises(TrustMutationError) as missing:
        service.revoke(
            trust_entry_id=entry["entryId"],
            expected_version=1,
            reason="remove again",
        )
    assert missing.value.code == "MCP_TRUST_MUTATION_NOT_FOUND"
    assert [event for event, _context in audit.events].count("mutation_noop") == 0


@pytest.mark.parametrize("expected_version", [True, 1.0, "1", None, 2])
def test_revoke_rejects_non_exact_or_wrong_entry_version(tmp_path: Path, expected_version: object) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, _cache, root, _values, _audit = _service(tmp_path)
    entry = _approved_entry(service, root)

    with pytest.raises(TrustMutationError) as caught:
        service.revoke(trust_entry_id=entry["entryId"], expected_version=expected_version, reason="remove")

    assert caught.value.code == "MCP_TRUST_MUTATION_INVALID_ARGUMENT"


def test_committed_audit_pending_cannot_be_masked_by_invalidation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    audit = RecordingAudit()
    audit.fail_commit = True
    service, cache, root, _values, _audit = _service(tmp_path, audit=audit)
    challenge = _approval_challenge(service, root)

    def fail_invalidation() -> None:
        raise RuntimeError("C:/private/repository confirmation secret")

    monkeypatch.setattr(service.confirmation, "invalidate_all", fail_invalidation)

    with pytest.raises(TrustMutationError) as pending:
        _confirm_approval(service, root, str(challenge["confirmationToken"]))
    assert pending.value.code == "MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING"
    assert pending.value.context["committed"] is True
    assert pending.value.context["operation"] == "approve-or-revoke"
    assert UUID(pending.value.context["entryId"]).version == 4
    assert UUID(pending.value.context["preparedAuditEventId"]).version == 4
    assert "private" not in str(pending.value).lower()
    assert pending.value.__cause__ is None
    assert pending.value.__context__ is None
    assert len(cache.list()) == 1

    with pytest.raises(TrustMutationError) as unhealthy:
        service.approve(
            cwd=str(root),
            command="python another.py",
            expires_at=EXPIRES_AT,
            reason="new request",
        )
    assert unhealthy.value.code == "MCP_TRUST_MUTATION_RECOVERY_REQUIRED"


def test_revoke_committed_audit_pending_uses_fixed_operation_context(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    audit = RecordingAudit()
    service, _cache, root, _values, _unused = _service(tmp_path, audit=audit)
    entry = _approved_entry(service, root)
    with pytest.raises(TrustMutationError) as challenge_error:
        service.revoke(trust_entry_id=entry["entryId"], expected_version=1, reason="remove exact entry")
    challenge = challenge_error.value.context["confirmation"]
    audit.fail_commit = True

    with pytest.raises(TrustMutationError) as pending:
        service.revoke(
            trust_entry_id=entry["entryId"],
            expected_version=1,
            reason="remove exact entry",
            confirmation_token=challenge["confirmationToken"],
        )

    assert pending.value.code == "MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING"
    assert pending.value.context["operation"] == "approve-or-revoke"


def test_authentic_token_dependency_failures_are_normalized_without_private_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, _cache, root, _values, _audit = _service(tmp_path)
    challenge = _approval_challenge(service, root)
    token = str(challenge["confirmationToken"])
    original_consume = service.confirmation.authenticate_and_consume

    def consume_then_fail(value: object):
        original_consume(value)
        raise RuntimeError("C:/private/repository raw token material")

    monkeypatch.setattr(service.confirmation, "authenticate_and_consume", consume_then_fail)

    with pytest.raises(TrustMutationError) as caught:
        _confirm_approval(service, root, token)

    assert caught.value.code == "MCP_TRUST_MUTATION_INTERNAL_ERROR"
    assert "private" not in str(caught.value).lower()
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None

    with pytest.raises(TrustMutationError) as replay:
        _confirm_approval(service, root, token)
    assert replay.value.code == "MCP_TRUST_MUTATION_CONFIRMATION_INVALID"


def test_real_audit_records_cannot_interleave_between_prepare_and_commit(tmp_path: Path) -> None:
    audit = _real_audit(tmp_path)
    service, _cache, root, _values, _unused = _service(tmp_path, audit=audit)  # type: ignore[arg-type]
    challenge = _approval_challenge(service, root)
    prepared = threading.Event()
    release_prepare = threading.Event()
    registration_attempted = threading.Event()
    registration_finished = threading.Event()
    errors: list[BaseException] = []
    original_prepare = audit.prepare_mutation
    original_record = service._record

    def paused_prepare(**kwargs: object) -> PreparedMutation:
        assert audit.reservation_path.exists()
        result = original_prepare(**kwargs)  # type: ignore[arg-type]
        prepared.set()
        if not release_prepare.wait(5):
            raise AssertionError("test did not release the prepared mutation")
        return result

    def observed_record(event: str, context: object) -> str:
        if event == "registration_state":
            registration_attempted.set()
        return original_record(event, context)  # type: ignore[arg-type]

    audit.prepare_mutation = paused_prepare  # type: ignore[method-assign]
    service._record = observed_record  # type: ignore[method-assign]

    def confirm() -> None:
        try:
            _confirm_approval(service, root, str(challenge["confirmationToken"]))
        except BaseException as error:
            errors.append(error)

    def register() -> None:
        try:
            service.record_registration_state()
        except BaseException as error:
            errors.append(error)
        finally:
            registration_finished.set()

    mutation_thread = threading.Thread(target=confirm)
    registration_thread = threading.Thread(target=register)
    mutation_thread.start()
    assert prepared.wait(5)
    registration_thread.start()
    assert registration_attempted.wait(5)
    try:
        assert not registration_finished.wait(0.2)
    finally:
        release_prepare.set()
        mutation_thread.join(5)
        registration_thread.join(5)

    assert not mutation_thread.is_alive()
    assert not registration_thread.is_alive()
    assert errors == []
    events = _audit_events(audit)
    prepared_index = events.index("mutation_prepared")
    committed_index = events.index("mutation_committed")
    registration_index = events.index("registration_state")
    assert prepared_index < committed_index < registration_index


def test_atomic_store_write_failure_leaves_recoverable_prepared_tail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    audit = _real_audit(tmp_path)
    service, cache, root, _values, _unused = _service(tmp_path, audit=audit)  # type: ignore[arg-type]
    challenge = _approval_challenge(service, root)

    def fail_atomic_write(_path: Path, _data: bytes) -> None:
        raise OSError("C:/private/repository raw trust bytes")

    monkeypatch.setattr(trust_cache_module, "write_bytes_atomic", fail_atomic_write)

    with pytest.raises(TrustMutationError) as caught:
        _confirm_approval(service, root, str(challenge["confirmationToken"]))

    assert caught.value.code == "MCP_TRUST_MUTATION_PERSISTENCE_FAILED"
    assert "private" not in str(caught.value).lower()
    assert not cache.path.exists()
    assert _audit_events(audit)[-1] == "mutation_prepared"
    assert audit.reservation_path.exists()

    with pytest.raises(TrustMutationError) as unhealthy:
        service.approve(
            cwd=str(root),
            command="python another.py",
            expires_at=EXPIRES_AT,
            reason="must recover first",
        )
    assert unhealthy.value.code == "MCP_TRUST_MUTATION_RECOVERY_REQUIRED"
    assert _audit_events(audit)[-1] == "mutation_prepared"

    recovery = service.recover_startup()
    assert recovery.status == "recovery_aborted"
    assert not audit.reservation_path.exists()
    assert _audit_events(audit)[-1] == "recovery_aborted"


def test_shared_trust_lock_hard_link_is_rejected_as_unsafe_storage(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, cache, root, _values, _audit = _service(tmp_path)
    _approval_challenge(service, root)
    lock_path = cache.path.with_suffix(f"{cache.path.suffix}.lock")
    lock_path.unlink()
    source = lock_path.with_name("shared.lock")
    source.write_bytes(b"")
    os.link(source, lock_path)

    with pytest.raises(TrustMutationError) as caught:
        service.approve(
            cwd=str(root),
            command="python private_script.py",
            expires_at=EXPIRES_AT,
            reason="reviewed again",
        )

    assert caught.value.code == "MCP_TRUST_MUTATION_UNSAFE_STORAGE"


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL fixture")
def test_world_writable_trust_lock_acl_is_rejected_as_unsafe_storage(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    service, cache, root, _values, _audit = _service(tmp_path)
    _approval_challenge(service, root)
    lock_path = cache.path.with_suffix(f"{cache.path.suffix}.lock")
    changed = subprocess.run(
        ["icacls", str(lock_path), "/grant", "*S-1-1-0:(F)"],
        capture_output=True,
        text=True,
        check=False,
    )
    if changed.returncode != 0:
        pytest.skip("unable to create the unsafe Windows ACL fixture")

    with pytest.raises(TrustMutationError) as caught:
        service.approve(
            cwd=str(root),
            command="python private_script.py",
            expires_at=EXPIRES_AT,
            reason="reviewed again",
        )

    assert caught.value.code == "MCP_TRUST_MUTATION_UNSAFE_STORAGE"


def test_disabled_service_does_not_touch_cache_or_issue_a_challenge(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError, TrustMutationService

    service = TrustMutationService(enabled=False)
    with pytest.raises(TrustMutationError) as caught:
        service.approve(
            cwd=str(tmp_path),
            command="pytest",
            expires_at=EXPIRES_AT,
            reason="reviewed",
        )
    assert caught.value.code == "MCP_TRUST_MUTATION_DISABLED"
    assert not (tmp_path / "trust.json").exists()


def test_cancellation_timeout_and_nonexecution_are_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    cancelled, _cache, root, _values, _audit = _service(tmp_path / "cancelled", cancel_check=lambda: True)
    with pytest.raises(TrustMutationError) as cancellation:
        cancelled.approve(cwd=str(root), command="python private_script.py", expires_at=EXPIRES_AT, reason="reviewed")
    assert cancellation.value.code == "MCP_TRUST_MUTATION_CANCELLED"

    timeout, _cache, root, _values, _audit = _service(
        tmp_path / "timeout",
        monotonic=iter([0.0, 31.0]).__next__,
    )
    with pytest.raises(TrustMutationError) as elapsed:
        timeout.approve(cwd=str(root), command="python private_script.py", expires_at=EXPIRES_AT, reason="reviewed")
    assert elapsed.value.code == "MCP_TRUST_MUTATION_TIMEOUT"

    service, _cache, root, _values, _audit = _service(tmp_path / "nonexecution")

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("commands and network access are forbidden")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    _approval_challenge(service, root)


def test_bounded_fingerprint_preserves_legacy_bytes_and_stops_for_limits_timeout_and_cancel(
    tmp_path: Path,
) -> None:
    from codex_preflight_core.repo.fingerprint import (
        CriticalFingerprintError,
        compute_critical_fingerprint,
    )

    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("readme", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]", encoding="utf-8")
    legacy = compute_critical_fingerprint(root)
    bounded = compute_critical_fingerprint(
        root,
        max_files=4096,
        max_file_bytes=8 * 1024 * 1024,
        max_total_bytes=64 * 1024 * 1024,
        deadline=100.0,
        monotonic=lambda: 0.0,
    )
    assert bounded == legacy

    with pytest.raises(CriticalFingerprintError, match="limit"):
        compute_critical_fingerprint(root, max_files=1)
    with pytest.raises(CriticalFingerprintError, match="cancel"):
        compute_critical_fingerprint(root, cancellation_check=lambda: True)
    with pytest.raises(CriticalFingerprintError, match="timeout"):
        compute_critical_fingerprint(root, deadline=0.0, monotonic=lambda: 1.0)
