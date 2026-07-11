from __future__ import annotations

import json
import socket
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from codex_preflight_core.cache.trust_cache import TrustCache
from codex_preflight_core.repo.identity import RepoIdentity
from codex_preflight_mcp.trust_mutation_audit import PreparedMutation, RecoveryResult
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

    def identity_resolver(path: Path) -> RepoIdentity:
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


def test_committed_audit_pending_invalidates_challenges_and_marks_service_unhealthy(tmp_path: Path) -> None:
    from codex_preflight_mcp.trust_mutation import TrustMutationError

    audit = RecordingAudit()
    audit.fail_commit = True
    service, cache, root, _values, _audit = _service(tmp_path, audit=audit)
    challenge = _approval_challenge(service, root)

    with pytest.raises(TrustMutationError) as pending:
        _confirm_approval(service, root, str(challenge["confirmationToken"]))
    assert pending.value.code == "MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING"
    assert pending.value.context["committed"] is True
    assert pending.value.context["operation"] == "approve"
    assert UUID(pending.value.context["entryId"]).version == 4
    assert UUID(pending.value.context["preparedAuditEventId"]).version == 4
    assert len(cache.list()) == 1

    with pytest.raises(TrustMutationError) as unhealthy:
        service.approve(
            cwd=str(root),
            command="python another.py",
            expires_at=EXPIRES_AT,
            reason="new request",
        )
    assert unhealthy.value.code == "MCP_TRUST_MUTATION_RECOVERY_REQUIRED"


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
