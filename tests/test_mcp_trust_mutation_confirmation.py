from __future__ import annotations

import base64
import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

import pytest

from codex_preflight_mcp.trust_mutation_confirmation import (
    TrustMutationConfirmationError,
    TrustMutationConfirmationManager,
)

ENTRY_ID = "123e4567-e89b-42d3-a456-426614174000"
SECRET = b"x" * 32


class Clock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _binding(*, tool: str = "trust_approve") -> dict[str, object]:
    return {
        "tool": tool,
        "operation": "approve",
        "target": {"repoId": "repo-identity", "commandScope": "test"},
    }


def _display() -> dict[str, object]:
    return {"title": "Approve trust", "repository": "caf\u00e9"}


def _resign(token: str, values: dict[str, object], secret: bytes = SECRET) -> str:
    encoded, _signature = token.split(".", 1)
    payload = json.loads(_decode(encoded))
    payload.update(values)
    updated = _encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _encode(hmac.new(secret, updated.encode("ascii"), hashlib.sha256).digest())
    return f"{updated}.{signature}"


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> str:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")


def test_issue_returns_immutable_bound_challenge_and_consumes_once() -> None:
    clock = Clock()
    manager = TrustMutationConfirmationManager(secret=SECRET, clock=clock)
    binding = _binding()
    display = _display()

    challenge = manager.issue("approve", binding, display, proposed_entry_id=ENTRY_ID)

    assert challenge.expires_at - challenge.issued_at == 300
    assert challenge.binding_digest == _binding_digest(binding)
    assert challenge.display == display
    assert challenge.proposed_entry_id == ENTRY_ID
    with pytest.raises(FrozenInstanceError):
        challenge.challenge_id = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        challenge.display["title"] = "changed"  # type: ignore[index]

    consumed = manager.authenticate_and_consume(challenge.token)

    assert consumed.challenge_id == challenge.challenge_id
    assert consumed.issued_at == challenge.issued_at
    assert consumed.expires_at == challenge.expires_at
    assert consumed.binding_digest == challenge.binding_digest
    assert consumed.binding == binding
    assert consumed.display == display
    assert consumed.proposed_entry_id == ENTRY_ID
    with pytest.raises(TrustMutationConfirmationError, match="CONFIRMATION_INVALID") as replay:
        manager.authenticate_and_consume(challenge.token)
    assert replay.value.code == "MCP_TRUST_MUTATION_CONFIRMATION_INVALID"


def test_confirmation_rejects_expiry_restart_signature_and_wrong_tool_binding() -> None:
    clock = Clock()
    manager = TrustMutationConfirmationManager(secret=SECRET, clock=clock)
    challenge = manager.issue("approve", _binding(), _display(), proposed_entry_id=ENTRY_ID)

    clock.value += 301
    with pytest.raises(TrustMutationConfirmationError, match="CONFIRMATION_EXPIRED") as expired:
        manager.authenticate_and_consume(challenge.token)
    assert expired.value.code == "MCP_TRUST_MUTATION_CONFIRMATION_EXPIRED"

    fresh = TrustMutationConfirmationManager(secret=SECRET, clock=Clock())
    challenge = fresh.issue("approve", _binding(), _display(), proposed_entry_id=ENTRY_ID)
    with pytest.raises(TrustMutationConfirmationError, match="CONFIRMATION_INVALID"):
        TrustMutationConfirmationManager(secret=b"y" * 32, clock=Clock()).authenticate_and_consume(challenge.token)
    replacement = "A" if challenge.token[-1] != "A" else "B"
    with pytest.raises(TrustMutationConfirmationError, match="CONFIRMATION_INVALID"):
        fresh.authenticate_and_consume(f"{challenge.token[:-1]}{replacement}")

    wrong_tool_token = _resign(
        challenge.token,
        {"bindingDigest": _binding_digest(_binding(tool="trust_revoke"))},
    )
    with pytest.raises(TrustMutationConfirmationError, match="CONFIRMATION_INVALID"):
        fresh.authenticate_and_consume(wrong_tool_token)


@pytest.mark.parametrize("token", ["\u00e9.payload", "a" * 1025])
def test_confirmation_rejects_unicode_and_tokens_over_1024_bytes(token: object) -> None:
    manager = TrustMutationConfirmationManager(secret=SECRET, clock=Clock())

    with pytest.raises(TrustMutationConfirmationError, match="CONFIRMATION_INVALID") as caught:
        manager.authenticate_and_consume(token)

    assert caught.value.code == "MCP_TRUST_MUTATION_CONFIRMATION_INVALID"


def test_confirmation_token_is_bounded_and_does_not_expose_private_binding() -> None:
    manager = TrustMutationConfirmationManager(secret=SECRET, clock=Clock())
    binding = {"tool": "trust_approve", "private": "secret value"}
    challenge = manager.issue("approve", binding, _display(), proposed_entry_id=ENTRY_ID)

    assert len(challenge.token.encode("utf-8")) <= 1024
    assert "secret value" not in challenge.token
    assert "caf\u00e9" not in challenge.token


def test_confirmation_allows_at_most_128_live_records_without_eviction() -> None:
    clock = Clock()
    manager = TrustMutationConfirmationManager(secret=SECRET, clock=clock)

    for index in range(128):
        clock.value = 1_000 + index * 2
        manager.issue("approve", _binding(), _display(), proposed_entry_id=f"entry-{index}")

    with pytest.raises(TrustMutationConfirmationError, match="CONFIRMATION_CAPACITY") as full:
        manager.issue("approve", _binding(), _display(), proposed_entry_id="entry-overflow")
    assert full.value.code == "MCP_TRUST_MUTATION_CONFIRMATION_CAPACITY"

    clock.value += 46
    manager.issue("approve", _binding(), _display(), proposed_entry_id="entry-after-expiry")


def test_confirmation_limits_issues_to_32_per_rolling_minute() -> None:
    clock = Clock()
    manager = TrustMutationConfirmationManager(secret=SECRET, clock=clock)

    for index in range(32):
        manager.issue("approve", _binding(), _display(), proposed_entry_id=f"entry-{index}")

    with pytest.raises(TrustMutationConfirmationError, match="CONFIRMATION_RATE_LIMITED") as limited:
        manager.issue("approve", _binding(), _display(), proposed_entry_id="entry-overflow")
    assert limited.value.code == "MCP_TRUST_MUTATION_CONFIRMATION_RATE_LIMITED"

    clock.value += 60
    manager.issue("approve", _binding(), _display(), proposed_entry_id="entry-after-window")


def test_confirmation_concurrent_consumption_has_one_winner_and_invalidate_all_revokes_tokens() -> None:
    manager = TrustMutationConfirmationManager(secret=SECRET, clock=Clock())
    challenge = manager.issue("approve", _binding(), _display(), proposed_entry_id=ENTRY_ID)

    def attempt() -> str:
        try:
            manager.authenticate_and_consume(challenge.token)
        except TrustMutationConfirmationError as error:
            return error.code
        return "consumed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _item: attempt(), range(2)))
    assert outcomes == ["MCP_TRUST_MUTATION_CONFIRMATION_INVALID", "consumed"]

    outstanding = manager.issue("approve", _binding(), _display(), proposed_entry_id="another-entry")
    manager.invalidate_all()
    with pytest.raises(TrustMutationConfirmationError, match="CONFIRMATION_INVALID"):
        manager.authenticate_and_consume(outstanding.token)


def _binding_digest(binding: dict[str, object]) -> str:
    serialized = json.dumps(binding, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()
