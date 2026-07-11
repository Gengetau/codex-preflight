from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from codex_preflight_mcp.remote_confirmation import (
    ConfirmationError,
    RemoteConfirmationManager,
)
from codex_preflight_mcp.remote_policy import ResourceLimits, validate_github_repository_url


class Clock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value


def issue(manager: RemoteConfirmationManager):
    return manager.issue(
        validate_github_repository_url("https://github.com/example/project"),
        "refs/heads/main",
        ResourceLimits(),
    )


def consume(manager: RemoteConfirmationManager, token: str) -> str:
    return manager.consume(
        token,
        validate_github_repository_url("https://github.com/example/project"),
        "refs/heads/main",
        ResourceLimits(),
    )


def test_confirmation_is_bound_and_consumed_once() -> None:
    clock = Clock()
    manager = RemoteConfirmationManager(secret=b"x" * 32, clock=clock)
    challenge = issue(manager)

    assert challenge.expires_at - challenge.issued_at == 300
    assert consume(manager, challenge.token) == challenge.challenge_id
    with pytest.raises(ConfirmationError) as replay:
        consume(manager, challenge.token)
    assert replay.value.code == "MCP_REMOTE_CONFIRMATION_REPLAYED"


def test_confirmation_rejects_argument_change_and_expiry() -> None:
    clock = Clock()
    manager = RemoteConfirmationManager(secret=b"x" * 32, clock=clock)
    challenge = issue(manager)

    with pytest.raises(ConfirmationError) as mismatch:
        manager.consume(
            challenge.token,
            validate_github_repository_url("https://github.com/example/other"),
            "refs/heads/main",
            ResourceLimits(),
        )
    assert mismatch.value.code == "MCP_REMOTE_CONFIRMATION_INVALID"

    clock.value += 301
    with pytest.raises(ConfirmationError) as expired:
        consume(manager, challenge.token)
    assert expired.value.code == "MCP_REMOTE_CONFIRMATION_EXPIRED"


def test_confirmation_cannot_survive_process_key_change() -> None:
    first = RemoteConfirmationManager(secret=b"x" * 32, clock=Clock())
    second = RemoteConfirmationManager(secret=b"y" * 32, clock=Clock())

    with pytest.raises(ConfirmationError) as caught:
        consume(second, issue(first).token)

    assert caught.value.code == "MCP_REMOTE_CONFIRMATION_INVALID"


def test_confirmation_concurrent_consume_has_one_winner() -> None:
    manager = RemoteConfirmationManager(secret=b"x" * 32, clock=Clock())
    token = issue(manager).token

    def attempt() -> str:
        try:
            consume(manager, token)
        except ConfirmationError as error:
            return error.code
        return "consumed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _item: attempt(), range(2)))

    assert outcomes == ["MCP_REMOTE_CONFIRMATION_REPLAYED", "consumed"]


def test_first_remote_call_returns_challenge_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp import server

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")
    monkeypatch.setattr(
        server,
        "run_remote_operation",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("network operation started")),
    )

    with pytest.raises(server.McpToolError) as caught:
        server.remote_repository_scan(
            remoteUrl="https://github.com/example/project",
            requestedRef="refs/heads/main",
        )

    detail = caught.value.to_dict()["error"]
    assert detail["code"] == "MCP_REMOTE_CONFIRMATION_REQUIRED"
    assert detail["field"] == "confirmationToken"
    assert detail["context"]["canonicalUrl"] == "https://github.com/example/project"
    assert detail["context"]["requestedRef"] == "refs/heads/main"
    assert detail["context"]["confirmationToken"]
    assert detail["context"]["expiresInSeconds"] == 300

