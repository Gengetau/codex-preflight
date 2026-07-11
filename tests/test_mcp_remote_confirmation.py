from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

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


@pytest.mark.parametrize("token", ["é.payload", "a" * 9000 + ".signature"])
def test_confirmation_rejects_unicode_and_oversized_tokens_stably(token: str) -> None:
    manager = RemoteConfirmationManager(secret=b"x" * 32, clock=Clock())

    with pytest.raises(ConfirmationError) as caught:
        consume(manager, token)

    assert caught.value.code == "MCP_REMOTE_CONFIRMATION_INVALID"


def test_confirmation_ledger_is_bounded_without_enabling_replay() -> None:
    manager = RemoteConfirmationManager(secret=b"x" * 32, clock=Clock(), max_records=2)
    first = issue(manager)
    second = issue(manager)
    third = issue(manager)

    with pytest.raises(ConfirmationError) as evicted:
        consume(manager, first.token)
    assert evicted.value.code == "MCP_REMOTE_CONFIRMATION_INVALID"
    assert consume(manager, second.token) == second.challenge_id
    assert consume(manager, third.token) == third.challenge_id


def test_first_remote_call_returns_challenge_without_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_preflight_mcp import server

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")
    monkeypatch.setenv("CODEX_PREFLIGHT_HOME", str(tmp_path))
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
    assert not (tmp_path / "remote" / "scan-cache.json").exists()


def test_confirmation_audit_records_issue_and_consume_without_raw_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_preflight_mcp import server

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")
    monkeypatch.setenv("CODEX_PREFLIGHT_HOME", str(tmp_path))
    monkeypatch.setattr(server, "_REMOTE_CONFIRMATIONS", RemoteConfirmationManager(secret=b"x" * 32))
    monkeypatch.setattr(
        server,
        "run_remote_operation",
        lambda **_kwargs: {"decision": "ALLOW", "repo": {}, "remoteProvenance": {}},
    )

    with pytest.raises(server.McpToolError) as challenge:
        server.remote_repository_scan(
            remoteUrl="https://github.com/example/project",
            requestedRef="refs/heads/main",
        )
    token = challenge.value.to_dict()["error"]["context"]["confirmationToken"]
    result = server.remote_repository_scan(
        remoteUrl="https://github.com/example/project",
        requestedRef="refs/heads/main",
        confirmationToken=token,
    )

    audit_path = tmp_path / "remote" / "audit.jsonl"
    audit_text = audit_path.read_text(encoding="utf-8")
    events = [json.loads(line)["event"] for line in audit_text.splitlines()]
    assert events == ["challenge_issue", "confirmation_consume"]
    assert result["safety"]["remoteRepositoryAccess"] is True
    assert token not in audit_text
    assert "https://github.com/example/project" not in audit_text
    assert "refs/heads/main" not in audit_text
