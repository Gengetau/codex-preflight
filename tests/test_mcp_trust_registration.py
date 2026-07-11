from __future__ import annotations

import asyncio
from typing import Any

import pytest

from codex_preflight_mcp.errors import McpErrorCode, McpToolError
from codex_preflight_mcp.trust_read import TrustReadError


def _tool_names() -> list[str]:
    from codex_preflight_mcp.server import tool_definitions

    return [tool["name"] for tool in tool_definitions()]


@pytest.mark.parametrize(
    ("remote", "trust", "expected"),
    [
        (False, False, ["preflight_check", "corpus_scan"]),
        (True, False, ["preflight_check", "corpus_scan", "remote_repository_scan"]),
        (False, True, ["preflight_check", "corpus_scan", "trust_list"]),
        (
            True,
            True,
            ["preflight_check", "corpus_scan", "remote_repository_scan", "trust_list"],
        ),
    ],
)
def test_startup_flags_select_exact_tool_inventory(
    monkeypatch: pytest.MonkeyPatch,
    remote: bool,
    trust: bool,
    expected: list[str],
) -> None:
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", raising=False)
    if remote:
        monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")
    if trust:
        monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")

    names = _tool_names()

    assert names == expected
    assert "trust_approve" not in names
    assert "trust_revoke" not in names


@pytest.mark.parametrize("value", ["", "0", "true", "TRUE", "yes", "2", " 1"])
def test_only_exact_one_enables_trust_read_registration(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", value)

    assert _tool_names() == ["preflight_check", "corpus_scan"]


def test_trust_list_schema_is_closed_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_preflight_mcp.server import tool_definitions

    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")

    trust = next(tool for tool in tool_definitions() if tool["name"] == "trust_list")

    assert trust["inputSchema"] == {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "repoId": {
                "type": "string",
                "description": "Exact stored repository identity filter; never opened or returned.",
            },
            "commandScope": {
                "type": "string",
                "enum": [
                    "dependency_install",
                    "script_execution",
                    "build",
                    "test",
                    "docker",
                    "network_shell",
                    "mcp_server_start",
                    "unknown_shell",
                ],
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 50,
            },
            "cursor": {
                "type": "string",
                "maxLength": 512,
            },
        },
    }
    assert "read-only" in trust["description"]
    assert "cannot approve, revoke, extend, consume, satisfy, or create trust" in trust["description"]


def test_direct_trust_list_call_is_disabled_without_startup_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp.server import trust_list

    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", raising=False)

    with pytest.raises(McpToolError) as caught:
        trust_list()

    assert caught.value.detail.code is McpErrorCode.TRUST_READ_DISABLED


def test_trust_list_maps_service_and_unknown_argument_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp import server

    class FailingService:
        def list(self, **_kwargs: object) -> dict[str, Any]:
            raise TrustReadError(
                "MCP_TRUST_LIST_CORRUPT",
                "The local trust store is corrupt.",
            )

        def reject_invalid_argument(self, *, field: str | None) -> None:
            raise TrustReadError(
                "MCP_TRUST_LIST_INVALID_ARGUMENT",
                "trust_list received an unsupported argument.",
                field=field,
            )

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    monkeypatch.setattr(server, "default_trust_read_service", FailingService)

    with pytest.raises(McpToolError) as corrupt:
        server.trust_list()
    with pytest.raises(McpToolError) as unknown:
        server.trust_list(outputPath="private/path")

    assert corrupt.value.detail.code is McpErrorCode.TRUST_LIST_CORRUPT
    assert "private/path" not in str(unknown.value)
    assert unknown.value.detail.code is McpErrorCode.TRUST_LIST_INVALID_ARGUMENT
    assert unknown.value.detail.field == "outputPath"


def test_runtime_registration_uses_named_schema_and_audits_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp import server

    class RecordingService:
        def __init__(self) -> None:
            self.registration_calls = 0

        def record_registration_state(self) -> str:
            self.registration_calls += 1
            return "registration-event"

        def list(self, **_kwargs: object) -> dict[str, Any]:
            return {"tool": "trust_list"}

    service = RecordingService()
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    monkeypatch.setattr(server, "default_trust_read_service", lambda: service)

    mcp = server.create_mcp_server()
    registered = mcp._tool_manager.get_tool("trust_list")
    definition = next(tool for tool in server.tool_definitions() if tool["name"] == "trust_list")

    assert service.registration_calls == 1
    assert registered is not None
    assert registered.parameters == definition["inputSchema"]


def test_registration_audit_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_preflight_mcp import server

    class FailingService:
        def record_registration_state(self) -> str:
            raise TrustReadError(
                "MCP_TRUST_LIST_AUDIT_FAILED",
                "The dedicated trust-read audit log failed closed.",
            )

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    monkeypatch.setattr(server, "default_trust_read_service", FailingService)

    with pytest.raises(McpToolError) as caught:
        server.create_mcp_server()

    assert caught.value.detail.code is McpErrorCode.TRUST_LIST_AUDIT_FAILED


@pytest.mark.parametrize(
    ("arguments", "expected_code"),
    [
        ({"outputPath": "private/path"}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"repoId": None}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"repoId": 7}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"repoId": "repo\ud800value"}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"commandScope": None}, "MCP_TRUST_LIST_INVALID_ARGUMENT"),
        ({"limit": None}, "MCP_TRUST_LIST_LIMIT_EXCEEDED"),
        ({"limit": "1"}, "MCP_TRUST_LIST_LIMIT_EXCEEDED"),
        ({"cursor": None}, "MCP_TRUST_LIST_CURSOR_INVALID"),
    ],
)
def test_transport_arguments_use_stable_trust_errors(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: dict[str, object],
    expected_code: str,
) -> None:
    from codex_preflight_mcp import server

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    monkeypatch.setenv("CODEX_PREFLIGHT_HOME", str(tmp_path))
    mcp = server.create_mcp_server()

    with pytest.raises(Exception) as caught:
        asyncio.run(mcp._tool_manager.call_tool("trust_list", arguments))

    assert expected_code in str(caught.value)
    assert "private/path" not in str(caught.value)


def test_transport_adapter_preserves_success_response(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp import server

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    monkeypatch.setenv("CODEX_PREFLIGHT_HOME", str(tmp_path))
    mcp = server.create_mcp_server()

    result = asyncio.run(mcp._tool_manager.call_tool("trust_list", {}))

    assert result["tool"] == "trust_list"
    assert result["entries"] == []
    assert result["pagination"]["limit"] == 50


def test_unknown_transport_argument_is_audited(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    from codex_preflight_mcp import server

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    monkeypatch.setenv("CODEX_PREFLIGHT_HOME", str(tmp_path))
    mcp = server.create_mcp_server()

    with pytest.raises(Exception, match="MCP_TRUST_LIST_INVALID_ARGUMENT"):
        asyncio.run(mcp._tool_manager.call_tool("trust_list", {"outputPath": "private/path"}))

    records = [
        json.loads(line)
        for line in (tmp_path / "trust-read" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [record["event"] for record in records] == [
        "registration_state",
        "request_validation_failed",
    ]


def test_unknown_argument_audit_failure_takes_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_preflight_mcp import server

    class AuditFailService:
        def record_registration_state(self) -> str:
            return "registration-event"

        def reject_invalid_argument(self, *, field: str | None) -> None:
            raise TrustReadError(
                "MCP_TRUST_LIST_AUDIT_FAILED",
                "The dedicated trust-read audit log failed closed.",
                field=field,
            )

        def list(self, **_kwargs: object) -> dict[str, Any]:
            return {"tool": "trust_list"}

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    monkeypatch.setattr(server, "default_trust_read_service", AuditFailService)
    mcp = server.create_mcp_server()

    with pytest.raises(Exception) as caught:
        asyncio.run(mcp._tool_manager.call_tool("trust_list", {"outputPath": "private/path"}))

    assert "MCP_TRUST_LIST_AUDIT_FAILED" in str(caught.value)
    assert "MCP_TRUST_LIST_INVALID_ARGUMENT" not in str(caught.value)


def test_unexpected_trust_list_failure_is_normalized_without_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_mcp import server

    class FailingService:
        def list(self, **_kwargs: object) -> dict[str, Any]:
            raise RuntimeError("C:/private/trust.json secret detail")

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    monkeypatch.setattr(server, "default_trust_read_service", FailingService)

    with pytest.raises(McpToolError) as caught:
        server.trust_list()

    assert caught.value.detail.code is McpErrorCode.TRUST_LIST_INTERNAL_ERROR
    assert caught.value.detail.retryable is True
    assert "private" not in str(caught.value)
    assert "secret" not in str(caught.value)
