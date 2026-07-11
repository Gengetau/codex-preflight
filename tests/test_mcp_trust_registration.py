from __future__ import annotations

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
                "type": ["string", "null"],
                "default": None,
                "description": "Exact stored repository identity filter; never opened or returned.",
            },
            "commandScope": {
                "type": ["string", "null"],
                "enum": [
                    "dependency_install",
                    "script_execution",
                    "build",
                    "test",
                    "docker",
                    "network_shell",
                    "mcp_server_start",
                    "unknown_shell",
                    None,
                ],
                "default": None,
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 50,
            },
            "cursor": {
                "type": ["string", "null"],
                "maxLength": 512,
                "default": None,
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
