from __future__ import annotations

import json

import pytest

from codex_preflight_mcp.errors import McpErrorCode, McpToolError


def tool_names() -> list[str]:
    from codex_preflight_mcp.server import tool_definitions

    return [tool["name"] for tool in tool_definitions()]


def test_remote_tool_registration_is_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)

    assert tool_names() == ["preflight_check", "corpus_scan"]


@pytest.mark.parametrize("value", ["", "0", "true", "TRUE", "yes", "2"])
def test_only_exact_one_enables_remote_registration(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", value)

    assert tool_names() == ["preflight_check", "corpus_scan"]


def test_enabled_inventory_adds_only_remote_repository_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")

    from codex_preflight_mcp.server import tool_definitions

    tools = tool_definitions()
    remote = tools[2]
    assert [tool["name"] for tool in tools] == [
        "preflight_check",
        "corpus_scan",
        "remote_repository_scan",
    ]
    assert remote["inputSchema"] == {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "remoteUrl": {"type": "string"},
            "requestedRef": {"type": "string"},
            "confirmationToken": {"type": ["string", "null"], "default": None},
        },
        "required": ["remoteUrl", "requestedRef"],
    }


def test_static_listing_respects_process_flag_without_runtime_probe(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_preflight_mcp import runtime_compatibility, server

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")
    monkeypatch.setattr(
        runtime_compatibility,
        "import_module",
        lambda _name: (_ for _ in ()).throw(AssertionError("runtime probe")),
    )

    assert server.main(["--list-tools"]) == 0
    assert [tool["name"] for tool in json.loads(capsys.readouterr().out)] == [
        "preflight_check",
        "corpus_scan",
        "remote_repository_scan",
    ]


def test_direct_remote_call_is_disabled_without_startup_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_preflight_mcp.server import remote_repository_scan

    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)

    with pytest.raises(McpToolError) as caught:
        remote_repository_scan(
            remoteUrl="https://github.com/example/project",
            requestedRef="refs/heads/main",
        )

    assert caught.value.detail.code is McpErrorCode.REMOTE_DISABLED


@pytest.mark.parametrize(
    ("code", "retryable"),
    [
        ("MCP_REMOTE_ADDRESS_NOT_ALLOWED", False),
        ("MCP_REMOTE_REF_NOT_FOUND", False),
        ("MCP_REMOTE_TIMEOUT", True),
        ("MCP_REMOTE_CANCELLED", False),
        ("MCP_REMOTE_LIMIT_EXCEEDED", False),
        ("MCP_REMOTE_TREE_UNSAFE", False),
        ("MCP_REMOTE_ACQUISITION_FAILED", True),
        ("MCP_REMOTE_SCAN_FAILED", False),
        ("MCP_REMOTE_CACHE_FAILED", False),
        ("MCP_REMOTE_CLEANUP_FAILED", False),
    ],
)
def test_remote_operation_errors_keep_stable_mcp_codes(
    monkeypatch: pytest.MonkeyPatch,
    code: str,
    retryable: bool,
) -> None:
    from codex_preflight_mcp import server
    from codex_preflight_mcp.remote_confirmation import RemoteConfirmationManager
    from codex_preflight_mcp.remote_operation import RemoteOperationError

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")
    monkeypatch.setattr(server, "_REMOTE_CONFIRMATIONS", RemoteConfirmationManager(secret=b"x" * 32))
    with pytest.raises(McpToolError) as challenge:
        server.remote_repository_scan(
            remoteUrl="https://github.com/example/project",
            requestedRef="refs/heads/main",
        )
    token = challenge.value.to_dict()["error"]["context"]["confirmationToken"]

    def fail(**_kwargs: object) -> dict:
        raise RemoteOperationError(code, "Stable remote failure.", retryable)

    monkeypatch.setattr(server, "run_remote_operation", fail)
    with pytest.raises(McpToolError) as caught:
        server.remote_repository_scan(
            remoteUrl="https://github.com/example/project",
            requestedRef="refs/heads/main",
            confirmationToken=token,
        )

    detail = caught.value.to_dict()["error"]
    assert detail["code"] == code
    assert detail["retryable"] is retryable
    assert "internal" not in detail["message"].lower()
