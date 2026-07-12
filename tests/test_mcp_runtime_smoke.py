from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from importlib.util import find_spec
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(
    find_spec("mcp") is None,
    reason="optional MCP runtime is not installed",
)


def test_create_mcp_server_smoke() -> None:
    from codex_preflight_mcp.server import SERVER_INSTRUCTIONS, create_mcp_server

    server = create_mcp_server()

    assert server is not None
    assert server.instructions == SERVER_INSTRUCTIONS
    assert server._mcp_server.instructions == SERVER_INSTRUCTIONS
    assert server._mcp_server.create_initialization_options().instructions == SERVER_INSTRUCTIONS


def test_fastmcp_runtime_uses_public_tool_names_required_schema_and_error_codes() -> None:
    from codex_preflight_mcp.server import create_mcp_server

    server = create_mcp_server()
    preflight_tool = server._tool_manager.get_tool("preflight_check")
    corpus_tool = server._tool_manager.get_tool("corpus_scan")

    assert preflight_tool is not None
    assert corpus_tool is not None
    assert preflight_tool.parameters["required"] == ["cwd", "command"]

    with pytest.raises(Exception) as caught:
        asyncio.run(server._tool_manager.call_tool("preflight_check", {"command": "pytest"}))

    assert "MCP_CWD_REQUIRED" in str(caught.value)
    assert "Traceback" not in str(caught.value)


def test_stdio_initialization_returns_fixed_server_instructions() -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from codex_preflight_mcp.server import SERVER_INSTRUCTIONS

    async def initialize() -> tuple[str | None, set[str]]:
        parameters = StdioServerParameters(command=sys.executable, args=["-m", "codex_preflight_mcp.server"])
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                result = await session.initialize()
                tools = await session.list_tools()
                return result.instructions, {tool.name for tool in tools.tools}

    instructions, tool_names = asyncio.run(initialize())
    assert instructions == SERVER_INSTRUCTIONS
    assert tool_names == {"preflight_check", "corpus_scan"}


def test_stdio_trust_read_initialization_registers_exact_inventory(tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.types import TextContent

    from codex_preflight_mcp.server import TRUST_SERVER_INSTRUCTIONS

    async def initialize() -> tuple[str | None, set[str], dict, str]:
        environment = {
            **os.environ,
            "CODEX_PREFLIGHT_ENABLE_TRUST_READ": "1",
            "CODEX_PREFLIGHT_HOME": str(tmp_path),
        }
        environment.pop("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", None)
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "codex_preflight_mcp.server"],
            env=environment,
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                result = await session.initialize()
                tools = await session.list_tools()
                trust_result = await session.call_tool("trust_list", arguments={})
                assert trust_result.structuredContent is not None
                invalid = await session.call_tool(
                    "trust_list",
                    arguments={"outputPath": "private/path"},
                )
                invalid_text = "\n".join(
                    item.text for item in invalid.content if isinstance(item, TextContent)
                )
                return (
                    result.instructions,
                    {tool.name for tool in tools.tools},
                    trust_result.structuredContent,
                    invalid_text,
                )

    instructions, tool_names, trust_result, invalid_text = asyncio.run(initialize())
    assert instructions == TRUST_SERVER_INSTRUCTIONS
    assert tool_names == {"preflight_check", "corpus_scan", "trust_list"}
    assert trust_result["tool"] == "trust_list"
    assert trust_result["entries"] == []
    assert "MCP_TRUST_LIST_INVALID_ARGUMENT" in invalid_text
    assert "private/path" not in invalid_text
    audit = tmp_path / "trust-read" / "audit.jsonl"
    assert audit.exists()
    assert '"event":"registration_state"' in audit.read_text(encoding="utf-8")


def test_stdio_mutation_flow(tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    repository = tmp_path / "repository"
    subprocess.run(["git", "init", "--initial-branch=main", str(repository)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.email", "codex@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "Codex Test"], check=True)
    (repository / "README.md").write_text("local test repository\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-m", "initial"], check=True, capture_output=True)
    expires_at = (datetime.now(UTC) + timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")

    def error_detail(result: Any) -> dict[str, object]:
        structured = result.structuredContent
        if hasattr(structured, "model_dump"):
            structured = structured.model_dump()
        if isinstance(structured, dict) and isinstance(structured.get("error"), dict):
            return structured["error"]
        content = result.content
        text = "\n".join(str(item.text) for item in content if hasattr(item, "text"))
        if not text:
            raise AssertionError(f"MCP error response had no serializable envelope: {result!r}")
        start = text.find('{"error":')
        if start >= 0:
            text = text[start:]
        try:
            return json.loads(text)["error"]
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise AssertionError(f"MCP error response was not a stable envelope: {text!r}") from error

    async def exercise(state_home: Path) -> tuple[dict, dict, dict, dict]:
        environment = {
            **os.environ,
            "CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION": "1",
            "CODEX_PREFLIGHT_HOME": str(state_home),
        }
        environment.pop("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", None)
        environment.pop("CODEX_PREFLIGHT_ENABLE_TRUST_READ", None)
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "codex_preflight_mcp.server"],
            env=environment,
        )
        approve = {
            "cwd": str(repository),
            "command": "pytest",
            "expiresAt": expires_at,
            "reason": "Human reviewed this exact local test target.",
        }
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                approval_challenge = await session.call_tool("trust_approve", arguments=approve)
                challenge = error_detail(approval_challenge)
                if challenge["code"] != "MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED":
                    raise AssertionError(challenge)
                token = challenge["context"]["confirmation"]["confirmationToken"]
                approved = await session.call_tool(
                    "trust_approve",
                    arguments={**approve, "confirmationToken": token},
                )
                if approved.structuredContent is None:
                    raise AssertionError(error_detail(approved))
                entry_id = approved.structuredContent["entry"]["entryId"]
                revoke = {
                    "trustEntryId": entry_id,
                    "expectedVersion": 1,
                    "reason": "Human reviewed this exact removal.",
                }
                revoke_challenge = await session.call_tool("trust_revoke", arguments=revoke)
                revoke_confirmation = error_detail(revoke_challenge)
                revoke_token = revoke_confirmation["context"]["confirmation"]["confirmationToken"]
                revoked = await session.call_tool(
                    "trust_revoke",
                    arguments={**revoke, "confirmationToken": revoke_token},
                )
                replay = await session.call_tool(
                    "trust_revoke",
                    arguments={**revoke, "confirmationToken": revoke_token},
                )
                assert revoked.structuredContent is not None
                return challenge, approved.structuredContent, revoked.structuredContent, error_detail(replay)

    challenge, approved, revoked, replay = asyncio.run(exercise(tmp_path / "state"))

    assert challenge["code"] == "MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED"
    assert approved["outcome"] == "approved"
    assert revoked["outcome"] == "revoked"
    assert replay["code"] == "MCP_TRUST_MUTATION_CONFIRMATION_INVALID"
