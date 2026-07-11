from __future__ import annotations

import asyncio
import os
import sys
from importlib.util import find_spec
from pathlib import Path

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

    from codex_preflight_mcp.server import TRUST_SERVER_INSTRUCTIONS

    async def initialize() -> tuple[str | None, set[str]]:
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
                return result.instructions, {tool.name for tool in tools.tools}

    instructions, tool_names = asyncio.run(initialize())
    assert instructions == TRUST_SERVER_INSTRUCTIONS
    assert tool_names == {"preflight_check", "corpus_scan", "trust_list"}
    audit = tmp_path / "trust-read" / "audit.jsonl"
    assert audit.exists()
    assert '"event":"registration_state"' in audit.read_text(encoding="utf-8")
