from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from importlib.util import find_spec

import pytest

pytestmark = pytest.mark.skipif(
    find_spec("mcp") is None,
    reason="optional MCP runtime is not installed",
)


def test_create_mcp_server_smoke() -> None:
    from codex_preflight_mcp.server import create_mcp_server

    server = create_mcp_server()

    assert server is not None


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


def test_codex_preflight_mcp_list_tools_cli_smoke() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "codex_preflight_mcp.server", "--list-tools"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    tools = json.loads(result.stdout)
    assert {tool["name"] for tool in tools} == {"preflight_check", "corpus_scan"}
