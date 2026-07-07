from __future__ import annotations

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
