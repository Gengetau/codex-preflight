from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import timedelta
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, TextContent

COMMAND_SCOPES = (
    "dependency_install",
    "script_execution",
    "build",
    "test",
    "docker",
    "network_shell",
    "mcp_server_start",
    "unknown_shell",
)


async def list_trust(repo_id: str | None, command_scope: str | None, limit: int) -> dict[str, Any]:
    environment = {**os.environ, "CODEX_PREFLIGHT_ENABLE_TRUST_READ": "1"}
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "codex_preflight_mcp.server"],
        env=environment,
    )
    arguments: dict[str, object] = {"limit": limit}
    if repo_id is not None:
        arguments["repoId"] = repo_id
    if command_scope is not None:
        arguments["commandScope"] = command_scope
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                "trust_list",
                arguments=arguments,
                read_timeout_seconds=timedelta(seconds=30),
            )
    return _result_payload(result)


def _result_payload(result: CallToolResult) -> dict[str, Any]:
    if result.isError:
        detail = _decode_error(result)
        raise RuntimeError(
            f"{detail.get('code', 'MCP_ERROR')}: {detail.get('message', 'MCP request failed')} "
            f"Remediation: {detail.get('remediation', 'Review the request and retry.')}"
        )
    if result.structuredContent is None:
        raise RuntimeError("The MCP server returned no structured result.")
    return result.structuredContent


def _decode_error(result: CallToolResult) -> dict[str, Any]:
    text = "\n".join(block.text for block in result.content if isinstance(block, TextContent))
    start = text.find('{"error":')
    if start < 0:
        return {"code": "MCP_ERROR", "message": text}
    try:
        return json.loads(text[start:])["error"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return {"code": "MCP_ERROR", "message": text}


def main() -> None:
    parser = argparse.ArgumentParser(description="List bounded redacted trust metadata over MCP stdio.")
    parser.add_argument("--repo-id", help="Optional exact stored identity filter; never returned.")
    parser.add_argument("--command-scope", choices=COMMAND_SCOPES)
    parser.add_argument("--limit", type=int, choices=range(1, 101), default=50)
    args = parser.parse_args()
    result = asyncio.run(list_trust(args.repo_id, args.command_scope, args.limit))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
