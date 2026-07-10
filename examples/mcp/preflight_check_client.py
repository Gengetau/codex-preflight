from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult, TextContent


async def call_preflight(cwd: Path, command: str) -> dict[str, Any]:
    server = StdioServerParameters(command=sys.executable, args=["-m", "codex_preflight_mcp.server"])
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                "preflight_check",
                arguments={"cwd": str(cwd), "command": command, "format": "json"},
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
        return {"code": "MCP_ERROR", "message": text, "remediation": "Review the MCP server logs."}
    try:
        return json.loads(text[start:])["error"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return {"code": "MCP_ERROR", "message": text, "remediation": "Review the MCP server logs."}


def main() -> None:
    parser = argparse.ArgumentParser(description="Call Codex Preflight preflight_check over MCP stdio.")
    parser.add_argument("cwd", type=Path, help="Existing local repository directory.")
    parser.add_argument("command", help="Planned command to analyze without executing.")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(call_preflight(args.cwd, args.command)), indent=2))


if __name__ == "__main__":
    main()
