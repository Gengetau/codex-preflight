from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import timedelta
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def call_corpus(case_id: str | None) -> dict[str, Any]:
    server = StdioServerParameters(command=sys.executable, args=["-m", "codex_preflight_mcp.server"])
    arguments = {"case_id": case_id} if case_id else {}
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                "corpus_scan",
                arguments=arguments,
                read_timeout_seconds=timedelta(seconds=30),
            )
    if result.isError:
        raise RuntimeError("corpus_scan failed; inspect the structured MCP error content.")
    if result.structuredContent is None:
        raise RuntimeError("The MCP server returned no structured result.")
    return result.structuredContent


def main() -> None:
    parser = argparse.ArgumentParser(description="Call Codex Preflight corpus_scan over MCP stdio.")
    parser.add_argument("--case-id", help="Optional bundled corpus case identifier.")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(call_corpus(args.case_id)), indent=2))


if __name__ == "__main__":
    main()
