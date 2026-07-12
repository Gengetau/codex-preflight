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


async def approve_trust(cwd: str, command: str, expires_at: str, reason: str) -> dict[str, Any]:
    environment = {**os.environ, "CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION": "1"}
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "codex_preflight_mcp.server"],
        env=environment,
    )
    arguments = {
        "cwd": cwd,
        "command": command,
        "expiresAt": expires_at,
        "reason": reason,
    }
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            challenge_result = await session.call_tool(
                "trust_approve",
                arguments=arguments,
                read_timeout_seconds=timedelta(seconds=30),
            )
            confirmation = _confirmation_challenge(challenge_result)
            print(json.dumps(confirmation["display"], indent=2))
            # This client never supplies automatic confirmation.
            if input("Type CONFIRM to approve this exact local trust entry: ").strip() != "CONFIRM":
                raise RuntimeError("Trust approval was not confirmed; no trust entry was created.")
            result = await session.call_tool(
                "trust_approve",
                arguments={**arguments, "confirmationToken": confirmation["confirmationToken"]},
                read_timeout_seconds=timedelta(seconds=30),
            )
    return _success_payload(result)


def _confirmation_challenge(result: CallToolResult) -> dict[str, Any]:
    if not result.isError:
        raise RuntimeError("The first trust_approve call unexpectedly bypassed confirmation.")
    detail = _decode_error(result)
    if detail.get("code") != "MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED":
        raise RuntimeError(f"{detail.get('code', 'MCP_ERROR')}: {detail.get('message', 'MCP request failed')}")
    context = detail.get("context")
    if not isinstance(context, dict):
        raise RuntimeError("The server returned an invalid confirmation challenge.")
    confirmation = context.get("confirmation")
    if not isinstance(confirmation, dict) or not isinstance(confirmation.get("confirmationToken"), str):
        raise RuntimeError("The server returned an invalid confirmation challenge.")
    return confirmation


def _success_payload(result: CallToolResult) -> dict[str, Any]:
    if result.isError:
        detail = _decode_error(result)
        raise RuntimeError(
            f"{detail.get('code', 'MCP_ERROR')}: {detail.get('message', 'MCP request failed')} "
            f"Remediation: {detail.get('remediation', 'Request a new challenge before retrying.')}"
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
    parser = argparse.ArgumentParser(description="Request one human-confirmed local trust approval over MCP stdio.")
    parser.add_argument("cwd", help="Existing local repository path.")
    parser.add_argument("command", help="Exact planned command to record without executing it.")
    parser.add_argument("expires_at", help="Exact RFC3339 UTC Z approval expiry.")
    parser.add_argument("reason", help="Human review reason for this exact request.")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(approve_trust(args.cwd, args.command, args.expires_at, args.reason)), indent=2))


if __name__ == "__main__":
    main()
