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


async def scan_remote(remote_url: str, requested_ref: str) -> dict[str, Any]:
    environment = {**os.environ, "CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN": "1"}
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "codex_preflight_mcp.server"],
        env=environment,
    )
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            challenge_result = await session.call_tool(
                "remote_repository_scan",
                arguments={"remoteUrl": remote_url, "requestedRef": requested_ref},
                read_timeout_seconds=timedelta(seconds=30),
            )
            challenge = _confirmation_challenge(challenge_result)
            _display_challenge(challenge)
            if input("Type CONFIRM to authorize this exact bounded network scan: ").strip() != "CONFIRM":
                raise RuntimeError("Remote scan was not confirmed; no network request was started.")
            result = await session.call_tool(
                "remote_repository_scan",
                arguments={
                    "remoteUrl": remote_url,
                    "requestedRef": requested_ref,
                    "confirmationToken": challenge["confirmationToken"],
                },
                read_timeout_seconds=timedelta(seconds=120),
            )
    return _success_payload(result)


def _confirmation_challenge(result: CallToolResult) -> dict[str, Any]:
    if not result.isError:
        raise RuntimeError("The first remote call unexpectedly bypassed confirmation.")
    detail = _decode_error(result)
    if detail.get("code") != "MCP_REMOTE_CONFIRMATION_REQUIRED":
        raise RuntimeError(f"{detail.get('code', 'MCP_ERROR')}: {detail.get('message', 'MCP request failed')}")
    context = detail.get("context")
    if not isinstance(context, dict) or not isinstance(context.get("confirmationToken"), str):
        raise RuntimeError("The server returned an invalid confirmation challenge.")
    return context


def _display_challenge(challenge: dict[str, Any]) -> None:
    safe_display = {
        "canonicalUrl": challenge.get("canonicalUrl"),
        "requestedRef": challenge.get("requestedRef"),
        "expiresInSeconds": challenge.get("expiresInSeconds"),
        "resourceLimits": challenge.get("resourceLimits"),
        "networkAccessRequired": challenge.get("networkAccessRequired"),
        "trustCreated": challenge.get("trustCreated"),
    }
    print(json.dumps(safe_display, indent=2))


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
    parser = argparse.ArgumentParser(description="Confirm and run a bounded public GitHub MCP static scan.")
    parser.add_argument("remote_url", help="Public https://github.com/OWNER/REPOSITORY URL.")
    parser.add_argument("requested_ref", help="Explicit branch, tag, full ref, or 40-hex commit.")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(scan_remote(args.remote_url, args.requested_ref)), indent=2))


if __name__ == "__main__":
    main()
