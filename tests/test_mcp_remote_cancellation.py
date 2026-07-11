from __future__ import annotations

import threading
import time

import anyio

from codex_preflight_mcp.remote_operation import CancellationToken, RemoteOperationError
from codex_preflight_mcp.server import _run_cancellable_remote


def test_mcp_cancellation_sets_core_token_and_waits_for_cleanup() -> None:
    started = threading.Event()
    cleaned = threading.Event()

    def operation(token: CancellationToken) -> dict:
        started.set()
        while not token.cancelled:
            time.sleep(0.005)
        cleaned.set()
        raise RemoteOperationError("MCP_REMOTE_CANCELLED", "cancelled")

    async def exercise() -> None:
        with anyio.move_on_after(0.1) as cancel_scope:
            await _run_cancellable_remote(operation)
        assert cancel_scope.cancel_called

    anyio.run(exercise)

    assert started.is_set()
    assert cleaned.is_set()
