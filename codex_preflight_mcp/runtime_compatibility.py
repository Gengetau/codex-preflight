from __future__ import annotations

import inspect
from collections.abc import Callable
from importlib import import_module
from importlib.util import find_spec
from typing import Any

MCP_RUNTIME_UPGRADE_COMMAND = 'python -m pip install --upgrade "codex-preflight[mcp]"'
MCP_RUNTIME_COMPATIBILITY_MESSAGE = (
    "Codex Preflight requires an instruction-capable MCP runtime. Install or upgrade with:\n"
    f"{MCP_RUNTIME_UPGRADE_COMMAND}"
)

_MISSING = object()


class McpRuntimeError(RuntimeError):
    """Base class for expected optional MCP runtime failures."""


class McpRuntimeMissingError(McpRuntimeError):
    """Raised when the optional MCP runtime cannot be discovered."""


class McpRuntimeCompatibilityError(McpRuntimeError):
    """Raised when FastMCP cannot preserve server initialization instructions."""


def create_instruction_capable_fastmcp(
    fastmcp_factory: Callable[..., Any] | None = None,
    *,
    name: str,
    instructions: str,
    runtime_finder: Callable[[str], object | None] = find_spec,
    runtime_loader: Callable[[], object] | None = None,
) -> Any:
    """Construct and return one FastMCP instance after fail-closed verification."""
    factory = fastmcp_factory
    if factory is None:
        factory = _load_fastmcp_factory(
            runtime_finder=runtime_finder,
            runtime_loader=runtime_loader,
        )
    _require_explicit_instructions_parameter(factory)

    try:
        server = factory(name, instructions=instructions)
        public_instructions = getattr(server, "instructions", _MISSING)
        underlying_server = getattr(server, "_mcp_server", _MISSING)
        underlying_instructions = getattr(underlying_server, "instructions", _MISSING)
        initialization_options = underlying_server.create_initialization_options()
        initialization_instructions = getattr(initialization_options, "instructions", _MISSING)
    except Exception as error:
        raise McpRuntimeCompatibilityError(MCP_RUNTIME_COMPATIBILITY_MESSAGE) from error

    if not all(
        observed == instructions
        for observed in (
            public_instructions,
            underlying_instructions,
            initialization_instructions,
        )
    ):
        raise McpRuntimeCompatibilityError(MCP_RUNTIME_COMPATIBILITY_MESSAGE)
    return server


def _load_fastmcp_factory(
    *,
    runtime_finder: Callable[[str], object | None],
    runtime_loader: Callable[[], object] | None,
) -> Callable[..., Any]:
    try:
        runtime_spec = runtime_finder("mcp")
    except Exception as error:
        raise McpRuntimeCompatibilityError(MCP_RUNTIME_COMPATIBILITY_MESSAGE) from error
    if runtime_spec is None:
        raise McpRuntimeMissingError(MCP_RUNTIME_COMPATIBILITY_MESSAGE)

    try:
        module = runtime_loader() if runtime_loader is not None else import_module("mcp.server.fastmcp")
        factory = module.FastMCP
    except Exception as error:
        raise McpRuntimeCompatibilityError(MCP_RUNTIME_COMPATIBILITY_MESSAGE) from error
    if not callable(factory):
        raise McpRuntimeCompatibilityError(MCP_RUNTIME_COMPATIBILITY_MESSAGE)
    return factory


def _require_explicit_instructions_parameter(factory: Callable[..., Any]) -> None:
    try:
        parameter = inspect.signature(factory).parameters.get("instructions")
    except (TypeError, ValueError) as error:
        raise McpRuntimeCompatibilityError(MCP_RUNTIME_COMPATIBILITY_MESSAGE) from error
    if parameter is None or parameter.kind not in {
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    }:
        raise McpRuntimeCompatibilityError(MCP_RUNTIME_COMPATIBILITY_MESSAGE)
