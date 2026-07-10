from __future__ import annotations

import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_preflight_mcp.runtime_compatibility import (
    MCP_RUNTIME_COMPATIBILITY_MESSAGE,
    MCP_RUNTIME_UPGRADE_COMMAND,
    McpRuntimeCompatibilityError,
    McpRuntimeMissingError,
    create_instruction_capable_fastmcp,
)

INSTRUCTIONS = "FIXED_TEST_SERVER_INSTRUCTIONS"
ROOT = Path(__file__).resolve().parents[1]


class CompatibleFastMCP:
    def __init__(self, name: str | None = None, instructions: str | None = None) -> None:
        self.name = name
        self.instructions = instructions
        self._mcp_server = _UnderlyingServer(instructions, instructions)


class LegacyFastMCP:
    constructed = False

    def __init__(self, name: str | None = None, **settings: object) -> None:
        type(self).constructed = True
        self.name = name
        self.settings = settings


class DroppingFastMCP:
    ran = False

    def __init__(self, name: str | None = None, instructions: str | None = None) -> None:
        self.name = name
        self.instructions = None
        self._mcp_server = _UnderlyingServer(None, None)

    def run(self, *, transport: str) -> None:
        type(self).ran = True


class InitializationDroppingFastMCP:
    def __init__(self, name: str | None = None, instructions: str | None = None) -> None:
        self.name = name
        self.instructions = instructions
        self._mcp_server = _UnderlyingServer(instructions, None)


class _UnderlyingServer:
    def __init__(self, instructions: str | None, initialization_instructions: str | None) -> None:
        self.instructions = instructions
        self._initialization_instructions = initialization_instructions

    def create_initialization_options(self) -> SimpleNamespace:
        return SimpleNamespace(instructions=self._initialization_instructions)


def test_instruction_capable_factory_returns_the_verified_instance() -> None:
    server = create_instruction_capable_fastmcp(
        CompatibleFastMCP,
        name="codex-preflight",
        instructions=INSTRUCTIONS,
    )

    assert isinstance(server, CompatibleFastMCP)
    assert server.instructions == INSTRUCTIONS
    assert server._mcp_server.create_initialization_options().instructions == INSTRUCTIONS


def test_mcp_extra_uses_the_lowest_verified_instruction_capable_floor() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["optional-dependencies"]["mcp"] == ["mcp>=1.3.0"]


def test_legacy_name_and_arbitrary_settings_shape_fails_before_construction() -> None:
    LegacyFastMCP.constructed = False

    with pytest.raises(McpRuntimeCompatibilityError) as caught:
        create_instruction_capable_fastmcp(
            LegacyFastMCP,
            name="codex-preflight",
            instructions=INSTRUCTIONS,
        )

    assert LegacyFastMCP.constructed is False
    assert str(caught.value) == MCP_RUNTIME_COMPATIBILITY_MESSAGE


@pytest.mark.parametrize("factory", [DroppingFastMCP, InitializationDroppingFastMCP])
def test_compatible_looking_factory_that_drops_instructions_fails_closed(factory) -> None:
    with pytest.raises(McpRuntimeCompatibilityError) as caught:
        create_instruction_capable_fastmcp(
            factory,
            name="codex-preflight",
            instructions=INSTRUCTIONS,
        )

    assert str(caught.value) == MCP_RUNTIME_COMPATIBILITY_MESSAGE


def test_missing_runtime_is_distinct_from_present_but_broken_runtime() -> None:
    with pytest.raises(McpRuntimeMissingError) as missing:
        create_instruction_capable_fastmcp(
            name="codex-preflight",
            instructions=INSTRUCTIONS,
            runtime_finder=lambda _name: None,
        )

    def broken_loader() -> object:
        raise ImportError("SECRET_MARKER_FROM_BROKEN_RUNTIME")

    with pytest.raises(McpRuntimeCompatibilityError) as incompatible:
        create_instruction_capable_fastmcp(
            name="codex-preflight",
            instructions=INSTRUCTIONS,
            runtime_finder=lambda _name: object(),
            runtime_loader=broken_loader,
        )

    assert str(missing.value) == MCP_RUNTIME_COMPATIBILITY_MESSAGE
    assert str(incompatible.value) == MCP_RUNTIME_COMPATIBILITY_MESSAGE
    assert "SECRET_MARKER" not in str(incompatible.value)


def test_shadowed_runtime_finder_failure_is_incompatible_not_missing() -> None:
    def broken_finder(_name: str) -> object:
        raise ValueError("SECRET_MARKER_FROM_SHADOWED_RUNTIME")

    with pytest.raises(McpRuntimeCompatibilityError) as caught:
        create_instruction_capable_fastmcp(
            name="codex-preflight",
            instructions=INSTRUCTIONS,
            runtime_finder=broken_finder,
        )

    assert not isinstance(caught.value, McpRuntimeMissingError)
    assert str(caught.value) == MCP_RUNTIME_COMPATIBILITY_MESSAGE
    assert "SECRET_MARKER" not in str(caught.value)


def test_server_main_rejects_instruction_dropping_runtime_without_start_or_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_preflight_mcp import server as server_module

    DroppingFastMCP.ran = False
    real_create = server_module.create_mcp_server
    monkeypatch.setattr(
        server_module,
        "create_mcp_server",
        lambda: real_create(fastmcp_factory=DroppingFastMCP),
    )

    return_code = server_module.main([])
    captured = capsys.readouterr()

    assert return_code == 1
    assert captured.out == ""
    assert captured.err == f"{MCP_RUNTIME_COMPATIBILITY_MESSAGE}\n"
    assert MCP_RUNTIME_UPGRADE_COMMAND in captured.err
    assert "Traceback" not in captured.err
    assert DroppingFastMCP.ran is False


def test_server_main_handles_missing_runtime_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_preflight_mcp import server as server_module

    def missing_runtime() -> object:
        raise McpRuntimeMissingError(MCP_RUNTIME_COMPATIBILITY_MESSAGE)

    monkeypatch.setattr(server_module, "create_mcp_server", missing_runtime)

    return_code = server_module.main([])
    captured = capsys.readouterr()

    assert return_code == 1
    assert captured.out == ""
    assert captured.err == f"{MCP_RUNTIME_COMPATIBILITY_MESSAGE}\n"
    assert "Traceback" not in captured.err
