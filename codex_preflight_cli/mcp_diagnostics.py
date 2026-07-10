from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path
from typing import Any

MCP_SERVER_NAME = "codex-preflight"
MCP_COMMAND = "codex-preflight-mcp"
MCP_INSTALL_COMMAND = 'python -m pip install "codex-preflight[mcp]"'
MCP_MANIFEST_PATH = "./.mcp.json"
EXPECTED_TOOL_NAMES = ("preflight_check", "corpus_scan")
BUNDLED_MCP_CONFIG: dict[str, dict[str, object]] = {
    MCP_SERVER_NAME: {
        "command": MCP_COMMAND,
        "args": [],
    }
}


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str
    remediation: str | None = None

    @property
    def passed(self) -> bool:
        return self.status in {"PASS", "SKIP"}


def render_codex_mcp_config() -> str:
    plugin_config = json.dumps(BUNDLED_MCP_CONFIG, indent=2)
    return "\n".join(
        (
            "Codex Preflight MCP setup (read-only; no files changed)",
            "",
            f"Python prerequisite: {MCP_INSTALL_COMMAND}",
            "The Codex plugin does not install Python packages or edit Codex configuration.",
            "",
            "Plugin-bundled .mcp.json:",
            plugin_config,
            "",
            "Equivalent standalone Codex config.toml:",
            f'[mcp_servers."{MCP_SERVER_NAME}"]',
            f'command = "{MCP_COMMAND}"',
            "args = []",
            "",
            "After plugin or MCP configuration changes, start a new Codex session or restart the local client.",
        )
    )


def diagnose_codex_mcp(
    *,
    source_root: Path | None = None,
    python_version: tuple[int, int] | None = None,
    executable_finder: Callable[[str], str | None] = shutil.which,
    runtime_finder: Callable[[str], object | None] = find_spec,
    tool_runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None,
) -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
    version = python_version or (sys.version_info.major, sys.version_info.minor)
    if version >= (3, 12):
        checks.append(DoctorCheck("python", "PASS", f"Python {version[0]}.{version[1]} is supported."))
    else:
        checks.append(
            DoctorCheck(
                "python",
                "FAIL",
                f"Python {version[0]}.{version[1]} is not supported.",
                "Install Python 3.12 or newer, then reinstall codex-preflight[mcp].",
            )
        )

    executable = executable_finder(MCP_COMMAND)
    if executable:
        checks.append(DoctorCheck("entry-point", "PASS", f"Found the {MCP_COMMAND} entry point."))
    else:
        checks.append(
            DoctorCheck(
                "entry-point",
                "FAIL",
                f"The {MCP_COMMAND} entry point is not available on PATH.",
                f"Run {MCP_INSTALL_COMMAND}, then ensure the Python scripts directory is on PATH.",
            )
        )

    try:
        runtime_available = runtime_finder("mcp") is not None
    except (ImportError, ValueError):
        runtime_available = False
    if runtime_available:
        checks.append(DoctorCheck("mcp-runtime", "PASS", "The optional MCP runtime is available."))
    else:
        checks.append(
            DoctorCheck(
                "mcp-runtime",
                "FAIL",
                "The optional MCP runtime is not installed.",
                f"Run {MCP_INSTALL_COMMAND}. No package was installed automatically.",
            )
        )

    if executable:
        checks.append(_check_tool_listing(executable, tool_runner or _run_tool_listing))
    else:
        checks.append(
            DoctorCheck(
                "tool-listing",
                "FAIL",
                "Tool listing could not run because the MCP entry point is unavailable.",
                f"Run {MCP_INSTALL_COMMAND}, then retry this doctor command.",
            )
        )

    root = source_root.resolve() if source_root is not None else _discover_source_root(Path.cwd())
    if root is None:
        checks.append(
            DoctorCheck(
                "source-plugin",
                "SKIP",
                "No Codex Preflight source checkout was detected; packaged plugin files were not checked.",
            )
        )
    else:
        checks.append(_check_source_plugin(root))
    return checks


def _run_tool_listing(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )


def _check_tool_listing(
    executable: str,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]],
) -> DoctorCheck:
    argv = [executable, "--list-tools"]
    try:
        result = runner(argv)
    except (OSError, subprocess.SubprocessError) as error:
        return DoctorCheck(
            "tool-listing",
            "FAIL",
            f"Tool listing failed to start: {type(error).__name__}.",
            f"Run `{MCP_COMMAND} --list-tools` and resolve the reported setup error.",
        )
    if result.returncode != 0:
        return DoctorCheck(
            "tool-listing",
            "FAIL",
            f"Tool listing exited with status {result.returncode}.",
            f"Run `{MCP_COMMAND} --list-tools` and resolve the reported setup error.",
        )
    try:
        tools = json.loads(result.stdout)
        names = tuple(tool["name"] for tool in tools if isinstance(tool, dict) and isinstance(tool.get("name"), str))
    except (json.JSONDecodeError, TypeError):
        names = ()
    if set(names) != set(EXPECTED_TOOL_NAMES) or len(names) != len(EXPECTED_TOOL_NAMES):
        return DoctorCheck(
            "tool-listing",
            "FAIL",
            "The MCP tool list does not match the expected read-only two-tool surface.",
            f"Expected exactly: {', '.join(EXPECTED_TOOL_NAMES)}. Reinstall the matching package version.",
        )
    return DoctorCheck("tool-listing", "PASS", f"Tool listing contains exactly: {', '.join(EXPECTED_TOOL_NAMES)}.")


def _discover_source_root(start: Path) -> Path | None:
    for candidate in (start.resolve(), *start.resolve().parents):
        pyproject = candidate / "pyproject.toml"
        manifest = candidate / ".codex-plugin" / "plugin.json"
        if not pyproject.is_file() or not manifest.is_file():
            continue
        try:
            project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
        except (OSError, tomllib.TOMLDecodeError):
            continue
        if isinstance(project, dict) and project.get("name") == "codex-preflight":
            return candidate
    return None


def _check_source_plugin(root: Path) -> DoctorCheck:
    root_manifest = root / ".codex-plugin" / "plugin.json"
    root_mcp = root / ".mcp.json"
    marketplace_root = root / ".agents" / "plugins" / "plugins" / MCP_SERVER_NAME
    marketplace_manifest = marketplace_root / ".codex-plugin" / "plugin.json"
    marketplace_mcp = marketplace_root / ".mcp.json"
    try:
        manifest = _load_json(root_manifest)
        mcp_config = _load_json(root_mcp)
        if manifest.get("mcpServers") != MCP_MANIFEST_PATH:
            raise ValueError(f"root manifest must declare mcpServers as {MCP_MANIFEST_PATH}")
        if mcp_config != BUNDLED_MCP_CONFIG:
            raise ValueError("root .mcp.json does not match the supported local stdio configuration")
        if marketplace_root.exists():
            packaged_manifest = _load_json(marketplace_manifest)
            packaged_mcp = _load_json(marketplace_mcp)
            if packaged_manifest.get("mcpServers") != manifest.get("mcpServers"):
                raise ValueError("marketplace manifest MCP declaration is stale")
            if packaged_mcp != mcp_config:
                raise ValueError("marketplace .mcp.json is stale")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return DoctorCheck(
            "source-plugin",
            "FAIL",
            f"Source plugin consistency check failed: {error}.",
            "Run `python scripts/sync_marketplace_plugin.py`, then retry the doctor command.",
        )
    return DoctorCheck("source-plugin", "PASS", "Root and marketplace plugin MCP configuration are consistent.")


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return data
