from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from codex_preflight_cli.main import app
from codex_preflight_cli.mcp_diagnostics import (
    DoctorCheck,
    diagnose_codex_mcp,
    render_codex_mcp_config,
)
from codex_preflight_mcp.runtime_compatibility import (
    MCP_RUNTIME_COMPATIBILITY_MESSAGE,
    MCP_RUNTIME_UPGRADE_COMMAND,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TOOLS = [{"name": "preflight_check"}, {"name": "corpus_scan"}]


def successful_tool_listing(_argv) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(EXPECTED_TOOLS),
        stderr="",
    )


def test_healthy_environment_reports_success_and_handles_entry_point_spaces() -> None:
    captured: list[list[str]] = []
    executable = "C:\\Program Files\\Codex Preflight\\codex-preflight-mcp.exe"

    def run(argv) -> subprocess.CompletedProcess[str]:
        captured.append(list(argv))
        return successful_tool_listing(argv)

    checks = diagnose_codex_mcp(
        source_root=ROOT,
        python_version=(3, 12),
        executable_finder=lambda _name: executable,
        runtime_finder=lambda _name: object(),
        runtime_checker=lambda: None,
        tool_runner=run,
    )

    assert all(check.passed for check in checks)
    assert captured == [[executable, "--list-tools"]]
    assert {check.name for check in checks} == {
        "python",
        "entry-point",
        "mcp-runtime",
        "tool-listing",
        "source-plugin",
    }


def test_missing_optional_runtime_has_exact_non_installing_remediation() -> None:
    checks = diagnose_codex_mcp(
        source_root=ROOT,
        executable_finder=lambda _name: "codex-preflight-mcp",
        runtime_finder=lambda _name: None,
        tool_runner=successful_tool_listing,
    )

    runtime = next(check for check in checks if check.name == "mcp-runtime")
    assert runtime.status == "FAIL"
    assert runtime.detail == "The optional MCP runtime is missing."
    assert runtime.remediation == (
        f"{MCP_RUNTIME_COMPATIBILITY_MESSAGE}\nNo package was installed automatically."
    )


def test_instruction_incompatible_runtime_is_distinct_and_does_not_leak_details() -> None:
    def incompatible_runtime() -> None:
        raise RuntimeError("SECRET_MARKER_FROM_BROKEN_RUNTIME")

    checks = diagnose_codex_mcp(
        source_root=ROOT,
        executable_finder=lambda _name: "codex-preflight-mcp",
        runtime_finder=lambda _name: object(),
        runtime_checker=incompatible_runtime,
        tool_runner=successful_tool_listing,
    )

    runtime = next(check for check in checks if check.name == "mcp-runtime")
    assert runtime.status == "FAIL"
    assert runtime.detail == "The optional MCP runtime is present but instruction-incompatible."
    assert runtime.remediation == (
        f"{MCP_RUNTIME_COMPATIBILITY_MESSAGE}\nNo package was installed automatically."
    )
    assert MCP_RUNTIME_UPGRADE_COMMAND in runtime.remediation
    assert "SECRET_MARKER" not in repr(checks)


def test_shadowed_runtime_discovery_failure_is_not_reported_as_missing() -> None:
    def broken_finder(_name: str) -> object:
        raise ValueError("SECRET_MARKER_FROM_SHADOWED_RUNTIME")

    checks = diagnose_codex_mcp(
        source_root=ROOT,
        executable_finder=lambda _name: "codex-preflight-mcp",
        runtime_finder=broken_finder,
        tool_runner=successful_tool_listing,
    )

    runtime = next(check for check in checks if check.name == "mcp-runtime")
    assert runtime.status == "FAIL"
    assert "present but instruction-incompatible" in runtime.detail
    assert "SECRET_MARKER" not in repr(checks)


def test_missing_console_entry_point_is_actionable() -> None:
    checks = diagnose_codex_mcp(
        source_root=ROOT,
        executable_finder=lambda _name: None,
        runtime_finder=lambda _name: object(),
        runtime_checker=lambda: None,
    )

    entry_point = next(check for check in checks if check.name == "entry-point")
    tool_listing = next(check for check in checks if check.name == "tool-listing")
    assert entry_point.status == "FAIL"
    assert "scripts directory" in str(entry_point.remediation)
    assert tool_listing.status == "FAIL"


def test_tool_list_mismatch_is_a_failure() -> None:
    def mismatched(_argv) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps([{"name": "preflight_check"}, {"name": "trust_approve"}]),
            stderr="",
        )

    checks = diagnose_codex_mcp(
        source_root=ROOT,
        executable_finder=lambda _name: "codex-preflight-mcp",
        runtime_finder=lambda _name: object(),
        runtime_checker=lambda: None,
        tool_runner=mismatched,
    )

    listing = next(check for check in checks if check.name == "tool-listing")
    assert listing.status == "FAIL"
    assert "two-tool" in listing.detail
    assert "preflight_check, corpus_scan" in str(listing.remediation)


def test_diagnostics_do_not_mutate_plugin_files() -> None:
    paths = [
        ROOT / ".codex-plugin" / "plugin.json",
        ROOT / ".mcp.json",
        ROOT / ".agents" / "plugins" / "plugins" / "codex-preflight" / ".codex-plugin" / "plugin.json",
        ROOT / ".agents" / "plugins" / "plugins" / "codex-preflight" / ".mcp.json",
    ]
    before = {path: path.read_bytes() for path in paths}

    diagnose_codex_mcp(
        source_root=ROOT,
        executable_finder=lambda _name: "codex-preflight-mcp",
        runtime_finder=lambda _name: object(),
        runtime_checker=lambda: None,
        tool_runner=successful_tool_listing,
    )

    assert {path: path.read_bytes() for path in paths} == before


def test_config_presentation_is_cross_platform_and_has_no_shell_wrapper() -> None:
    output = render_codex_mcp_config()
    lowered = output.lower()

    assert 'python -m pip install "codex-preflight[mcp]"' in output
    assert "mcp>=1.3.0" in output
    assert 'command = "codex-preflight-mcp"' in output
    assert '[mcp_servers."codex-preflight"]' in output
    assert '"command": "codex-preflight-mcp"' in output
    assert "no files changed" in lowered
    assert not any(token in lowered for token in ("bash -c", "powershell", "cmd /c", "shell=true"))


def test_cli_config_command_prints_supported_setup() -> None:
    result = CliRunner().invoke(app, ["mcp", "config", "--client", "codex"])

    assert result.exit_code == 0
    assert "Plugin-bundled .mcp.json" in result.stdout
    assert "Python prerequisite" in result.stdout


def test_cli_doctor_exit_status_reflects_failures(monkeypatch) -> None:
    monkeypatch.setattr(
        "codex_preflight_cli.main.diagnose_codex_mcp",
        lambda: [DoctorCheck("synthetic", "FAIL", "not ready", "install the prerequisite")],
    )

    result = CliRunner().invoke(app, ["mcp", "doctor", "--client", "codex"])

    assert result.exit_code == 1
    assert "[FAIL] synthetic: not ready" in result.stdout
    assert "Remediation: install the prerequisite" in result.stdout


def test_diagnostics_module_does_not_import_optional_mcp_runtime() -> None:
    sys.modules.pop("mcp", None)
    __import__("codex_preflight_cli.mcp_diagnostics")
    assert "mcp" not in sys.modules
