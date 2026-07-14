from __future__ import annotations

import json
import tomllib
from pathlib import Path

from codex_preflight_core import __version__ as core_version
from codex_preflight_mcp import __version__ as mcp_version
from codex_preflight_mcp.errors import McpErrorCode

ROOT = Path(__file__).resolve().parents[1]


def test_current_version_sources_and_plugin_copies_are_aligned() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    root_plugin = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    marketplace_plugin = json.loads(
        (ROOT / ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json").read_text(
            encoding="utf-8"
        )
    )

    assert project["project"]["version"] == "0.3.7"
    assert core_version == "0.3.7"
    assert mcp_version == "0.3.7"
    assert root_plugin["version"] == "0.3.7"
    assert marketplace_plugin["version"] == "0.3.7"


def test_trust_read_docs_cover_authority_migration_audit_and_rollback() -> None:
    files = (
        ROOT / "README.md",
        ROOT / "docs/mcp.md",
        ROOT / "docs/mcp-client-examples.md",
        ROOT / "docs/cache-design.md",
        ROOT / "docs/design/mcp-trust-management.md",
        ROOT / "docs/threat-model.md",
        ROOT / "docs/release-history.md",
        ROOT / "docs/plugin.md",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in files)

    for required in (
        "CODEX_PREFLIGHT_ENABLE_TRUST_READ=1",
        "trust-list/v1",
        "default-off",
        "metadata-only",
        "UUIDv4",
        "1 MiB",
        "trust-read/audit.jsonl",
        "4096",
        "300 seconds",
        "identityStatus: unavailable",
        "trust_approve",
        "trust_revoke",
        "cannot approve, revoke, extend, consume, satisfy, or create trust",
        "Rollback",
    ):
        assert required in combined


def test_trust_read_has_complete_stable_error_code_set() -> None:
    expected = {
        "MCP_TRUST_READ_DISABLED",
        "MCP_TRUST_LIST_INVALID_ARGUMENT",
        "MCP_TRUST_LIST_CURSOR_INVALID",
        "MCP_TRUST_LIST_LIMIT_EXCEEDED",
        "MCP_TRUST_LIST_UNAVAILABLE",
        "MCP_TRUST_LIST_CORRUPT",
        "MCP_TRUST_LIST_UNSUPPORTED_SCHEMA",
        "MCP_TRUST_LIST_LOCK_TIMEOUT",
        "MCP_TRUST_LIST_MIGRATION_FAILED",
        "MCP_TRUST_LIST_AUDIT_FAILED",
        "MCP_TRUST_LIST_INTERNAL_ERROR",
    }

    assert expected <= {code.value for code in McpErrorCode}


def test_trust_read_implementation_does_not_import_other_state_or_network_layers() -> None:
    source = (ROOT / "codex_preflight_mcp/trust_read.py").read_text(encoding="utf-8")

    for forbidden in (
        "scan_cache",
        "remote_state",
        "remote_operation",
        "requests",
        "urllib",
        "subprocess",
        "socket",
    ):
        assert forbidden not in source
