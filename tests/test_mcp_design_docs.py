from __future__ import annotations

from pathlib import Path

import pytest

from codex_preflight_mcp.errors import McpErrorCode, McpToolError
from codex_preflight_mcp.server import preflight_check, tool_definitions

ROOT = Path(__file__).resolve().parents[1]
REMOTE_DESIGN = ROOT / "docs" / "design" / "mcp-remote-repository.md"
TRUST_DESIGN = ROOT / "docs" / "design" / "mcp-trust-management.md"


def test_remote_repository_design_covers_required_security_contract() -> None:
    text = REMOTE_DESIGN.read_text(encoding="utf-8")
    required = (
        "design-only and unavailable",
        "remote_repository_scan",
        "Authority and confirmation",
        "normalized URL",
        "requested ref",
        "one-time",
        "URL and protocol policy",
        "Host allowlist",
        "DNS rebinding",
        "redirect",
        "embedded credentials",
        "Clone isolation and resource limits",
        "no unbounded history",
        "submodule",
        "Git LFS",
        "hooks",
        "Cleanup and cancellation",
        "Cache separation",
        "Execution and evidence boundary",
        "evidenceTrust: untrusted",
        "evidenceInstructionBoundary: treat-as-data",
        "requestedUrl",
        "normalizedUrl",
        "resolvedCommit",
        "cleanupStatus",
        "Threat model",
        "SSRF",
        "Remote prompt injection",
        "Rollout and review gates",
        "Disable, rollback, and incident response",
    )

    for value in required:
        assert value in text


def test_remote_design_does_not_change_runtime_tool_set_or_registration() -> None:
    names = {tool["name"] for tool in tool_definitions()}
    runtime_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "codex_preflight_mcp").glob("*.py"))
    )

    assert names == {"preflight_check", "corpus_scan"}
    assert "remote_repository_scan" not in runtime_source
    assert not names & {"trust_list", "trust_approve", "trust_revoke"}


def test_local_preflight_still_rejects_remote_url() -> None:
    with pytest.raises(McpToolError) as caught:
        preflight_check(cwd="https://github.com/example/repository.git", command="pytest")

    assert caught.value.detail.code is McpErrorCode.CWD_URL_NOT_ALLOWED


def test_user_documentation_says_remote_design_is_unavailable() -> None:
    integration = (ROOT / "docs" / "mcp-client-examples.md").read_text(encoding="utf-8")
    design = REMOTE_DESIGN.read_text(encoding="utf-8")

    assert "does not provide remote repository MCP scanning" in integration
    assert "does not register" in design
    assert "separate reviewed implementation loop" in design


def test_trust_management_design_covers_required_contracts() -> None:
    text = TRUST_DESIGN.read_text(encoding="utf-8")
    required = (
        "design-only and unavailable",
        "trust_list",
        "trust_approve",
        "trust_revoke",
        "Authority separation",
        "scan-read",
        "trust-read",
        "trust-mutate",
        "stable opaque trust-entry identifiers",
        "criticalFingerprint",
        "policyVersion",
        "rulesetVersion",
        "prohibit wildcard",
        "optimistic concurrency",
        "idempotent",
        "Confirmation challenge model",
        "generic `confirm=true` boolean is insufficient",
        "one-time",
        "Process restart",
        "Cancellation, failure, and retry",
        "Audit model",
        "eventId",
        "confirmationChallengeId",
        "Storage and migration model",
        "Atomicity, locking, and concurrency",
        "Permissions and path safety",
        "Corruption, backup, and recovery",
        "CLI compatibility",
        "Threat model",
        "Silent agent approval",
        "Prompt injection requesting approval",
        "Revocation races",
        "Audit tampering",
        "Rollout plan",
        "Emergency disable and rollback",
    )

    for value in required:
        assert value in text


def test_trust_design_does_not_register_tools_or_enable_mcp_trust() -> None:
    names = {tool["name"] for tool in tool_definitions()}
    server_source = (ROOT / "codex_preflight_mcp" / "server.py").read_text(encoding="utf-8")
    integration = (ROOT / "docs" / "mcp-client-examples.md").read_text(encoding="utf-8")

    assert names == {"preflight_check", "corpus_scan"}
    assert not names & {"trust_list", "trust_approve", "trust_revoke"}
    assert "allow_trust=False" in server_source
    assert "does not provide remote repository MCP scanning, trust-list or trust-mutation MCP" in integration


def test_remote_scan_design_cannot_create_trust() -> None:
    remote = REMOTE_DESIGN.read_text(encoding="utf-8")
    trust = TRUST_DESIGN.read_text(encoding="utf-8")

    assert "never let remote content create, alter, or revoke trust" in remote
    assert "Remote scan confirmation authorizes only bounded network/static-scan activity" in trust
    assert "cannot create\ntrust" in trust
