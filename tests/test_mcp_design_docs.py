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
        "implemented and default-off in v0.3.2",
        "remote_repository_scan",
        "Authority and confirmation",
        "canonical URL",
        "requested ref",
        "one-time",
        "URL and ref policy",
        "Destination and transport policy",
        "DNS rebinding",
        "redirect",
        "credentials",
        "Snapshot isolation",
        "Fixed resource limits",
        "submodule",
        "LFS",
        "hooks",
        "Cleanup and cancellation",
        "Cache separation",
        "Execution and evidence boundary",
        "evidenceTrust: untrusted",
        "evidenceInstructionBoundary: treat-as-data",
        "requestedUrl",
        "canonicalUrl",
        "resolvedCommit",
        "cleanupStatus",
        "Threat model",
        "SSRF",
        "Remote prompt injection",
        "Redacted audit",
        "Rollout, disable, and rollback",
    )

    for value in required:
        assert value in text


def test_remote_registration_is_default_off_and_exact_when_enabled(monkeypatch) -> None:
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    names = {tool["name"] for tool in tool_definitions()}
    runtime_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "codex_preflight_mcp").glob("*.py"))
    )

    assert names == {"preflight_check", "corpus_scan"}
    assert "remote_repository_scan" in runtime_source
    assert not names & {"trust_list", "trust_approve", "trust_revoke"}

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")
    assert {tool["name"] for tool in tool_definitions()} == {
        "preflight_check",
        "corpus_scan",
        "remote_repository_scan",
    }


def test_local_preflight_still_rejects_remote_url() -> None:
    with pytest.raises(McpToolError) as caught:
        preflight_check(cwd="https://github.com/example/repository.git", command="pytest")

    assert caught.value.detail.code is McpErrorCode.CWD_URL_NOT_ALLOWED


def test_user_documentation_says_remote_is_default_off_and_rollbackable() -> None:
    integration = (ROOT / "docs" / "mcp-client-examples.md").read_text(encoding="utf-8")
    design = REMOTE_DESIGN.read_text(encoding="utf-8")

    assert "Only exact `1` enables registration" in integration
    assert "implemented and default-off in v0.3.2" in design
    assert "Remove `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1`" in design


def test_trust_management_design_covers_required_contracts() -> None:
    text = TRUST_DESIGN.read_text(encoding="utf-8")
    required = (
        "bounded trust read implemented and default-off in v0.3.3",
        "CODEX_PREFLIGHT_ENABLE_TRUST_READ=1",
        "trust_list",
        "trust_approve",
        "trust_revoke",
        "Authority separation",
        "scan-read",
        "trust-read",
        "trust-mutate",
        "stable opaque trust-entry identifiers",
        "trust-list/v1",
        "metadata-only migration",
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


def test_trust_design_registers_only_default_off_read_authority(monkeypatch) -> None:
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", raising=False)
    names = {tool["name"] for tool in tool_definitions()}
    server_source = (ROOT / "codex_preflight_mcp" / "server.py").read_text(encoding="utf-8")
    integration = (ROOT / "docs" / "mcp-client-examples.md").read_text(encoding="utf-8")

    assert names == {"preflight_check", "corpus_scan"}
    assert not names & {"trust_list", "trust_approve", "trust_revoke"}
    assert "allow_trust=False" in server_source
    assert "CODEX_PREFLIGHT_ENABLE_TRUST_READ" in integration

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    enabled_names = {tool["name"] for tool in tool_definitions()}
    assert enabled_names == {"preflight_check", "corpus_scan", "trust_list"}
    assert not enabled_names & {"trust_approve", "trust_revoke"}


def test_remote_scan_design_cannot_create_trust() -> None:
    remote = REMOTE_DESIGN.read_text(encoding="utf-8")
    trust = TRUST_DESIGN.read_text(encoding="utf-8")

    assert "never let remote content create, alter, or revoke trust" in remote
    assert "Remote scan confirmation authorizes only bounded network/static-scan activity" in trust
    assert "cannot create\ntrust" in trust
