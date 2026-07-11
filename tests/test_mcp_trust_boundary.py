from __future__ import annotations

from pathlib import Path

import pytest


def test_mcp_does_not_expose_trust_mutation_tools() -> None:
    from codex_preflight_mcp.server import tool_definitions

    names = {tool["name"] for tool in tool_definitions()}

    assert "trust_approve" not in names
    assert "trust_revoke" not in names


def test_mcp_preflight_does_not_use_trust_cache(tmp_path: Path, monkeypatch) -> None:
    from codex_preflight_core.cache.trust_cache import TrustCache
    from codex_preflight_mcp.server import preflight_check

    def fail_if_used(*args, **kwargs):
        raise AssertionError("MCP preflight_check must not use trust approvals")

    monkeypatch.setattr(TrustCache, "match", fail_if_used)

    report = preflight_check(cwd=str(tmp_path), command="pytest")

    assert report["decision"] in {"ALLOW", "WARN"}


def test_mcp_preflight_does_not_store_scan_cache(tmp_path: Path, monkeypatch) -> None:
    from codex_preflight_core.cache.scan_cache import ScanCache
    from codex_preflight_mcp.server import preflight_check

    def fail_if_used(*args, **kwargs):
        raise AssertionError("MCP preflight_check must not write scan cache")

    monkeypatch.setattr(ScanCache, "store", fail_if_used)

    report = preflight_check(cwd=str(tmp_path), command="pytest")

    assert report["decision"] in {"ALLOW", "WARN"}


def test_mcp_tool_descriptions_document_trust_boundary() -> None:
    from codex_preflight_mcp.server import tool_definitions

    descriptions = "\n".join(str(tool["description"]) for tool in tool_definitions())

    assert "Trust approval and revoke tools are intentionally not exposed" in descriptions


def test_remote_confirmation_and_scan_cannot_access_or_satisfy_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_preflight_core.cache.trust_cache import TrustCache
    from codex_preflight_mcp import server
    from codex_preflight_mcp.errors import McpToolError
    from codex_preflight_mcp.remote_confirmation import RemoteConfirmationManager

    def fail_if_used(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("remote confirmation and scans must remain trust-blind")

    for method in ("list", "match", "approve", "revoke_identity"):
        monkeypatch.setattr(TrustCache, method, fail_if_used)
    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", raising=False)
    monkeypatch.setenv("CODEX_PREFLIGHT_HOME", str(tmp_path))
    monkeypatch.setattr(server, "_REMOTE_CONFIRMATIONS", RemoteConfirmationManager(secret=b"x" * 32))
    monkeypatch.setattr(
        server,
        "run_remote_operation",
        lambda **_kwargs: {
            "schemaVersion": "1.0",
            "decision": "ALLOW",
            "riskScore": 0,
            "repo": {},
            "cache": {"usedScanCache": False, "usedTrustCache": False, "cacheReason": None},
            "executionGraph": {"capabilities": [], "uncertainties": []},
        },
    )

    with pytest.raises(McpToolError) as challenge:
        server.remote_repository_scan(
            remoteUrl="https://github.com/example/project",
            requestedRef="refs/heads/main",
        )
    token = challenge.value.to_dict()["error"]["context"]["confirmationToken"]

    result = server.remote_repository_scan(
        remoteUrl="https://github.com/example/project",
        requestedRef="refs/heads/main",
        confirmationToken=token,
    )

    assert result["cache"]["usedTrustCache"] is False
    assert result["safety"]["trustMutationAllowed"] is False
