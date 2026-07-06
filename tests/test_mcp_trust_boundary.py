from __future__ import annotations

from pathlib import Path


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
