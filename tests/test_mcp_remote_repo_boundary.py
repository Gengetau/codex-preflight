from __future__ import annotations

from pathlib import Path

import pytest


def test_mcp_preflight_schema_has_no_repo_parameter() -> None:
    from codex_preflight_mcp.server import tool_definitions

    preflight = next(tool for tool in tool_definitions() if tool["name"] == "preflight_check")

    assert "repo" not in preflight["inputSchema"]["properties"]


@pytest.mark.parametrize(
    "cwd",
    [
        "https://github.com/example/repo.git",
        "git@github.com:example/repo.git",
        "ssh://github.com/example/repo.git",
        "git://github.com/example/repo.git",
        "file:///tmp/repo",
        "ext::sh -c id",
    ],
)
def test_mcp_preflight_rejects_remote_or_clone_like_cwd(cwd: str) -> None:
    from codex_preflight_mcp.server import preflight_check

    with pytest.raises(ValueError, match="local path"):
        preflight_check(cwd=cwd, command="pytest")


def test_mcp_preflight_rejects_missing_local_cwd(tmp_path: Path) -> None:
    from codex_preflight_mcp.server import preflight_check

    with pytest.raises(ValueError, match="existing local directory"):
        preflight_check(cwd=str(tmp_path / "missing"), command="pytest")


def test_local_tool_description_keeps_remote_authority_separate(monkeypatch) -> None:
    from codex_preflight_mcp.server import tool_definitions

    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    tools = tool_definitions()
    assert [tool["name"] for tool in tools] == ["preflight_check", "corpus_scan"]
    descriptions = "\n".join(str(tool["description"]) for tool in tool_definitions())

    assert "opt-in remote authority is isolated in the separate remote_repository_scan tool" in descriptions
