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


def test_mcp_docs_state_remote_repositories_are_not_exposed() -> None:
    from codex_preflight_mcp.server import tool_definitions

    descriptions = "\n".join(str(tool["description"]) for tool in tool_definitions())

    assert "Remote repository scanning is intentionally not exposed" in descriptions
