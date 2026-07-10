from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from codex_preflight_mcp.errors import McpErrorCode, McpToolError
from codex_preflight_mcp.server import (
    _is_remote_or_clone_like,
    corpus_scan,
    create_mcp_server,
    preflight_check,
)


def assert_error(
    error: McpToolError,
    code: McpErrorCode,
    *,
    field: str | None,
    retryable: bool = False,
) -> dict[str, object]:
    detail = error.to_dict()["error"]
    assert detail["code"] == code.value
    assert detail["field"] == field
    assert detail["retryable"] is retryable
    assert detail["message"]
    assert detail["remediation"]
    assert "Traceback" not in str(error)
    return detail


def test_missing_cwd_has_stable_error() -> None:
    with pytest.raises(McpToolError) as caught:
        preflight_check(command="pytest")

    assert_error(caught.value, McpErrorCode.CWD_REQUIRED, field="cwd")


def test_missing_command_has_stable_error(tmp_path: Path) -> None:
    with pytest.raises(McpToolError) as caught:
        preflight_check(cwd=str(tmp_path))

    assert_error(caught.value, McpErrorCode.COMMAND_REQUIRED, field="command")


@pytest.mark.parametrize("cwd", ["", " ", "\t\r\n"])
def test_empty_cwd_has_stable_error(cwd: str) -> None:
    with pytest.raises(McpToolError) as caught:
        preflight_check(cwd=cwd, command="pytest")

    assert_error(caught.value, McpErrorCode.CWD_EMPTY, field="cwd")


@pytest.mark.parametrize(
    "cwd",
    [
        "http://example.com/repo.git",
        "https://example.com/repo.git",
        "ssh://example.com/repo.git",
        "git://example.com/repo.git",
        "file:///tmp/repo",
        "git@example.com:owner/repo.git",
        "example.com:owner/repo.git",
        "ext::sh -c id",
        "git clone https://example.com/repo.git",
        "gh repo clone owner/repo",
    ],
)
def test_remote_and_clone_forms_are_rejected_before_filesystem_access(cwd: str) -> None:
    with pytest.raises(McpToolError) as caught:
        preflight_check(cwd=cwd, command="pytest")

    detail = assert_error(caught.value, McpErrorCode.CWD_URL_NOT_ALLOWED, field="cwd")
    assert "local-path-only" in str(detail["safetyBoundary"])


def test_existing_relative_and_mixed_slash_paths_are_normalized(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "nested" / "repo"
    repo.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)

    relative_report = preflight_check(cwd="nested/repo", command="pytest")
    mixed_report = preflight_check(cwd=str(repo).replace("\\", "/"), command="pytest")

    assert Path(relative_report["repo"]["path"]) == repo.resolve()
    assert Path(mixed_report["repo"]["path"]) == repo.resolve()


def test_home_directory_expansion(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    repo = home / "repo"
    repo.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    report = preflight_check(cwd="~/repo", command="pytest")

    assert Path(report["repo"]["path"]) == repo.resolve()


def test_regular_file_is_distinct_from_missing_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "README.md"
    file_path.write_text("data", encoding="utf-8")

    with pytest.raises(McpToolError) as file_error:
        preflight_check(cwd=str(file_path), command="pytest")
    with pytest.raises(McpToolError) as missing_error:
        preflight_check(cwd=str(tmp_path / "missing"), command="pytest")

    assert_error(file_error.value, McpErrorCode.CWD_FILE_NOT_DIRECTORY, field="cwd")
    assert_error(missing_error.value, McpErrorCode.CWD_NOT_FOUND, field="cwd")


def test_permission_failure_is_distinct_and_retryable(monkeypatch) -> None:
    def deny_access(_path: Path) -> bool:
        raise PermissionError("synthetic denied path")

    monkeypatch.setattr(Path, "exists", deny_access)

    with pytest.raises(McpToolError) as caught:
        preflight_check(cwd="permission-denied", command="pytest")

    assert_error(caught.value, McpErrorCode.CWD_PERMISSION_DENIED, field="cwd", retryable=True)


def test_invalid_non_string_path_has_stable_error() -> None:
    with pytest.raises(McpToolError) as caught:
        preflight_check(cwd=object(), command="pytest")  # type: ignore[arg-type]

    assert_error(caught.value, McpErrorCode.CWD_INVALID, field="cwd")


@pytest.mark.parametrize(
    "cwd",
    [
        "C:\\work\\repo",
        "C:/work/repo",
        "C:repo",
        "\\\\server\\share\\repo",
        "//server/share/repo",
    ],
)
def test_windows_drive_and_unc_forms_are_not_classified_as_urls(cwd: str) -> None:
    assert not _is_remote_or_clone_like(cwd)


def test_directory_symlink_resolves_to_scanned_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    report = preflight_check(cwd=str(link), command="pytest")

    assert Path(report["repo"]["path"]) == target.resolve()


def test_unsupported_format_and_argument_have_stable_errors(tmp_path: Path) -> None:
    with pytest.raises(McpToolError) as format_error:
        preflight_check(cwd=str(tmp_path), command="pytest", format="markdown")
    with pytest.raises(McpToolError) as argument_error:
        preflight_check(cwd=str(tmp_path), command="pytest", repo="https://example.com/repo.git")

    assert_error(format_error.value, McpErrorCode.FORMAT_UNSUPPORTED, field="format")
    detail = assert_error(argument_error.value, McpErrorCode.ARGUMENT_UNSUPPORTED, field="repo")
    assert "not exposed" in str(detail["safetyBoundary"])


def test_unknown_corpus_case_has_stable_error() -> None:
    with pytest.raises(McpToolError) as caught:
        corpus_scan(case_id="not-a-real-case")

    assert_error(caught.value, McpErrorCode.CASE_NOT_FOUND, field="case_id")


def test_internal_error_hides_exception_details(tmp_path: Path, monkeypatch) -> None:
    def fail_preflight(*args, **kwargs):
        raise RuntimeError("SECRET_INTERNAL_TRACE_MARKER")

    monkeypatch.setattr("codex_preflight_mcp.server.run_preflight", fail_preflight)

    with pytest.raises(McpToolError) as caught:
        preflight_check(cwd=str(tmp_path), command="pytest")

    detail = assert_error(caught.value, McpErrorCode.INTERNAL_ERROR, field=None, retryable=True)
    assert "SECRET_INTERNAL_TRACE_MARKER" not in str(caught.value)
    assert "not returned" in str(detail["safetyBoundary"])


def test_fastmcp_runtime_uses_public_tool_names_required_schema_and_error_codes() -> None:
    server = create_mcp_server()
    preflight_tool = server._tool_manager.get_tool("preflight_check")
    corpus_tool = server._tool_manager.get_tool("corpus_scan")

    assert preflight_tool is not None
    assert corpus_tool is not None
    assert preflight_tool.parameters["required"] == ["cwd", "command"]

    with pytest.raises(Exception) as caught:
        asyncio.run(server._tool_manager.call_tool("preflight_check", {"command": "pytest"}))

    assert "MCP_CWD_REQUIRED" in str(caught.value)
    assert "Traceback" not in str(caught.value)
