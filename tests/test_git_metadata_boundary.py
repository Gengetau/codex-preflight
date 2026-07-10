from __future__ import annotations

import subprocess
from pathlib import Path

from codex_preflight_core.repo.git import GIT_METADATA_TIMEOUT_SECONDS, run_git


def test_git_metadata_uses_closed_stdin_and_timeout(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="abc123\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert run_git(tmp_path, "rev-parse", "HEAD") == "abc123"
    assert captured["command"] == ["git", "rev-parse", "HEAD"]
    assert captured["cwd"] == tmp_path
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["capture_output"] is True
    assert captured["check"] is False
    assert captured["timeout"] == GIT_METADATA_TIMEOUT_SECONDS


def test_git_metadata_timeout_degrades_to_unknown_identity(tmp_path: Path, monkeypatch) -> None:
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["git", "rev-parse", "HEAD"], timeout=5)

    monkeypatch.setattr(subprocess, "run", timeout)

    assert run_git(tmp_path, "rev-parse", "HEAD") is None


def test_git_metadata_os_error_degrades_to_unknown_identity(tmp_path: Path, monkeypatch) -> None:
    def unavailable(*args, **kwargs):
        raise FileNotFoundError("git unavailable")

    monkeypatch.setattr(subprocess, "run", unavailable)

    assert run_git(tmp_path, "rev-parse", "HEAD") is None
