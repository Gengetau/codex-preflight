from pathlib import Path

import pytest

from codex_preflight_core.repo.temp_clone import clone_repo_to_temp


def test_clone_repo_to_temp_scans_mocked_git_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(args: list[str], **kwargs: object) -> object:
        assert args[0] == "git"
        assert "protocol.ext.allow=never" in args
        assert "clone" in args
        assert "--depth" in args
        target = Path(args[-1])
        target.mkdir(parents=True)
        (target / "README.md").write_text("hello", encoding="utf-8")

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr("codex_preflight_core.repo.temp_clone.subprocess.run", fake_run)

    with clone_repo_to_temp("https://github.com/example/repo.git") as cloned:
        assert (cloned / "README.md").read_text(encoding="utf-8") == "hello"


def test_clone_repo_uses_optional_temp_dir_and_keep_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(args: list[str], **kwargs: object) -> object:
        target = Path(args[-1])
        target.mkdir(parents=True)
        (target / "README.md").write_text("kept", encoding="utf-8")

        class Result:
            returncode = 0

        return Result()

    temp_root = tmp_path / "debug-temp"
    temp_root.mkdir()
    monkeypatch.setattr("codex_preflight_core.repo.temp_clone.subprocess.run", fake_run)

    with clone_repo_to_temp("https://github.com/example/repo.git", keep_temp=True, temp_dir=temp_root) as cloned:
        kept_parent = cloned.parent

    assert kept_parent.exists()
    assert kept_parent.parent == temp_root


def test_clone_cleanup_error_warns_to_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_run(args: list[str], **kwargs: object) -> object:
        target = Path(args[-1])
        target.mkdir(parents=True)

        class Result:
            returncode = 0

        return Result()

    def fail_cleanup(path: Path) -> None:
        raise OSError("locked")

    monkeypatch.setattr("codex_preflight_core.repo.temp_clone.subprocess.run", fake_run)
    monkeypatch.setattr("codex_preflight_core.repo.temp_clone._cleanup_tree", fail_cleanup)

    with clone_repo_to_temp("https://github.com/example/repo.git", temp_dir=tmp_path):
        pass

    assert "Warning: failed to remove temporary clone" in capsys.readouterr().err
