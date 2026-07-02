from pathlib import Path

import pytest

from codex_preflight_core.repo.temp_clone import clone_repo_to_temp


def test_clone_repo_to_temp_scans_mocked_git_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(args: list[str], **kwargs: object) -> object:
        assert args[:3] == ["git", "clone", "--depth"]
        target = Path(args[-1])
        target.mkdir(parents=True)
        (target / "README.md").write_text("hello", encoding="utf-8")

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr("codex_preflight_core.repo.temp_clone.subprocess.run", fake_run)

    with clone_repo_to_temp("https://github.com/example/repo.git") as cloned:
        assert (cloned / "README.md").read_text(encoding="utf-8") == "hello"
