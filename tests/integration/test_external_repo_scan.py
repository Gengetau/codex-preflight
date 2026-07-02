import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from typer.testing import CliRunner

from codex_preflight_cli.main import app
from codex_preflight_core.repo.temp_clone import clone_repo_to_temp


def test_preflight_repo_reports_github_source_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("safe fixture\n", encoding="utf-8")

    @contextmanager
    def fake_clone(
        clone_url: str,
        *,
        ref: str | None = None,
        depth: int = 1,
        keep_temp: bool = False,
        temp_dir: Path | None = None,
    ) -> Iterator[Path]:
        assert clone_url == "https://github.com/example/safe-repo.git"
        assert ref == "main"
        assert depth == 7
        assert keep_temp is False
        assert temp_dir is None
        yield repo

    monkeypatch.setattr("codex_preflight_cli.main.clone_repo_to_temp", fake_clone)
    monkeypatch.setattr("codex_preflight_cli.main.resolve_cloned_commit", lambda cloned: "abc123")

    result = CliRunner().invoke(
        app,
        [
            "preflight",
            "--repo",
            "https://github.com/example/safe-repo.git",
            "--ref",
            "main",
            "--depth",
            "7",
            "--command",
            "cat README.md",
            "--format",
            "json",
            "--no-cache",
        ],
    )

    assert result.exit_code in {0, 10}
    report = json.loads(result.output)
    assert report["repo"]["sourceType"] == "github"
    assert report["repo"]["cloneUrl"] == "https://github.com/example/safe-repo.git"
    assert report["repo"]["requestedRef"] == "main"
    assert report["repo"]["resolvedCommit"] == "abc123"


def test_clone_repo_to_temp_uses_ref_depth_and_reports_clear_errors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> object:
        calls.append(args)
        target = Path(args[-1]) if args[:2] == ["git", "clone"] else None
        if target is not None:
            target.mkdir(parents=True)
            (target / "README.md").write_text("hello", encoding="utf-8")

        class Result:
            returncode = 0
            stdout = "ok"
            stderr = ""

        return Result()

    monkeypatch.setattr("codex_preflight_core.repo.temp_clone.subprocess.run", fake_run)

    with clone_repo_to_temp(
        "https://github.com/example/repo.git",
        ref="v1.2.3",
        depth=3,
        temp_dir=tmp_path,
    ) as cloned:
        assert (cloned / "README.md").exists()

    assert calls[0][:5] == ["git", "clone", "--depth", "3", "https://github.com/example/repo.git"]
    assert Path(calls[0][5]).name == "repo"
    assert calls[1][:6] == ["git", "-C", str(cloned), "fetch", "--depth", "3"]
    assert calls[1][-2:] == ["origin", "v1.2.3"]
    assert calls[2] == ["git", "-C", str(cloned), "checkout", "--detach", "FETCH_HEAD"]


def test_clone_repo_to_temp_raises_actionable_clone_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from codex_preflight_core.repo.temp_clone import RepoCloneError

    def fake_run(args: list[str], **kwargs: object) -> object:
        class Result:
            returncode = 128
            stdout = ""
            stderr = "repository not found"

        return Result()

    monkeypatch.setattr("codex_preflight_core.repo.temp_clone.subprocess.run", fake_run)

    try:
        with clone_repo_to_temp("https://github.com/example/missing.git", temp_dir=tmp_path):
            pass
    except RepoCloneError as error:
        message = str(error)
        assert "Unable to clone repository" in message
        assert "https://github.com/example/missing.git" in message
        assert "repository not found" in message
    else:
        raise AssertionError("expected RepoCloneError")
