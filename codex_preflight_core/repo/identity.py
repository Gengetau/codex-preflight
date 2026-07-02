from dataclasses import dataclass
from pathlib import Path

from codex_preflight_core.repo.git import run_git


@dataclass(frozen=True)
class RepoIdentity:
    path: Path
    remote_url: str | None
    head_commit: str | None
    branch: str | None
    identity_confidence: str

    @property
    def repo_id(self) -> str:
        return self.remote_url or str(self.path)


def resolve_repo_identity(cwd: Path) -> RepoIdentity:
    cwd = cwd.resolve()
    root = run_git(cwd, "rev-parse", "--show-toplevel")
    if root is None:
        return RepoIdentity(cwd, None, None, None, "low")

    root_path = Path(root).resolve()
    return RepoIdentity(
        path=root_path,
        remote_url=run_git(root_path, "remote", "get-url", "origin"),
        head_commit=run_git(root_path, "rev-parse", "HEAD"),
        branch=run_git(root_path, "branch", "--show-current"),
        identity_confidence="high",
    )
