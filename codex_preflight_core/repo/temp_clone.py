import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4


class RepoCloneError(RuntimeError):
    pass


GIT_PROTOCOL_HARDENING = [
    "-c",
    "protocol.ext.allow=never",
    "-c",
    "protocol.file.allow=never",
    "-c",
    "protocol.ssh.allow=never",
]


@contextmanager
def clone_repo_to_temp(
    repo: str,
    ref: str | None = None,
    depth: int = 1,
    keep_temp: bool = False,
    temp_dir: Path | None = None,
) -> Iterator[Path]:
    validate_clone_url(repo)
    temporary_directory: tempfile.TemporaryDirectory[str] | None = None
    if keep_temp:
        parent = _manual_temp_parent(temp_dir)
        print(f"Kept temporary clone at {parent}", file=sys.stderr)
    elif temp_dir is not None:
        parent = _manual_temp_parent(temp_dir)
    else:
        temporary_directory = _temporary_directory()
        parent = (
            Path(temporary_directory.name)
            if temporary_directory is not None
            else _manual_temp_parent(Path.cwd() / "test-tmp")
        )
    target = parent / "repo"
    try:
        _run_git(
            ["git", *GIT_PROTOCOL_HARDENING, "clone", "--depth", str(depth), repo, str(target)],
            error_prefix=f"Unable to clone repository {repo}",
        )
        if ref:
            _run_git(
                ["git", *GIT_PROTOCOL_HARDENING, "-C", str(target), "fetch", "--depth", str(depth), "origin", ref],
                error_prefix=f"Unable to fetch ref {ref} from {repo}",
            )
            _run_git(
                ["git", "-C", str(target), "checkout", "--detach", "FETCH_HEAD"],
                error_prefix=f"Unable to check out ref {ref} from {repo}",
            )
        yield target
    finally:
        if not keep_temp:
            try:
                if temporary_directory is not None:
                    temporary_directory.cleanup()
                else:
                    _cleanup_tree(parent)
            except OSError as error:
                print(f"Warning: failed to remove temporary clone {parent}: {error}", file=sys.stderr)


def _cleanup_tree(path: Path) -> None:
    shutil.rmtree(path, onexc=_make_writable_and_retry)


def resolve_cloned_commit(path: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def validate_clone_url(repo: str) -> None:
    candidate = repo.strip()
    lowered = candidate.lower()
    if not candidate or candidate.startswith("-"):
        raise RepoCloneError(f"Unsupported clone URL: {repo}")
    if lowered.startswith(("ext::", "file://", "ssh://", "git://")):
        raise RepoCloneError(f"Unsupported clone URL: {repo}")
    parsed = urlparse(candidate)
    if parsed.scheme != "https":
        raise RepoCloneError(f"Unsupported clone URL: {repo}. Only https:// clone URLs are allowed.")
    if Path(candidate).is_absolute():
        raise RepoCloneError(f"Unsupported clone URL: {repo}")


def _run_git(args: list[str], error_prefix: str) -> None:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git exited without details"
        raise RepoCloneError(f"{error_prefix}. {detail}")


def _manual_temp_parent(root: Path | None) -> Path:
    base = root if root is not None else _default_temp_root()
    base.mkdir(parents=True, exist_ok=True)
    parent = base / f"codex-preflight-{uuid4().hex}"
    parent.mkdir()
    return parent


def _temporary_directory() -> tempfile.TemporaryDirectory[str] | None:
    for base in (_default_temp_root(), Path.cwd() / "test-tmp"):
        base.mkdir(parents=True, exist_ok=True)
        temporary_directory = tempfile.TemporaryDirectory(prefix="codex-preflight-", dir=base)
        parent = Path(temporary_directory.name)
        try:
            _assert_can_create_clone_target(parent)
            return temporary_directory
        except OSError:
            try:
                temporary_directory.cleanup()
            except OSError:
                pass
    return None


def _default_temp_root() -> Path:
    system_temp = Path(tempfile.gettempdir())
    if _can_create_child_dir(system_temp):
        return system_temp
    fallback = Path.cwd() / "test-tmp"
    fallback.mkdir(exist_ok=True)
    return fallback


def _can_create_child_dir(parent: Path) -> bool:
    probe = parent / f"codex-preflight-probe-{uuid4().hex}"
    try:
        parent.mkdir(parents=True, exist_ok=True)
        probe.mkdir()
        (probe / "repo").mkdir()
        _cleanup_tree(probe)
    except OSError:
        return False
    return True


def _assert_can_create_clone_target(parent: Path) -> None:
    probe = parent / f"repo-probe-{uuid4().hex}"
    probe.mkdir()
    probe.rmdir()


def _make_writable_and_retry(function: object, path: str, excinfo: BaseException) -> None:
    _ = excinfo
    os.chmod(path, 0o700)
    function(path)
