import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from codex_preflight_core.repo.git import GIT_METADATA_TIMEOUT_SECONDS, run_git


class RepoIdentityError(OSError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


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


def resolve_repo_identity(
    cwd: Path,
    *,
    deadline: float | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> RepoIdentity:
    if deadline is not None and (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise ValueError("deadline must be a finite monotonic timestamp")
    _check_budget(deadline, cancellation_check, monotonic)
    cwd = cwd.resolve()
    _check_budget(deadline, cancellation_check, monotonic)
    root = _read_git(
        cwd,
        "rev-parse",
        "--show-toplevel",
        deadline=deadline,
        cancellation_check=cancellation_check,
        monotonic=monotonic,
    )
    if root is None:
        return RepoIdentity(cwd, None, None, None, "low")

    _check_budget(deadline, cancellation_check, monotonic)
    root_path = Path(root).resolve()
    _check_budget(deadline, cancellation_check, monotonic)
    return RepoIdentity(
        path=root_path,
        remote_url=_read_git(
            root_path,
            "remote",
            "get-url",
            "origin",
            deadline=deadline,
            cancellation_check=cancellation_check,
            monotonic=monotonic,
        ),
        head_commit=_read_git(
            root_path,
            "rev-parse",
            "HEAD",
            deadline=deadline,
            cancellation_check=cancellation_check,
            monotonic=monotonic,
        ),
        branch=_read_git(
            root_path,
            "branch",
            "--show-current",
            deadline=deadline,
            cancellation_check=cancellation_check,
            monotonic=monotonic,
        ),
        identity_confidence="high",
    )


def _read_git(
    root: Path,
    *git_args: str,
    deadline: float | None,
    cancellation_check: Callable[[], bool] | None,
    monotonic: Callable[[], float],
) -> str | None:
    timeout = _remaining_git_timeout(deadline, cancellation_check, monotonic)
    result = run_git(root, *git_args, timeout=timeout)
    _check_budget(deadline, cancellation_check, monotonic)
    return result


def _remaining_git_timeout(
    deadline: float | None,
    cancellation_check: Callable[[], bool] | None,
    monotonic: Callable[[], float],
) -> float:
    if cancellation_check is not None:
        try:
            if cancellation_check():
                raise RepoIdentityError("cancelled", "The target operation was cancelled.")
        except RepoIdentityError:
            raise
        except Exception as error:
            raise RepoIdentityError("cancelled", "The target operation was cancelled.") from error
    if deadline is None:
        return GIT_METADATA_TIMEOUT_SECONDS
    try:
        now = monotonic()
    except Exception as error:
        raise RepoIdentityError("timeout", "The target operation reached its timeout.") from error
    if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now) or now >= deadline:
        raise RepoIdentityError("timeout", "The target operation reached its timeout.")
    return min(GIT_METADATA_TIMEOUT_SECONDS, float(deadline - now))


def _check_budget(
    deadline: float | None,
    cancellation_check: Callable[[], bool] | None,
    monotonic: Callable[[], float],
) -> None:
    if cancellation_check is not None:
        try:
            cancelled = cancellation_check()
        except Exception as error:
            raise RepoIdentityError("cancelled", "The target operation was cancelled.") from error
        if cancelled:
            raise RepoIdentityError("cancelled", "The target operation was cancelled.")
    if deadline is None:
        return
    try:
        now = monotonic()
    except Exception as error:
        raise RepoIdentityError("timeout", "The target operation reached its timeout.") from error
    if (
        isinstance(now, bool)
        or not isinstance(now, (int, float))
        or not math.isfinite(now)
        or now >= deadline
    ):
        raise RepoIdentityError("timeout", "The target operation reached its timeout.")
