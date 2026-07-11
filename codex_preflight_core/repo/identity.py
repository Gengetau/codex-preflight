import configparser
import math
import os
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from codex_preflight_core.repo.git import GIT_METADATA_TIMEOUT_SECONDS, run_git
from codex_preflight_core.repo.safe_path import (
    SafePathError,
    hold_directory_nofollow,
    local_absolute_path,
    read_text_file_nofollow,
)

_GIT_CONTROL_FILE_MAX_BYTES = 1024 * 1024


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


@dataclass(frozen=True)
class _GitLayout:
    worktree: Path
    git_dir: Path
    common_dir: Path


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
    try:
        cwd = local_absolute_path(cwd)
        with hold_directory_nofollow(cwd):
            pass
        layout = _discover_git_layout(cwd)
    except (OSError, ValueError, configparser.Error):
        raise RepoIdentityError("unsafe", "The repository identity path is unsafe.") from None
    _check_budget(deadline, cancellation_check, monotonic)
    if layout is None:
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
        try:
            root_path = local_absolute_path(root)
            with hold_directory_nofollow(root_path):
                pass
            layout = _discover_git_layout(root_path)
        except (OSError, ValueError, configparser.Error):
            raise RepoIdentityError("unsafe", "The repository identity path is unsafe.") from None
        if layout is None:
            raise RepoIdentityError("unsafe", "The repository identity path is unsafe.")

    prefix = (f"--git-dir={layout.git_dir}", f"--work-tree={layout.worktree}")
    try:
        with ExitStack() as stack:
            for path in dict.fromkeys((layout.worktree, layout.git_dir, layout.common_dir)):
                stack.enter_context(hold_directory_nofollow(path))
            root = _read_git(
                layout.worktree,
                *prefix,
                "rev-parse",
                "--show-toplevel",
                deadline=deadline,
                cancellation_check=cancellation_check,
                monotonic=monotonic,
            )
            if root is None:
                return RepoIdentity(cwd, None, None, None, "low")
            root_path = local_absolute_path(root)
            if not _same_path(root_path, layout.worktree):
                raise SafePathError("Git returned an unexpected worktree.")
            _check_budget(deadline, cancellation_check, monotonic)
            return RepoIdentity(
                path=layout.worktree,
                remote_url=_read_git(
                    layout.worktree,
                    *prefix,
                    "remote",
                    "get-url",
                    "origin",
                    deadline=deadline,
                    cancellation_check=cancellation_check,
                    monotonic=monotonic,
                ),
                head_commit=_read_git(
                    layout.worktree,
                    *prefix,
                    "rev-parse",
                    "HEAD",
                    deadline=deadline,
                    cancellation_check=cancellation_check,
                    monotonic=monotonic,
                ),
                branch=_read_git(
                    layout.worktree,
                    *prefix,
                    "branch",
                    "--show-current",
                    deadline=deadline,
                    cancellation_check=cancellation_check,
                    monotonic=monotonic,
                ),
                identity_confidence="high",
            )
    except RepoIdentityError:
        raise
    except (OSError, ValueError, configparser.Error):
        raise RepoIdentityError("unsafe", "The repository identity path is unsafe.") from None


def _discover_git_layout(cwd: Path) -> _GitLayout | None:
    for worktree in _discovery_candidates(cwd):
        marker = worktree / ".git"
        try:
            with hold_directory_nofollow(marker):
                git_dir = marker
        except FileNotFoundError:
            continue
        except SafePathError:
            try:
                git_dir = _parse_gitfile(marker)
            except FileNotFoundError:
                continue
        with hold_directory_nofollow(git_dir):
            pass
        common_dir = _read_common_dir(git_dir)
        with hold_directory_nofollow(common_dir):
            pass
        configured_worktree = _read_configured_worktree(git_dir, common_dir)
        selected_worktree = configured_worktree or worktree
        with hold_directory_nofollow(selected_worktree):
            pass
        return _GitLayout(selected_worktree, git_dir, common_dir)
    return None


def _discovery_candidates(cwd: Path) -> tuple[Path, ...]:
    ceilings: set[str] = set()
    for value in os.environ.get("GIT_CEILING_DIRECTORIES", "").split(os.pathsep):
        if not value:
            continue
        try:
            ceilings.add(_path_key(local_absolute_path(value)))
        except SafePathError:
            continue
    candidates: list[Path] = []
    for candidate in (cwd, *cwd.parents):
        candidates.append(candidate)
        if _path_key(candidate) in ceilings:
            break
    return tuple(candidates)


def _parse_gitfile(path: Path) -> Path:
    value = read_text_file_nofollow(path, max_bytes=4096)
    lines = value.splitlines()
    if len(lines) != 1 or not lines[0].startswith("gitdir: "):
        raise SafePathError("The Git control file is invalid.")
    return local_absolute_path(lines[0][len("gitdir: ") :], base=path.parent)


def _read_common_dir(git_dir: Path) -> Path:
    try:
        value = read_text_file_nofollow(git_dir / "commondir", max_bytes=4096).strip()
    except FileNotFoundError:
        return git_dir
    if not value or "\n" in value or "\r" in value:
        raise SafePathError("The Git common directory file is invalid.")
    return local_absolute_path(value, base=git_dir)


def _read_configured_worktree(git_dir: Path, common_dir: Path) -> Path | None:
    config = _read_optional_config(common_dir / "config")
    worktree_value, worktree_config = _inspect_git_config(config)
    if worktree_config:
        worktree_specific = _read_optional_config(git_dir / "config.worktree")
        specific_value, _specific_flag = _inspect_git_config(worktree_specific)
        if specific_value is not None:
            worktree_value = specific_value
    if worktree_value is None:
        return None
    return local_absolute_path(worktree_value, base=git_dir)


def _read_optional_config(path: Path) -> str:
    try:
        return read_text_file_nofollow(path, max_bytes=_GIT_CONTROL_FILE_MAX_BYTES)
    except FileNotFoundError:
        return ""


def _inspect_git_config(value: str) -> tuple[str | None, bool]:
    if not value:
        return None, False
    parser = configparser.RawConfigParser(interpolation=None, strict=False)
    parser.read_string(value)
    worktree: str | None = None
    worktree_config = False
    for section in parser.sections():
        lowered = section.lower()
        if lowered == "include" or lowered.startswith("includeif "):
            if parser.has_option(section, "path"):
                raise SafePathError("Git config includes are not permitted for trust identity.")
        elif lowered == "core" and parser.has_option(section, "worktree"):
            worktree = _strip_config_value(parser.get(section, "worktree"))
        elif lowered == "extensions" and parser.has_option(section, "worktreeconfig"):
            worktree_config = parser.getboolean(section, "worktreeconfig")
    return worktree, worktree_config


def _strip_config_value(value: str) -> str:
    result = value.strip()
    if len(result) >= 2 and result[0] == result[-1] and result[0] in {"'", '"'}:
        result = result[1:-1]
    if not result:
        raise SafePathError("The Git config path is invalid.")
    return result


def _same_path(left: Path, right: Path) -> bool:
    return _path_key(left) == _path_key(right)


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


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
