import configparser
import json
import math
import os
import re
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
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
_GIT_PACKED_REFS_MAX_BYTES = 8 * 1024 * 1024
_GIT_REF = re.compile(r"refs/(?!.*(?:^|/)\.\.?)(?!.*[\\:*?\[~^\x00-\x20])[^\x00-\x20]+\Z")
_GIT_OBJECT = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?\Z")


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
    config: str
    worktree_config: str


@dataclass(frozen=True)
class _ConfigValues:
    worktree: str | None
    worktree_config: bool
    remote_url: str | None


def resolve_repo_identity(
    cwd: Path,
    *,
    deadline: float | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    strict_safety: bool = False,
) -> RepoIdentity:
    if deadline is not None and (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise ValueError("deadline must be a finite monotonic timestamp")
    if type(strict_safety) is not bool:
        raise ValueError("strict_safety must be a boolean")
    _check_budget(deadline, cancellation_check, monotonic)
    if not strict_safety:
        return _resolve_ordinary(
            cwd,
            deadline=deadline,
            cancellation_check=cancellation_check,
            monotonic=monotonic,
        )
    return _resolve_strict(
        cwd,
        deadline=deadline,
        cancellation_check=cancellation_check,
        monotonic=monotonic,
    )


def _resolve_ordinary(
    cwd: Path,
    *,
    deadline: float | None,
    cancellation_check: Callable[[], bool] | None,
    monotonic: Callable[[], float],
) -> RepoIdentity:
    try:
        cwd = cwd.resolve(strict=True)
        if not cwd.is_dir():
            raise OSError("not a directory")
    except (OSError, RuntimeError, ValueError):
        raise RepoIdentityError("unsafe", "The repository identity path is unsafe.") from None
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
        root_path = Path(root).resolve(strict=True)
        if not root_path.is_dir():
            raise OSError("not a directory")
    except (OSError, RuntimeError, ValueError):
        raise RepoIdentityError("unsafe", "The repository identity path is unsafe.") from None
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


def _resolve_strict(
    cwd: Path,
    *,
    deadline: float | None,
    cancellation_check: Callable[[], bool] | None,
    monotonic: Callable[[], float],
) -> RepoIdentity:
    try:
        cwd = local_absolute_path(cwd)
        with hold_directory_nofollow(cwd):
            pass
        layout = _discover_git_layout(cwd)
    except (OSError, ValueError, configparser.Error):
        raise RepoIdentityError("unsafe", "The repository identity path is unsafe.") from None
    _check_budget(deadline, cancellation_check, monotonic)
    if layout is None:
        return RepoIdentity(cwd, None, None, None, "low")

    try:
        with ExitStack() as stack:
            for path in dict.fromkeys((layout.worktree, layout.git_dir, layout.common_dir)):
                stack.enter_context(hold_directory_nofollow(path))
            snapshot = stack.enter_context(_control_snapshot(layout))
            prefix = (f"--git-dir={snapshot}", f"--work-tree={layout.worktree}")
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
                raise SafePathError("Git did not return the mandatory worktree root.")
            root_path = local_absolute_path(root)
            if not _same_path(root_path, layout.worktree):
                raise SafePathError("Git returned an unexpected worktree.")
            remote_url = _read_git(
                layout.worktree,
                *prefix,
                "remote",
                "get-url",
                "origin",
                deadline=deadline,
                cancellation_check=cancellation_check,
                monotonic=monotonic,
            )
            head_commit = _read_git(
                layout.worktree,
                *prefix,
                "rev-parse",
                "HEAD",
                deadline=deadline,
                cancellation_check=cancellation_check,
                monotonic=monotonic,
            )
            if head_commit is None:
                raise SafePathError("Git did not return the mandatory head.")
            branch = _read_git(
                layout.worktree,
                *prefix,
                "branch",
                "--show-current",
                deadline=deadline,
                cancellation_check=cancellation_check,
                monotonic=monotonic,
            )
            return RepoIdentity(root_path, remote_url, head_commit, branch, "high")
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
        config = _read_optional_config(common_dir / "config")
        common_values = _inspect_git_config(config)
        worktree_config = ""
        selected_value = common_values.worktree
        if common_values.worktree_config:
            worktree_config = _read_optional_config(git_dir / "config.worktree")
            worktree_values = _inspect_git_config(worktree_config)
            if worktree_values.worktree is not None:
                selected_value = worktree_values.worktree
        selected_worktree = (
            local_absolute_path(selected_value, base=git_dir)
            if selected_value is not None
            else worktree
        )
        with hold_directory_nofollow(selected_worktree):
            pass
        if not _is_within(cwd, selected_worktree):
            raise SafePathError("The requested directory is outside the selected worktree.")
        return _GitLayout(selected_worktree, git_dir, common_dir, config, worktree_config)
    return None


def _discovery_candidates(cwd: Path) -> tuple[Path, ...]:
    return (cwd, *cwd.parents)


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


def _read_optional_config(path: Path) -> str:
    try:
        return read_text_file_nofollow(path, max_bytes=_GIT_CONTROL_FILE_MAX_BYTES)
    except FileNotFoundError:
        return ""


def _inspect_git_config(value: str) -> _ConfigValues:
    if not value:
        return _ConfigValues(None, False, None)
    parser = configparser.RawConfigParser(interpolation=None, strict=False)
    parser.read_string(value)
    worktree: str | None = None
    worktree_config = False
    remote_url: str | None = None
    for section in parser.sections():
        lowered = section.lower()
        if lowered == "include" or lowered.startswith("includeif "):
            if parser.has_option(section, "path"):
                raise SafePathError("Git config includes are not permitted for trust identity.")
        elif lowered == "core" and parser.has_option(section, "worktree"):
            worktree = _strip_config_value(parser.get(section, "worktree"))
        elif lowered == "extensions" and parser.has_option(section, "worktreeconfig"):
            worktree_config = parser.getboolean(section, "worktreeconfig")
        elif lowered == 'remote "origin"' and parser.has_option(section, "url"):
            remote_url = parser.get(section, "url").strip()
            if not remote_url or any(ord(character) < 32 for character in remote_url):
                raise SafePathError("The Git remote URL is invalid.")
    return _ConfigValues(worktree, worktree_config, remote_url)


@contextmanager
def _control_snapshot(layout: _GitLayout) -> Iterator[Path]:
    common_values = _inspect_git_config(layout.config)
    worktree_values = _inspect_git_config(layout.worktree_config)
    remote_url = worktree_values.remote_url or common_values.remote_url
    head, ref_name, object_id = _read_head(layout)
    with tempfile.TemporaryDirectory(prefix="codex-preflight-git-") as temporary:
        snapshot = Path(temporary) / "control"
        snapshot.mkdir(mode=0o700)
        (snapshot / "objects").mkdir()
        config = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        if remote_url is not None:
            config += f'[remote "origin"]\n\turl = {json.dumps(remote_url, ensure_ascii=True)}\n'
        (snapshot / "config").write_text(config, encoding="utf-8", newline="\n")
        (snapshot / "HEAD").write_text(f"{head}\n", encoding="ascii", newline="\n")
        if ref_name is not None:
            ref_path = snapshot.joinpath(*ref_name.split("/"))
            ref_path.parent.mkdir(parents=True)
            ref_path.write_text(f"{object_id}\n", encoding="ascii", newline="\n")
        yield snapshot


def _read_head(layout: _GitLayout) -> tuple[str, str | None, str]:
    head = read_text_file_nofollow(layout.git_dir / "HEAD", max_bytes=4096).strip()
    if head.startswith("ref: "):
        ref_name = head[len("ref: ") :]
        if _GIT_REF.fullmatch(ref_name) is None:
            raise SafePathError("The Git HEAD reference is invalid.")
        object_id = _read_loose_ref(layout.git_dir, ref_name)
        if object_id is None and not _same_path(layout.git_dir, layout.common_dir):
            object_id = _read_loose_ref(layout.common_dir, ref_name)
        if object_id is None:
            object_id = _read_packed_ref(layout.common_dir, ref_name)
        if object_id is None:
            raise SafePathError("The Git HEAD reference is unavailable.")
        return head, ref_name, object_id
    if _GIT_OBJECT.fullmatch(head) is None:
        raise SafePathError("The Git HEAD is invalid.")
    return head, None, head.lower()


def _read_loose_ref(directory: Path, ref_name: str) -> str | None:
    try:
        value = read_text_file_nofollow(
            directory.joinpath(*ref_name.split("/")),
            max_bytes=4096,
        ).strip()
    except FileNotFoundError:
        return None
    if _GIT_OBJECT.fullmatch(value) is None:
        raise SafePathError("The Git reference is invalid.")
    return value.lower()


def _read_packed_ref(directory: Path, ref_name: str) -> str | None:
    try:
        packed = read_text_file_nofollow(
            directory / "packed-refs",
            max_bytes=_GIT_PACKED_REFS_MAX_BYTES,
        )
    except FileNotFoundError:
        return None
    for line in packed.splitlines():
        if not line or line.startswith(("#", "^")):
            continue
        try:
            object_id, name = line.split(" ", 1)
        except ValueError:
            raise SafePathError("The packed Git references are invalid.") from None
        if name == ref_name:
            if _GIT_OBJECT.fullmatch(object_id) is None:
                raise SafePathError("The packed Git reference is invalid.")
            return object_id.lower()
    return None


def _strip_config_value(value: str) -> str:
    result = value.strip()
    if len(result) >= 2 and result[0] == result[-1] and result[0] in {"'", '"'}:
        result = result[1:-1]
    if not result:
        raise SafePathError("The Git config path is invalid.")
    return result


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


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
