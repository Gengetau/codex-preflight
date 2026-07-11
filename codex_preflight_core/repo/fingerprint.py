import math
import os
import stat
import time
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path

from codex_preflight_core.repo.collector import (
    CriticalFileCollectionError,
    CriticalFileCollectionLimitError,
    collect_critical_files,
)
from codex_preflight_core.repo.safe_path import local_absolute_path, open_regular_file_nofollow

_READ_CHUNK_BYTES = 64 * 1024


class CriticalFingerprintError(OSError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def compute_critical_fingerprint(
    root: Path,
    command: str | None = None,
    *,
    max_files: int | None = None,
    max_file_bytes: int | None = None,
    max_total_bytes: int | None = None,
    deadline: float | None = None,
    cancellation_check: Callable[[], bool] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    strict_safety: bool = False,
) -> str:
    _validate_limit(max_files)
    _validate_limit(max_file_bytes)
    _validate_limit(max_total_bytes)
    if deadline is not None and (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise ValueError("deadline must be a finite monotonic timestamp")
    if type(strict_safety) is not bool:
        raise ValueError("strict_safety must be a boolean")
    _check_budget(deadline, cancellation_check, monotonic)
    try:
        if strict_safety:
            _assert_safe_root(root)
            root = local_absolute_path(root)
        else:
            root = root.resolve()
    except OSError as error:
        raise CriticalFingerprintError("unavailable", "The repository root is unsafe.") from error
    _check_budget(deadline, cancellation_check, monotonic)

    def budget_check() -> None:
        _check_budget(deadline, cancellation_check, monotonic)

    try:
        files = collect_critical_files(
            root,
            command=command,
            budget_check=budget_check,
            reject_unsafe=strict_safety,
            max_files=max_files,
        )
    except CriticalFileCollectionLimitError as error:
        raise CriticalFingerprintError("limit-exceeded", "The critical-file limit was exceeded.") from error
    except CriticalFileCollectionError as error:
        raise CriticalFingerprintError("unavailable", "A critical file could not be read safely.") from error
    _check_budget(deadline, cancellation_check, monotonic)
    if max_files is not None and len(files) > max_files:
        raise CriticalFingerprintError("limit-exceeded", "The critical-file limit was exceeded.")

    entries: list[str] = []
    total_bytes = 0
    for relative in files:
        _check_budget(deadline, cancellation_check, monotonic)
        path = root / relative
        try:
            _check_budget(deadline, cancellation_check, monotonic)
            size, digest = _hash_bounded_file(
                path,
                total_bytes=total_bytes,
                max_file_bytes=max_file_bytes,
                max_total_bytes=max_total_bytes,
                budget_check=budget_check,
                strict_safety=strict_safety,
            )
        except CriticalFingerprintError:
            raise
        except OSError as error:
            raise CriticalFingerprintError("unavailable", "A critical file could not be read safely.") from error
        total_bytes += size
        entries.append(f"{relative.as_posix()}:{digest}")
        _check_budget(deadline, cancellation_check, monotonic)
    _check_budget(deadline, cancellation_check, monotonic)
    joined = "\n".join(entries).encode("utf-8")
    return f"sha256:{sha256(joined).hexdigest()}"


def _hash_bounded_file(
    path: Path,
    *,
    total_bytes: int,
    max_file_bytes: int | None,
    max_total_bytes: int | None,
    budget_check: Callable[[], None],
    strict_safety: bool,
) -> tuple[int, str]:
    size = 0
    digest = sha256()
    budget_check()
    context = open_regular_file_nofollow(path) if strict_safety else path.open("rb")
    with context as handle:
        opened = os.fstat(handle.fileno())
        if strict_safety:
            _validate_regular_file(opened)
        expected_size = opened.st_size
        budget_check()
        if expected_size < 0:
            raise OSError("negative file size")
        if max_file_bytes is not None and expected_size > max_file_bytes:
            raise CriticalFingerprintError("limit-exceeded", "The critical-file size limit was exceeded.")
        if max_total_bytes is not None and total_bytes + expected_size > max_total_bytes:
            raise CriticalFingerprintError("limit-exceeded", "The total critical-file limit was exceeded.")
        while True:
            budget_check()
            chunk = handle.read(_READ_CHUNK_BYTES)
            budget_check()
            if not chunk:
                break
            size += len(chunk)
            if max_file_bytes is not None and size > max_file_bytes:
                raise CriticalFingerprintError("limit-exceeded", "The critical-file size limit was exceeded.")
            if max_total_bytes is not None and total_bytes + size > max_total_bytes:
                raise CriticalFingerprintError("limit-exceeded", "The total critical-file limit was exceeded.")
            digest.update(chunk)
    budget_check()
    return size, digest.hexdigest()


def _assert_safe_root(root: Path) -> None:
    absolute = root.absolute()
    parts = absolute.parts
    if not parts:
        raise OSError("invalid repository root")
    candidate = Path(parts[0])
    for part in parts[1:]:
        info = candidate.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise OSError("repository root uses a reparse path")
        candidate /= part
    info = candidate.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise OSError("repository root uses a reparse path")


def _validate_regular_file(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _is_reparse(info)
        or info.st_nlink != 1
    ):
        raise OSError("unsafe critical file")


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _validate_limit(value: int | None) -> None:
    if value is not None and (type(value) is not int or value < 0):
        raise ValueError("fingerprint limits must be non-negative integers")


def _check_budget(
    deadline: float | None,
    cancellation_check: Callable[[], bool] | None,
    monotonic: Callable[[], float],
) -> None:
    if cancellation_check is not None:
        try:
            cancelled = cancellation_check()
        except Exception as error:
            raise CriticalFingerprintError("cancelled", "The target operation was cancelled.") from error
        if cancelled:
            raise CriticalFingerprintError("cancelled", "The target operation was cancelled.")
    if deadline is not None:
        try:
            now = monotonic()
        except Exception as error:
            raise CriticalFingerprintError("timeout", "The target operation reached its timeout.") from error
        if (
            isinstance(now, bool)
            or not isinstance(now, (int, float))
            or not math.isfinite(now)
            or now >= deadline
        ):
            raise CriticalFingerprintError("timeout", "The target operation reached its timeout.")
