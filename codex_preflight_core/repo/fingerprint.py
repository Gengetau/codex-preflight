import time
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path

from codex_preflight_core.repo.collector import collect_critical_files


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
) -> str:
    _validate_limit(max_files)
    _validate_limit(max_file_bytes)
    _validate_limit(max_total_bytes)
    if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float))):
        raise ValueError("deadline must be a finite monotonic timestamp")
    root = root.resolve()
    _check_budget(deadline, cancellation_check, monotonic)
    files = collect_critical_files(root, command=command)
    if max_files is not None and len(files) > max_files:
        raise CriticalFingerprintError("limit-exceeded", "The critical-file limit was exceeded.")

    entries: list[str] = []
    total_bytes = 0
    for relative in files:
        _check_budget(deadline, cancellation_check, monotonic)
        path = root / relative
        try:
            expected_size = path.stat().st_size
            if expected_size < 0:
                raise OSError("negative file size")
            if max_file_bytes is not None and expected_size > max_file_bytes:
                raise CriticalFingerprintError("limit-exceeded", "The critical-file size limit was exceeded.")
            if max_total_bytes is not None and total_bytes + expected_size > max_total_bytes:
                raise CriticalFingerprintError("limit-exceeded", "The total critical-file limit was exceeded.")
            contents = path.read_bytes()
        except CriticalFingerprintError:
            raise
        except OSError as error:
            raise CriticalFingerprintError("unavailable", "A critical file could not be read safely.") from error
        if max_file_bytes is not None and len(contents) > max_file_bytes:
            raise CriticalFingerprintError("limit-exceeded", "The critical-file size limit was exceeded.")
        if max_total_bytes is not None and total_bytes + len(contents) > max_total_bytes:
            raise CriticalFingerprintError("limit-exceeded", "The total critical-file limit was exceeded.")
        total_bytes += len(contents)
        digest = sha256(contents).hexdigest()
        entries.append(f"{relative.as_posix()}:{digest}")
        _check_budget(deadline, cancellation_check, monotonic)
    joined = "\n".join(entries).encode("utf-8")
    return f"sha256:{sha256(joined).hexdigest()}"


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
        if now >= deadline:
            raise CriticalFingerprintError("timeout", "The target operation reached its timeout.")
