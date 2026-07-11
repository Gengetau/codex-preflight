import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class CacheLockTimeoutError(TimeoutError):
    pass


@contextmanager
def locked_cache_file(
    path: Path,
    *,
    timeout: float = 5.0,
    lock_opener: Callable[[Path], BinaryIO] | None = None,
) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    opener = lock_opener or (lambda candidate: candidate.open("a+b"))
    with opener(lock_path) as handle:
        deadline = time.monotonic() + timeout
        while True:
            try:
                _lock(handle)
                break
            except OSError as error:
                if time.monotonic() >= deadline:
                    raise CacheLockTimeoutError("The cache lock timed out.") from error
                time.sleep(0.01)
        try:
            yield
        finally:
            _unlock(handle)


def _lock(handle) -> None:
    if os.name == "nt":
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(handle) -> None:
    if os.name == "nt":
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
