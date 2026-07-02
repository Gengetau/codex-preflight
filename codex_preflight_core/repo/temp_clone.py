import os
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


@contextmanager
def clone_repo_to_temp(repo: str, keep_temp: bool = False) -> Iterator[Path]:
    local_temp = Path.cwd() / "test-tmp"
    local_temp.mkdir(exist_ok=True)
    parent = local_temp / f"codex-preflight-{uuid4().hex}"
    parent.mkdir()
    target = parent / "repo"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo, str(target)],
            check=True,
            capture_output=True,
            text=True,
        )
        yield target
    finally:
        if not keep_temp:
            try:
                shutil.rmtree(parent, onexc=_make_writable_and_retry)
            except OSError:
                pass


def _make_writable_and_retry(function: object, path: str, excinfo: BaseException) -> None:
    _ = excinfo
    os.chmod(path, 0o700)
    function(path)
