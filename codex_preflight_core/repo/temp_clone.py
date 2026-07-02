import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


@contextmanager
def clone_repo_to_temp(
    repo: str,
    keep_temp: bool = False,
    temp_dir: Path | None = None,
) -> Iterator[Path]:
    if keep_temp:
        parent = _manual_temp_parent(temp_dir)
        print(f"Kept temporary clone at {parent}", file=sys.stderr)
    elif temp_dir is not None:
        parent = _manual_temp_parent(temp_dir)
    else:
        parent = _manual_temp_parent(_default_temp_root())
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
                _cleanup_tree(parent)
            except OSError as error:
                print(f"Warning: failed to remove temporary clone {parent}: {error}", file=sys.stderr)


def _cleanup_tree(path: Path) -> None:
    shutil.rmtree(path, onexc=_make_writable_and_retry)


def _manual_temp_parent(root: Path | None) -> Path:
    base = root if root is not None else _default_temp_root()
    base.mkdir(parents=True, exist_ok=True)
    parent = base / f"codex-preflight-{uuid4().hex}"
    parent.mkdir()
    return parent


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
        probe.rmdir()
    except OSError:
        return False
    return True


def _make_writable_and_retry(function: object, path: str, excinfo: BaseException) -> None:
    _ = excinfo
    os.chmod(path, 0o700)
    function(path)
