import json
import os
import shutil
import stat
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from codex_preflight_core.cache.file_lock import (
    open_owner_only_file,
    replace_file_durably,
    validate_private_cache_storage,
)


def read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
        backup = path.with_name(f"{path.name}.corrupt.{timestamp}")
        shutil.copy2(path, backup)
        return default


def write_json_atomic(path: Path, data: object) -> None:
    encoded = json.dumps(data, indent=2).replace("\n", os.linesep).encode("utf-8")
    write_bytes_atomic(path, encoded)


def write_bytes_atomic(path: Path, data: bytes, *, private_storage: bool = False) -> None:
    if private_storage:
        validate_private_cache_storage(path)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        temp_path = path.parent / f"{path.name}.{uuid4().hex}.tmp"
        if private_storage:
            handle_context = open_owner_only_file(temp_path)
        else:
            handle_context = temp_path.open("xb")
        with handle_context as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if private_storage:
            validate_private_cache_storage(temp_path)
        elif path.exists():
            os.chmod(temp_path, stat.S_IMODE(path.stat().st_mode))
        else:
            os.chmod(temp_path, 0o600)
        if private_storage:
            replace_file_durably(temp_path, path)
        else:
            os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
