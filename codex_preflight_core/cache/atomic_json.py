import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


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
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        _write_json_direct(path, data)
        return
    temp_path: Path | None = None
    try:
        temp_path = path.parent / f"{path.name}.{uuid4().hex}.tmp"
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def _write_json_direct(path: Path, data: object) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
