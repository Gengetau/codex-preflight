from dataclasses import dataclass
from pathlib import Path

MAX_FILE_SIZE = 2 * 1024 * 1024


@dataclass(frozen=True)
class ReadResult:
    text: str | None
    skipped_reason: str | None = None


def read_text_safely(root: Path, relative: Path, max_size: int = MAX_FILE_SIZE) -> ReadResult:
    root = root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return ReadResult(None, "outside_repo")
    if not path.is_file():
        return ReadResult(None, "not_file")
    if path.stat().st_size > max_size:
        return ReadResult(None, "oversized")
    data = path.read_bytes()
    if b"\x00" in data[:4096]:
        return ReadResult(None, "binary")
    try:
        return ReadResult(data.decode("utf-8"))
    except UnicodeDecodeError:
        return ReadResult(data.decode("utf-8", errors="replace"))
