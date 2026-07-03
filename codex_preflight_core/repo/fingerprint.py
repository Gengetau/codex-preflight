from hashlib import sha256
from pathlib import Path

from codex_preflight_core.repo.collector import collect_critical_files


def compute_critical_fingerprint(root: Path, command: str | None = None) -> str:
    root = root.resolve()
    entries: list[str] = []
    for relative in collect_critical_files(root, command=command):
        digest = sha256((root / relative).read_bytes()).hexdigest()
        entries.append(f"{relative.as_posix()}:{digest}")
    joined = "\n".join(entries).encode("utf-8")
    return f"sha256:{sha256(joined).hexdigest()}"
