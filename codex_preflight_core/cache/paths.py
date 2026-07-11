import os
from pathlib import Path


def default_cache_dir() -> Path:
    override = os.environ.get("CODEX_PREFLIGHT_HOME")
    if override:
        return Path(override)
    return Path.home() / ".codex-preflight"


def scan_cache_path(base: Path | None = None) -> Path:
    return (base or default_cache_dir()) / "scan-cache.json"


def trust_cache_path(base: Path | None = None) -> Path:
    return (base or default_cache_dir()) / "trust.json"


def remote_scan_cache_path(base: Path | None = None) -> Path:
    return (base or default_cache_dir()) / "remote" / "scan-cache.json"


def remote_audit_path(base: Path | None = None) -> Path:
    return (base or default_cache_dir()) / "remote" / "audit.jsonl"
