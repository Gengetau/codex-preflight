from pathlib import Path


def default_cache_dir() -> Path:
    return Path.home() / ".codex-preflight"


def scan_cache_path(base: Path | None = None) -> Path:
    return (base or default_cache_dir()) / "scan-cache.json"


def trust_cache_path(base: Path | None = None) -> Path:
    return (base or default_cache_dir()) / "trust.json"
