from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

PLUGIN_NAME = "codex-preflight"
MARKETPLACE_PLUGIN_SOURCE = "./plugins/codex-preflight"
PLUGIN_FILES = (
    Path(".codex-plugin/plugin.json"),
    Path(".mcp.json"),
    Path("skills/codex-preflight/SKILL.md"),
    Path("hooks/hooks.json"),
    Path("scripts/launch-mcp.mjs"),
    Path("scripts/launch-hook.mjs"),
    Path("scripts/runtime-launcher.mjs"),
)


@dataclass(frozen=True)
class SyncItem:
    source: Path
    destination: Path


def sync_items(root: Path) -> list[SyncItem]:
    root = root.resolve()
    marketplace_plugin = root / "plugins" / PLUGIN_NAME
    items = [SyncItem(root / relative, marketplace_plugin / relative) for relative in PLUGIN_FILES]

    runtime_root = root / "runtime"
    if runtime_root.is_dir():
        for source in sorted(path for path in runtime_root.rglob("*") if path.is_file()):
            items.append(SyncItem(source, marketplace_plugin / "runtime" / source.relative_to(runtime_root)))
    return items


def check(root: Path) -> list[Path]:
    _validate_layout(root)
    stale: list[Path] = []
    for item in sync_items(root):
        if not item.destination.is_file() or item.destination.read_bytes() != item.source.read_bytes():
            stale.append(item.destination)
    stale.extend(_runtime_extras(root))
    return sorted(set(stale))


def sync(root: Path) -> list[Path]:
    _validate_layout(root)
    updated: list[Path] = []
    for extra in _runtime_extras(root):
        extra.unlink()
        updated.append(extra)
    _remove_empty_runtime_directories(root)

    for item in sync_items(root):
        source_bytes = item.source.read_bytes()
        destination_bytes = item.destination.read_bytes() if item.destination.is_file() else None
        if destination_bytes == source_bytes:
            continue
        item.destination.parent.mkdir(parents=True, exist_ok=True)
        item.destination.write_bytes(source_bytes)
        if item.source.stat().st_mode & 0o111:
            item.destination.chmod(item.destination.stat().st_mode | 0o111)
        updated.append(item.destination)
    return updated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sync the marketplace plugin copy from the root plugin package.")
    parser.add_argument("--check", action="store_true", help="Fail if the marketplace plugin copy is stale.")
    parser.add_argument(
        "--root",
        type=Path,
        default=_default_root(),
        help="Repository root. Defaults to this checkout.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    try:
        if args.check:
            stale = check(root)
            if stale:
                for path in stale:
                    print(f"stale: {_display(root, path)}")
                return 1
            print("up to date")
            return 0
        updated = sync(root)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if not updated:
        print("up to date")
        return 0
    for path in updated:
        print(f"synced: {_display(root, path)}")
    return 0


def _runtime_extras(root: Path) -> list[Path]:
    source_root = root.resolve() / "runtime"
    destination_root = root.resolve() / "plugins" / PLUGIN_NAME / "runtime"
    if not destination_root.is_dir():
        return []
    source_files = {
        path.relative_to(source_root)
        for path in source_root.rglob("*")
        if path.is_file()
    }
    return sorted(
        path
        for path in destination_root.rglob("*")
        if path.is_file() and path.relative_to(destination_root) not in source_files
    )


def _remove_empty_runtime_directories(root: Path) -> None:
    destination_root = root.resolve() / "plugins" / PLUGIN_NAME / "runtime"
    if not destination_root.is_dir():
        return
    for path in sorted((item for item in destination_root.rglob("*") if item.is_dir()), reverse=True):
        try:
            path.rmdir()
        except OSError:
            pass
    if destination_root.exists() and not any(destination_root.iterdir()):
        shutil.rmtree(destination_root)


def _validate_layout(root: Path) -> None:
    root = root.resolve()
    for item in sync_items(root):
        if not item.source.is_file():
            raise ValueError(f"missing source file: {_display(root, item.source)}")
        if item.source.is_symlink():
            raise ValueError(f"source file must not be a symlink: {_display(root, item.source)}")
        _validate_destination(root, item.destination)

    runtime_manifest = root / "runtime" / "runtime-manifest.json"
    if not runtime_manifest.is_file():
        raise ValueError("missing bundled runtime manifest: runtime/runtime-manifest.json")

    marketplace = root / ".agents" / "plugins" / "marketplace.json"
    if not marketplace.is_file():
        raise ValueError("missing marketplace wrapper: .agents/plugins/marketplace.json")

    try:
        data = json.loads(marketplace.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid marketplace JSON: {error}") from error

    plugins = data.get("plugins")
    if not isinstance(plugins, list):
        raise ValueError("marketplace wrapper must contain a plugins list")
    matching = [entry for entry in plugins if isinstance(entry, dict) and entry.get("name") == PLUGIN_NAME]
    if len(matching) != 1:
        raise ValueError(f"marketplace wrapper must contain exactly one {PLUGIN_NAME} plugin entry")
    source = matching[0].get("source")
    source_path = source.get("path") if isinstance(source, dict) else None
    if source_path != MARKETPLACE_PLUGIN_SOURCE:
        raise ValueError(f"marketplace plugin path must be {MARKETPLACE_PLUGIN_SOURCE}")


def _validate_destination(root: Path, destination: Path) -> None:
    marketplace_plugin = (root / "plugins" / PLUGIN_NAME).resolve()
    resolved = destination.resolve()
    if resolved != marketplace_plugin and marketplace_plugin not in resolved.parents:
        raise ValueError(f"destination escapes marketplace plugin copy: {_display(root, destination)}")


def _default_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _display(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
