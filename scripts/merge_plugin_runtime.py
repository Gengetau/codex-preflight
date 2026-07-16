from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

SCHEMA_VERSION = "codex-preflight-runtime/v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def merge(artifact_root: Path, output_root: Path) -> Path:
    entry_paths = sorted(artifact_root.glob("**/entries/*.json"))
    if not entry_paths:
        raise ValueError("no runtime entry descriptors were found")

    parsed: list[dict[str, str]] = []
    for entry_path in entry_paths:
        entry = json.loads(entry_path.read_text(encoding="utf-8"))
        required = {"runtimeId", "pluginVersion", "sourceCommit", "path", "sha256"}
        if not required <= set(entry):
            raise ValueError(f"runtime entry is incomplete: {entry_path}")
        parsed.append(entry)

    plugin_versions = {entry["pluginVersion"] for entry in parsed}
    source_commits = {entry["sourceCommit"] for entry in parsed}
    runtime_ids = [entry["runtimeId"] for entry in parsed]
    if len(plugin_versions) != 1:
        raise ValueError("runtime entries do not share one plugin version")
    if len(source_commits) != 1:
        raise ValueError("runtime entries do not share one source commit")
    if len(runtime_ids) != len(set(runtime_ids)):
        raise ValueError("duplicate runtime id")

    shutil.rmtree(output_root, ignore_errors=True)
    output_root.mkdir(parents=True, exist_ok=True)
    runtimes: dict[str, dict[str, str]] = {}

    for entry_path, entry in zip(entry_paths, parsed, strict=True):
        artifact_runtime_root = entry_path.parent.parent
        source = (artifact_runtime_root / entry["path"]).resolve()
        if artifact_runtime_root.resolve() not in source.parents:
            raise ValueError(f"runtime entry escapes its artifact root: {entry_path}")
        if not source.is_file():
            raise ValueError(f"runtime executable is missing: {source}")
        if _sha256(source) != entry["sha256"]:
            raise ValueError(f"runtime digest mismatch: {source}")

        destination = output_root / entry["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        runtimes[entry["runtimeId"]] = {
            "path": entry["path"],
            "sha256": entry["sha256"],
        }

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "pluginVersion": next(iter(plugin_versions)),
        "sourceCommit": next(iter(source_commits)),
        "runtimes": dict(sorted(runtimes.items())),
    }
    manifest_path = output_root / "runtime-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge platform runtime artifacts into one plugin runtime tree.")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, default=Path("runtime"))
    args = parser.parse_args()

    try:
        manifest = merge(args.artifacts.resolve(), args.output_root.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"runtime merge failed: {error}", file=sys.stderr)
        return 1
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
