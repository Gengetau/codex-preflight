from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path


def _runtime_id() -> str:
    platforms = {"win32": "windows", "linux": "linux", "darwin": "macos"}
    machines = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}
    platform_name = platforms.get(sys.platform)
    machine_name = machines.get(platform.machine().lower())
    if platform_name is None or machine_name is None:
        raise ValueError(f"unsupported build host: {sys.platform}/{platform.machine()}")
    return f"{platform_name}-{machine_name}"


def _source_commit(root: Path) -> str:
    configured = os.environ.get("GITHUB_SHA")
    if configured:
        return configured
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(root: Path, output_root: Path, requested_runtime_id: str) -> Path:
    actual_runtime_id = _runtime_id()
    if requested_runtime_id != actual_runtime_id:
        raise ValueError(
            f"requested runtime {requested_runtime_id} does not match build host {actual_runtime_id}"
        )

    plugin_manifest = json.loads((root / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    runtime_dir = output_root / requested_runtime_id
    work_dir = root / "build" / "plugin-runtime" / requested_runtime_id
    spec_dir = work_dir / "spec"
    shutil.rmtree(runtime_dir, ignore_errors=True)
    shutil.rmtree(work_dir, ignore_errors=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    spec_dir.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--console",
        "--clean",
        "--noconfirm",
        "--noupx",
        "--name",
        "codex-preflight-runtime",
        "--distpath",
        str(runtime_dir),
        "--workpath",
        str(work_dir / "work"),
        "--specpath",
        str(spec_dir),
        "--copy-metadata",
        "codex-preflight",
        "--collect-submodules",
        "codex_preflight_core",
        "--collect-submodules",
        "codex_preflight_guardian",
        "--collect-submodules",
        "codex_preflight_mcp",
        "--collect-all",
        "mcp",
        "--collect-all",
        "pydantic",
        "--add-data",
        f"{root / 'case_corpus'}{os.pathsep}case_corpus",
        str(root / "scripts" / "codex_preflight_runtime.py"),
    ]
    subprocess.run(command, cwd=root, check=True)

    executable_name = "codex-preflight-runtime.exe" if sys.platform == "win32" else "codex-preflight-runtime"
    executable = runtime_dir / executable_name
    if not executable.is_file():
        raise RuntimeError(f"PyInstaller did not produce {executable}")
    if sys.platform != "win32":
        executable.chmod(0o755)

    entry = {
        "runtimeId": requested_runtime_id,
        "pluginVersion": plugin_manifest["version"],
        "sourceCommit": _source_commit(root),
        "path": f"{requested_runtime_id}/{executable_name}",
        "sha256": _sha256(executable),
        "builder": f"pyinstaller-{version('pyinstaller')}",
    }
    entries_dir = output_root / "entries"
    entries_dir.mkdir(parents=True, exist_ok=True)
    entry_path = entries_dir / f"{requested_runtime_id}.json"
    entry_path.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return entry_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build one self-contained Codex Preflight plugin runtime.")
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-root", type=Path, default=Path("runtime"))
    args = parser.parse_args()

    root = args.root.resolve()
    output_root = args.output_root
    if not output_root.is_absolute():
        output_root = (root / output_root).resolve()
    try:
        entry = build(root, output_root, args.runtime_id)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"runtime build failed: {error}", file=sys.stderr)
        return 1
    print(entry)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
