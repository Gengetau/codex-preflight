from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

import yaml

from codex_preflight_core.preflight import run_preflight
from codex_preflight_core.repo.temp_clone import RepoCloneError

CloneFactory = Callable[..., AbstractContextManager[Path]]
ResolveCommit = Callable[[Path], str | None]


def scan_batch(
    config_path: Path,
    clone_repo: CloneFactory,
    resolve_commit: ResolveCommit,
) -> dict[str, Any]:
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    entries = list(data if isinstance(data, list) else data.get("repos", []))
    results = [_scan_entry(entry, clone_repo, resolve_commit) for entry in entries]
    return {
        "passed": all(result["passed"] for result in results),
        "results": results,
    }


def render_batch_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Codex Preflight Batch Scan",
        "",
        "| Name | Decision | Expected | Result | Ref | Resolved commit |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in result["results"]:
        expected = item["expected"] or ""
        status = "pass" if item["passed"] else "fail"
        lines.append(
            f"| {item['name']} | {item['decision']} | {expected} | {status} | "
            f"{item['ref'] or ''} | {item['resolvedCommit'] or ''} |"
        )
    return "\n".join(lines) + "\n"


def _scan_entry(
    entry: dict[str, Any],
    clone_repo: CloneFactory,
    resolve_commit: ResolveCommit,
) -> dict[str, Any]:
    name = str(entry["name"])
    url = str(entry["url"])
    ref = entry.get("ref")
    command = str(entry["command"])
    expected = entry.get("expected")
    try:
        with clone_repo(url, ref=ref, depth=1, keep_temp=False, temp_dir=None) as cloned:
            resolved_commit = resolve_commit(cloned)
            report = run_preflight(
                cloned,
                command,
                use_cache=False,
                allow_trust=False,
                source_metadata={
                    "sourceType": "github",
                    "cloneUrl": url,
                    "requestedRef": ref,
                    "resolvedCommit": resolved_commit,
                },
            )
        decision = report["decision"]
        passed = expected is None or decision == expected
        error = None
    except RepoCloneError as exc:
        resolved_commit = None
        decision = "ERROR"
        passed = False
        error = str(exc)
    return {
        "name": name,
        "url": url,
        "ref": ref,
        "command": command,
        "expected": expected,
        "decision": decision,
        "resolvedCommit": resolved_commit,
        "passed": passed,
        "error": error,
    }
