from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from codex_preflight_core.preflight import run_preflight

SYNTHETIC_MARKER = "SYNTHETIC_FIXTURE_DO_NOT_EXECUTE"

REASON_INVALID_INPUT = "PREFLIGHT_INVALID_INPUT"
REASON_SCANNER_FAILURE = "PREFLIGHT_SCANNER_FAILURE"
REASON_SYNTHETIC_FIXTURE = "PREFLIGHT_SYNTHETIC_FIXTURE"
REASON_WARN = "PREFLIGHT_WARN_REVIEW_REQUIRED"
REASON_ASK_USER = "PREFLIGHT_ASK_USER"
REASON_BLOCK = "PREFLIGHT_BLOCK"

PERMISSION_MODES = {"default", "acceptEdits", "plan", "dontAsk", "bypassPermissions"}

Scanner = Callable[..., dict[str, Any]]
MarkerCheck = Callable[[str | bytes | os.PathLike[str] | os.PathLike[bytes]], bool]


@dataclass(frozen=True)
class BashHookInput:
    cwd: str
    command: str


def handle_payload(
    payload: object,
    *,
    scanner: Scanner | None = None,
    marker_exists: MarkerCheck = os.path.lexists,
) -> dict[str, object] | None:
    """Return a deny response, or None for the documented silent allow path."""
    parsed = _parse_bash_hook_input(payload)
    if parsed is None:
        return _deny(REASON_INVALID_INPUT)

    try:
        marker_path = Path(parsed.cwd) / SYNTHETIC_MARKER
        if marker_exists(marker_path):
            return _deny(REASON_SYNTHETIC_FIXTURE)

        active_scanner = scanner if scanner is not None else run_preflight
        report = active_scanner(
            Path(parsed.cwd),
            parsed.command,
            use_cache=False,
            allow_trust=False,
        )
    except Exception:
        return _deny(REASON_SCANNER_FAILURE)

    if not isinstance(report, dict):
        return _deny(REASON_SCANNER_FAILURE)

    decision = report.get("decision")
    if decision == "ALLOW":
        return None
    if decision == "WARN":
        return _deny(REASON_WARN)
    if decision == "ASK_USER":
        return _deny(REASON_ASK_USER)
    if decision == "BLOCK":
        return _deny(REASON_BLOCK)
    return _deny(REASON_SCANNER_FAILURE)


def main(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    input_stream = stdin if stdin is not None else sys.stdin
    output_stream = stdout if stdout is not None else sys.stdout

    try:
        payload = json.load(input_stream)
    except Exception:
        response = _deny(REASON_INVALID_INPUT)
    else:
        response = handle_payload(payload)

    if response is not None:
        json.dump(response, output_stream, ensure_ascii=True, separators=(",", ":"))
    return 0


def _parse_bash_hook_input(payload: object) -> BashHookInput | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("hook_event_name") != "PreToolUse":
        return None
    if payload.get("tool_name") != "Bash":
        return None

    for field in ("session_id", "turn_id", "cwd", "model", "tool_use_id"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            return None

    if payload.get("permission_mode") not in PERMISSION_MODES:
        return None
    if "transcript_path" not in payload:
        return None
    transcript_path = payload.get("transcript_path")
    if transcript_path is not None and not isinstance(transcript_path, str):
        return None

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None

    return BashHookInput(cwd=payload["cwd"], command=command)


def _deny(reason_code: str) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason_code,
        }
    }


if __name__ == "__main__":
    raise SystemExit(main())
