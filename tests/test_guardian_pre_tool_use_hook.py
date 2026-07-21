from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from codex_preflight_guardian import pre_tool_use


def payload(cwd: Path) -> dict[str, Any]:
    return {
        "session_id": "session-1",
        "transcript_path": None,
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "model": "gpt-test",
        "turn_id": "turn-1",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_use_id": "tool-1",
        "tool_input": {"command": "echo guardian-spike"},
    }


def deny(reason_code: str) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason_code,
        }
    }


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        ("ALLOW", None),
        ("WARN", deny(pre_tool_use.REASON_WARN)),
        ("ASK_USER", deny(pre_tool_use.REASON_ASK_USER)),
        ("BLOCK", deny(pre_tool_use.REASON_BLOCK)),
    ],
)
def test_deterministic_decisions_map_to_silent_allow_or_supported_deny(
    tmp_path: Path,
    decision: str,
    expected: dict[str, object] | None,
) -> None:
    calls: list[tuple[Path, str, dict[str, object]]] = []

    def scanner(cwd: Path, command: str, **kwargs: object) -> dict[str, str]:
        calls.append((cwd, command, kwargs))
        return {"decision": decision}

    result = pre_tool_use.handle_payload(payload(tmp_path), scanner=scanner)

    assert result == expected
    assert calls == [
        (
            tmp_path,
            "echo guardian-spike",
            {"use_cache": False, "allow_trust": False},
        )
    ]


def test_main_returns_zero_with_no_output_for_allow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pre_tool_use, "run_preflight", lambda *_args, **_kwargs: {"decision": "ALLOW"})
    stdout = io.StringIO()

    exit_code = pre_tool_use.main(io.StringIO(json.dumps(payload(tmp_path))), stdout)

    assert exit_code == 0
    assert stdout.getvalue() == ""


def test_main_emits_exact_supported_deny_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pre_tool_use, "run_preflight", lambda *_args, **_kwargs: {"decision": "BLOCK"})
    stdout = io.StringIO()

    exit_code = pre_tool_use.main(io.StringIO(json.dumps(payload(tmp_path))), stdout)

    assert exit_code == 0
    assert json.loads(stdout.getvalue()) == deny(pre_tool_use.REASON_BLOCK)
    assert set(json.loads(stdout.getvalue())) == {"hookSpecificOutput"}


def test_synthetic_marker_denies_before_scanner_is_called(tmp_path: Path) -> None:
    (tmp_path / pre_tool_use.SYNTHETIC_MARKER).write_text("deny\n", encoding="utf-8")
    scanner_called = False

    def scanner(*_args: object, **_kwargs: object) -> dict[str, str]:
        nonlocal scanner_called
        scanner_called = True
        return {"decision": "ALLOW"}

    result = pre_tool_use.handle_payload(payload(tmp_path), scanner=scanner)

    assert result == deny(pre_tool_use.REASON_SYNTHETIC_FIXTURE)
    assert scanner_called is False


def test_scanner_failure_is_fixed_and_redacted(tmp_path: Path) -> None:
    def scanner(*_args: object, **_kwargs: object) -> dict[str, str]:
        raise RuntimeError("secret scanner detail")

    result = pre_tool_use.handle_payload(payload(tmp_path), scanner=scanner)

    assert result == deny(pre_tool_use.REASON_SCANNER_FAILURE)
    assert "secret scanner detail" not in json.dumps(result)


@pytest.mark.parametrize(
    "invalid_payload",
    [
        None,
        [],
        {},
        {"hook_event_name": "PostToolUse"},
        {"hook_event_name": "PreToolUse", "tool_name": "apply_patch"},
    ],
)
def test_malformed_envelopes_deny_without_scanning(tmp_path: Path, invalid_payload: object) -> None:
    scanner_called = False

    def scanner(*_args: object, **_kwargs: object) -> dict[str, str]:
        nonlocal scanner_called
        scanner_called = True
        return {"decision": "ALLOW"}

    result = pre_tool_use.handle_payload(invalid_payload, scanner=scanner)

    assert result == deny(pre_tool_use.REASON_INVALID_INPUT)
    assert scanner_called is False


def test_invalid_json_returns_fixed_deny_and_zero_exit() -> None:
    stdout = io.StringIO()

    exit_code = pre_tool_use.main(io.StringIO("not-json"), stdout)

    assert exit_code == 0
    assert json.loads(stdout.getvalue()) == deny(pre_tool_use.REASON_INVALID_INPUT)


def test_unknown_scanner_decision_fails_closed(tmp_path: Path) -> None:
    result = pre_tool_use.handle_payload(
        payload(tmp_path),
        scanner=lambda *_args, **_kwargs: {"decision": "UNKNOWN"},
    )

    assert result == deny(pre_tool_use.REASON_SCANNER_FAILURE)


def test_extra_input_fields_do_not_affect_or_enter_output(tmp_path: Path) -> None:
    hook_payload = payload(tmp_path)
    hook_payload["unsupported"] = "secret input"

    result = pre_tool_use.handle_payload(
        hook_payload,
        scanner=lambda *_args, **_kwargs: {"decision": "BLOCK"},
    )

    assert result == deny(pre_tool_use.REASON_BLOCK)
    assert "secret input" not in json.dumps(result)


def test_formal_handler_does_not_write_plugin_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin_data = tmp_path / "plugin-data"
    plugin_data.mkdir()
    monkeypatch.setenv("PLUGIN_DATA", str(plugin_data))

    result = pre_tool_use.handle_payload(
        payload(tmp_path),
        scanner=lambda *_args, **_kwargs: {"decision": "ALLOW"},
    )

    assert result is None
    assert list(plugin_data.iterdir()) == []


def test_installed_console_entry_point_emits_fixed_deny() -> None:
    executable = shutil.which("codex-preflight-hook")
    if executable is None:
        if os.environ.get("CI"):
            raise AssertionError("codex-preflight-hook is missing after package installation")
        pytest.skip("codex-preflight-hook is not installed in this local environment")

    result = subprocess.run(
        [executable],
        input="not-json",
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == deny(pre_tool_use.REASON_INVALID_INPUT)
