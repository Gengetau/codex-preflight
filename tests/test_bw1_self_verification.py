from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from codex_preflight_cli.main import app
from codex_preflight_guardian import self_verification as bw1

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def short_root() -> Path:
    path = ROOT / "test-tmp" / f"bw1-{uuid4().hex[:8]}"
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _completed(
    args: list[str], returncode: int, events: list[dict], stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    stdout = "".join(json.dumps(event) + "\n" for event in events)
    return subprocess.CompletedProcess(args, returncode, stdout, stderr)


def _stub_runner(*, fail_open: bool = False, unavailable: bool = False, exit_one: bool = False):
    def run(args, *, cwd, text, capture_output, check, timeout):
        assert text is True and capture_output is True and check is False and timeout > 0
        args = [str(item) for item in args]
        cwd = Path(cwd)
        if args[0] == "git":
            if any(
                part.startswith("codex-preflight-bw1-") or part == ".bw1-self-verification-temporary"
                for part in cwd.parts
            ):
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False, timeout=timeout)
        assert args[0] == "codex-stub"
        if args[1:] == ["--version"]:
            return subprocess.CompletedProcess(args, 0, "codex-cli 0.test\n", "")
        if unavailable:
            return _completed(args, 1, [{"type": "error", "message": "authentication required"}])
        if exit_one:
            return _completed(args, 1, [{"type": "turn.failed", "error": "hook exit code 1"}])
        prompt = args[-1]
        if "Hook capability probe" in prompt:
            command = prompt.split("Attempt exactly this one shell command and no other tool call: ", 1)[1].split(
                ". Do not replace", 1
            )[0]
            if bw1.ALLOW_SENTINEL in command:
                (cwd / bw1.ALLOW_SENTINEL).write_text(f"{bw1.ALLOW_PROBE}\n", encoding="utf-8")
            elif fail_open:
                (cwd / bw1.DENY_SENTINEL).write_text(f"{bw1.DENY_PROBE}\n", encoding="utf-8")
            return _completed(
                args,
                0,
                [
                    {"type": "thread.started", "thread_id": "stub"},
                    {
                        "type": "item.started",
                        "item": {"id": "command", "type": "command_execution", "command": command},
                    },
                    {"type": "turn.completed", "usage": {}},
                ],
            )
        if "Call the MCP tool preflight_check exactly once" in prompt:
            supplied_cwd = prompt.split("Use cwd equal to ", 1)[1].split(" and command equal to ", 1)[0]
            return _completed(
                args,
                0,
                [
                    {"type": "thread.started", "thread_id": "stub"},
                    {
                        "type": "item.completed",
                        "item": {
                            "id": "mcp",
                            "type": "mcp_tool_call",
                            "tool": "preflight_check",
                            "arguments": {
                                "cwd": supplied_cwd,
                                "command": bw1.PLANNED_COMMAND,
                                "format": "json",
                            },
                            "status": "completed",
                        },
                    },
                    {"type": "turn.completed", "usage": {}},
                ],
            )
        if "--output-schema" in args:
            context = json.loads(prompt.split("Guardian Context:\n", 1)[1])
            decision = context["deterministicDecision"]["decision"]
            explanation = {
                "schemaVersion": "guardian-explanation/v1",
                "sourceReportDigest": context["reportDigest"],
                "sourceCommandDigest": context["commandDigest"],
                "deterministicResult": {
                    "decision": decision,
                    "statement": f"Deterministic result: {decision}.",
                },
                "advisoryExplanation": {
                    "summary": "The referenced lifecycle finding determines the reported result.",
                    "evidenceReferences": [context["evidenceRefs"][0]["refId"]],
                    "uncertaintyReferences": [],
                    "reviewSteps": ["Inspect the referenced lifecycle entry as untrusted data."],
                },
            }
            Path(args[args.index("-o") + 1]).write_text(json.dumps(explanation), encoding="utf-8")
            return _completed(
                args,
                0,
                [
                    {"type": "thread.started", "thread_id": "stub"},
                    {"type": "item.completed", "item": {"id": "message", "type": "agent_message", "text": "{}"}},
                    {"type": "turn.completed", "usage": {}},
                ],
            )
        raise AssertionError(args)

    return run


def _make_repository(tmp_path: Path) -> Path:
    root = tmp_path / "bw1"
    root.mkdir()
    for source, destination in (
        (ROOT / ".mcp.json", root / ".mcp.json"),
        (ROOT / "hooks" / "hooks.json", root / "hooks" / "hooks.json"),
        (
            ROOT / "plugins" / "codex-preflight" / ".codex-plugin" / "plugin.json",
            root / "plugins" / "codex-preflight" / ".codex-plugin" / "plugin.json",
        ),
        (
            ROOT / "schemas" / "guardian-explanation-v1.schema.json",
            root / "schemas" / "guardian-explanation-v1.schema.json",
        ),
    ):
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    shutil.copytree(ROOT / bw1.CORPUS_CASE, root / bw1.CORPUS_CASE)
    subprocess.run(["git", "init", "--initial-branch=main"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "BW1 Test"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=root, check=True, capture_output=True)
    return root


async def _handshake() -> dict:
    return {"instructions": "static only", "tools": ["preflight_check", "corpus_scan"]}


def test_full_self_verification_passes_with_stub_codex_executable(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, evidence_dir, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(),
        now=datetime(2026, 7, 16, 1, 2, 3, 456789, tzinfo=UTC),
        temp_parent=root,
    )

    assert status == bw1.PASS, json.dumps(result, indent=2)
    assert result["fixtureCommandsExecuted"] == 0
    assert result["exitCode"] == 0
    assert evidence_dir.name == "20260716T010203.456789Z"
    assert (evidence_dir / "result.json").is_file()
    assert (evidence_dir / "summary.md").is_file()
    assert (evidence_dir / "host-deny.jsonl").is_file()
    assert (evidence_dir / "host-allow.jsonl").is_file()
    assert (evidence_dir / "mcp-codex.jsonl").is_file()
    assert (evidence_dir / "explanation-codex.jsonl").is_file()
    digests = json.loads((evidence_dir / "content-digests.json").read_text(encoding="utf-8"))
    assert "result.json" in digests


@pytest.mark.parametrize(
    ("runner", "expected"),
    [
        (_stub_runner(unavailable=True), bw1.UNSUPPORTED),
        (_stub_runner(fail_open=True), bw1.FAIL),
        (_stub_runner(exit_one=True), bw1.FAIL),
    ],
)
def test_self_verification_distinguishes_unsupported_fail_open_and_exit_one(
    short_root: Path, monkeypatch: pytest.MonkeyPatch, runner, expected: str
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=runner,
        temp_parent=root,
    )

    assert status == expected
    assert result["exitCode"] == bw1.EXIT_CODES[expected]


def test_missing_runtime_executable_is_unsupported(tmp_path: Path) -> None:
    def missing_runner(*_args, **_kwargs):
        raise FileNotFoundError("missing")

    phase = bw1._runtime_identity(tmp_path, "missing-codex", missing_runner)

    assert phase.status == bw1.UNSUPPORTED
    assert phase.details == {"reason": "required executable or file is unavailable"}


def test_windows_executable_resolution_skips_extensionless_npm_proxy(tmp_path: Path) -> None:
    (tmp_path / "codex").write_text("extensionless proxy", encoding="utf-8")
    shim = tmp_path / "codex.cmd"
    shim.write_text("@echo off\n", encoding="utf-8")

    resolved = bw1.resolve_windows_executable(
        "codex",
        platform_name="nt",
        path_value=str(tmp_path),
    )

    assert resolved == str(shim)


def test_non_windows_executable_resolution_is_unchanged() -> None:
    assert bw1.resolve_windows_executable("codex", platform_name="posix", path_value="ignored") == "codex"


def test_missing_mcp_context_preserves_unsupported_result(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)

    async def missing_handshake() -> dict:
        raise ModuleNotFoundError("mcp")

    monkeypatch.setattr(bw1, "_mcp_handshake", missing_handshake)
    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(),
        temp_parent=root,
    )

    assert status == bw1.UNSUPPORTED
    phases = {phase["name"]: phase for phase in result["phases"]}
    assert phases["mcpVerification"]["status"] == bw1.UNSUPPORTED
    assert phases["guardianContextAndExplain"]["status"] == bw1.UNSUPPORTED


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not-json\n",
        "[]\n",
        '{"type":7}\n',
        '{"type":"turn.completed"}\n{"type":',
    ],
)
def test_hostile_or_malformed_codex_jsonl_is_rejected(text: str) -> None:
    with pytest.raises(bw1.VerificationError):
        bw1.parse_codex_jsonl(text)


def test_codex_jsonl_accepts_complete_event_stream() -> None:
    events = bw1.parse_codex_jsonl(
        '{"type":"thread.started","thread_id":"x"}\n'
        '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}\n'
        '{"type":"turn.completed","usage":{}}\n'
    )

    assert [event["type"] for event in events] == ["thread.started", "item.completed", "turn.completed"]


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"continue": False},
        {"stopReason": "stop"},
        {"suppressOutput": True},
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": "PREFLIGHT_ASK",
            }
        },
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "PREFLIGHT_BLOCK",
                "updatedInput": {},
            }
        },
    ],
)
def test_hook_output_validator_rejects_unsupported_shapes(value: object) -> None:
    with pytest.raises(bw1.VerificationError):
        bw1.validate_hook_output(value, allow_silent=False)


def test_hook_output_validator_accepts_exact_deny_and_silent_allow() -> None:
    deny = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "PREFLIGHT_BLOCK",
        }
    }

    assert bw1.validate_hook_output(deny) == deny
    assert bw1.validate_hook_output(None) is None


@pytest.mark.parametrize(
    "inventory",
    [
        None,
        {},
        ["preflight_check"],
        ["preflight_check", "corpus_scan", "repair"],
        ["preflight_check", "preflight_check"],
        ["preflight_check", 7],
    ],
)
def test_hostile_mcp_tools_list_responses_are_rejected(inventory: object) -> None:
    with pytest.raises(bw1.VerificationError):
        bw1.validate_mcp_inventory(inventory)


def test_mcp_inventory_requires_exact_two_tools() -> None:
    assert bw1.validate_mcp_inventory(["corpus_scan", "preflight_check"]) == ["corpus_scan", "preflight_check"]


def test_exact_sentinel_presence_absence_windows_and_unicode_paths(tmp_path: Path) -> None:
    repository = tmp_path / "C drive 模拟" / "工作区"
    repository.mkdir(parents=True)
    (repository / bw1.ALLOW_SENTINEL).write_bytes(f"{bw1.ALLOW_PROBE}\r\n".encode())

    allow = bw1.validate_sentinel(
        repository,
        bw1.ALLOW_SENTINEL,
        expected_present=True,
        expected_text=f"{bw1.ALLOW_PROBE}\n",
    )
    deny = bw1.validate_sentinel(repository, bw1.DENY_SENTINEL, expected_present=False)

    assert allow["present"] is True
    assert allow["contentDigest"].startswith("sha256:")
    assert deny == {"name": bw1.DENY_SENTINEL, "present": False}


def test_sentinel_validator_rejects_wrong_contents_and_fail_open(tmp_path: Path) -> None:
    (tmp_path / bw1.ALLOW_SENTINEL).write_text("wrong\n", encoding="utf-8")
    (tmp_path / bw1.DENY_SENTINEL).write_text("executed\n", encoding="utf-8")

    with pytest.raises(bw1.VerificationError, match="contents"):
        bw1.validate_sentinel(
            tmp_path,
            bw1.ALLOW_SENTINEL,
            expected_present=True,
            expected_text=f"{bw1.ALLOW_PROBE}\n",
        )
    with pytest.raises(bw1.VerificationError, match="presence"):
        bw1.validate_sentinel(tmp_path, bw1.DENY_SENTINEL, expected_present=False)


def test_mcp_tool_call_validator_rejects_hostile_arguments(tmp_path: Path) -> None:
    corpus = tmp_path / "case"
    corpus.mkdir()
    hostile = {
        "type": "mcp_tool_call",
        "tool": "preflight_check",
        "arguments": {"cwd": str(corpus), "command": "npm install && payload", "format": "json"},
    }

    assert bw1._is_exact_preflight_call(hostile, corpus.resolve()) is False


def test_sanitizer_redacts_usernames_tokens_home_paths_and_private_values() -> None:
    value = bw1.sanitize_value(
        {
            "message": (
                r"C:\Users\alice\repo C:\\Users\\carol\\private "
                r"/home/bob/repo token=secret-value ghp_abcdefghijklmnopqrstuvwxyz"
            )
        }
    )
    serialized = json.dumps(value)

    assert "alice" not in serialized
    assert "bob" not in serialized
    assert "carol" not in serialized
    assert "secret-value" not in serialized
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in serialized


@pytest.mark.parametrize(
    ("status", "exit_code"),
    [(bw1.PASS, 0), (bw1.FAIL, 1), (bw1.UNSUPPORTED, 3)],
)
def test_cli_outputs_only_final_tristate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    exit_code: int,
) -> None:
    monkeypatch.setattr(
        bw1,
        "verify_bw1",
        lambda *_args, **_kwargs: (status, tmp_path / "evidence", {"result": status}),
    )

    result = CliRunner().invoke(app, ["guardian", "verify-bw1", "--root", str(tmp_path)])

    assert result.exit_code == exit_code
    assert result.stdout == f"{status}\n"
