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
_REQUESTED_MODEL = "__requested_model__"


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


def _stub_runner(
    *,
    fail_open: bool = False,
    unavailable: bool = False,
    exit_one: bool = False,
    snapshot_warning: bool = False,
    no_command_attempt: bool = False,
    allow_denied: bool = False,
    missing_allow_completion: bool = False,
    allow_stdout: str = "true\n",
    fixture_attempt: bool = False,
    observed_model: str | None = _REQUESTED_MODEL,
    unsupported_models: tuple[str, ...] = (),
):
    def run(args, *, cwd, text, encoding, errors, capture_output, check, timeout):
        assert text is True and encoding == "utf-8" and errors == "replace"
        assert capture_output is True and check is False and timeout > 0
        args = [str(item) for item in args]
        cwd = Path(cwd)
        if args[0] == "git":
            return subprocess.run(
                args,
                cwd=cwd,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        assert args[0] == "codex-stub"
        if args[1:] == ["--version"]:
            return subprocess.CompletedProcess(args, 0, "codex-cli 0.test\n", "")
        if args[1:] == ["features", "list"]:
            return subprocess.CompletedProcess(
                args,
                0,
                "hooks stable true\nshell_snapshot stable true\n",
                "",
            )
        if args[1:] == ["exec", "--disable", "shell_snapshot", "--help"]:
            return subprocess.CompletedProcess(args, 0, "--disable <FEATURE>\n", "")
        assert args[1:4] == ["exec", "--disable", "shell_snapshot"]
        if unavailable:
            return _completed(
                args,
                1,
                [{"type": "error", "error": {"code": "shell_unavailable", "message": "shell unavailable"}}],
            )
        if exit_one:
            return _completed(
                args,
                1,
                [{"type": "turn.failed", "error": "hook exit code 1"}],
                "Failed to create shell snapshot for powershell: Shell snapshot not supported yet for PowerShell",
            )
        prompt = args[-1]
        if "Hook capability probe" in prompt:
            command = prompt.split("Attempt exactly this one shell command and no other tool call: ", 1)[1].split(
                ". Do not replace", 1
            )[0]
            warning = (
                "Failed to create shell snapshot for powershell: "
                "Shell snapshot not supported yet for PowerShell"
                if snapshot_warning
                else ""
            )
            if no_command_attempt:
                return _completed(
                    args,
                    0,
                    [
                        {"type": "thread.started", "thread_id": "stub"},
                        {"type": "turn.completed", "usage": {}},
                    ],
                    warning,
                )
            is_allow = command == bw1.ALLOW_COMMAND
            if is_allow and allow_denied:
                return _completed(
                    args,
                    0,
                    [
                        {"type": "thread.started", "thread_id": "stub"},
                        {
                            "type": "item.completed",
                            "item": {
                                "id": "message",
                                "type": "agent_message",
                                "text": "Command blocked by PreToolUse hook: `PREFLIGHT_WARN_REVIEW_REQUIRED`.",
                            },
                        },
                        {"type": "turn.completed", "usage": {}},
                    ],
                    warning,
                )
            if is_allow and missing_allow_completion:
                return _completed(
                    args,
                    0,
                    [
                        {"type": "thread.started", "thread_id": "stub"},
                        {
                            "type": "item.started",
                            "item": {
                                "id": "command",
                                "type": "command_execution",
                                "command": command,
                                "status": "in_progress",
                            },
                        },
                        {"type": "turn.completed", "usage": {}},
                    ],
                    warning,
                )
            if fail_open and not is_allow:
                (cwd / bw1.DENY_SENTINEL).write_text(f"{bw1.DENY_PROBE}\n", encoding="utf-8")
            if not is_allow and not fail_open:
                return _completed(
                    args,
                    0,
                    [
                        {"type": "thread.started", "thread_id": "stub"},
                        {
                            "type": "item.completed",
                            "item": {
                                "id": "message",
                                "type": "agent_message",
                                "text": "Command blocked by PreToolUse hook: `PREFLIGHT_SYNTHETIC_FIXTURE`.",
                            },
                        },
                        {"type": "turn.completed", "usage": {}},
                    ],
                    warning,
                )
            return _completed(
                args,
                0,
                [
                    {"type": "thread.started", "thread_id": "stub"},
                    {
                        "type": "item.started",
                        "item": {
                            "id": "command",
                            "type": "command_execution",
                            "command": command,
                            "status": "in_progress",
                        },
                    },
                    {
                        "type": "item.completed",
                        "item": {
                            "id": "command",
                            "type": "command_execution",
                            "command": command,
                            "status": "completed",
                            "exit_code": 0,
                            "aggregated_output": allow_stdout if is_allow else "",
                        },
                    },
                    {"type": "turn.completed", "usage": {}},
                ],
                warning,
            )
        if "Call the MCP tool preflight_check exactly once" in prompt:
            supplied_cwd = prompt.split("Use cwd equal to ", 1)[1].split(" and command equal to ", 1)[0]
            events = [
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
            ]
            if fixture_attempt:
                events.append(
                    {
                        "type": "item.started",
                        "item": {
                            "id": "fixture-command",
                            "type": "command_execution",
                            "command": bw1.PLANNED_COMMAND,
                        },
                    }
                )
            events.append({"type": "turn.completed", "usage": {}})
            return _completed(
                args,
                0,
                events,
            )
        if "--output-schema" in args:
            requested_model = args[args.index("--model") + 1]
            assert requested_model in bw1.GPT_5_6_CANDIDATES
            if requested_model in unsupported_models:
                return _completed(
                    args,
                    1,
                    [
                        {
                            "type": "turn.failed",
                            "error": {
                                "code": "model_not_found",
                                "message": f"The '{requested_model}' model is not supported",
                            },
                        }
                    ],
                )
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
            actual_model = requested_model if observed_model == _REQUESTED_MODEL else observed_model
            return _completed(
                args,
                0,
                [
                    {
                        "type": "thread.started",
                        "thread_id": "stub",
                        **({"model": actual_model} if actual_model is not None else {}),
                    },
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
    assert result["shellSnapshotOverride"]["status"] == "accepted"
    assert result["shellSnapshotOverride"]["hooksDisabled"] is False
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


def test_powershell_snapshot_warning_with_valid_deny_and_allow_evidence_passes(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(snapshot_warning=True),
        temp_parent=root,
    )

    assert status == bw1.PASS, json.dumps(result, indent=2)
    host = next(phase for phase in result["phases"] if phase["name"] == "realHostGate")
    assert host["details"]["deny"]["commandAttempted"] is True
    assert host["details"]["allow"]["commandAttempted"] is True
    assert host["details"]["deny"]["sentinel"]["valid"] is True
    assert host["details"]["allowPrerequisite"]["decision"] == "ALLOW"
    assert host["details"]["allow"]["commandStatus"] == "completed"
    assert host["details"]["allow"]["commandExitCode"] == 0
    assert host["details"]["allow"]["normalizedStdout"] == "true"
    assert host["details"]["allow"]["repositoryMutation"]["mutated"] is False


def test_deterministic_allow_prerequisite_rejects_non_allow_without_child_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    child_calls: list[list[str]] = []
    stub = _stub_runner()

    def recording_runner(args, **kwargs):
        normalized = [str(item) for item in args]
        if normalized[:2] == ["codex-stub", "exec"]:
            child_calls.append(normalized)
        return stub(args, **kwargs)

    monkeypatch.setattr(
        bw1,
        "run_preflight",
        lambda *_args, **_kwargs: {
            "decision": "WARN",
            "commandScope": "safe_readonly",
            "riskScore": 10,
        },
    )

    phase = bw1._real_host_gate(
        tmp_path,
        evidence,
        "codex-stub",
        recording_runner,
        ("--disable", "shell_snapshot"),
    )

    assert phase.status == bw1.FAIL
    assert phase.details["allowPrerequisite"]["decision"] == "WARN"
    assert phase.details["childSessionsLaunched"] is False
    assert child_calls == []


def test_allow_command_denied_is_fail(short_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(allow_denied=True),
        temp_parent=root,
    )

    assert status == bw1.FAIL
    host = next(phase for phase in result["phases"] if phase["name"] == "realHostGate")
    assert host["status"] == bw1.FAIL
    assert host["details"]["allow"]["hookDenied"] is True
    assert host["details"]["allow"]["hookBlockReason"] == "PREFLIGHT_WARN_REVIEW_REQUIRED"


def test_missing_allow_structured_completion_is_unsupported(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(missing_allow_completion=True),
        temp_parent=root,
    )

    assert status == bw1.UNSUPPORTED
    host = next(phase for phase in result["phases"] if phase["name"] == "realHostGate")
    assert host["status"] == bw1.UNSUPPORTED
    assert "did not prove completed" in host["details"]["allow"]["reason"]


def test_powershell_snapshot_warning_plus_hook_exit_one_fails(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(exit_one=True),
        temp_parent=root,
    )

    assert status == bw1.FAIL
    host = next(phase for phase in result["phases"] if phase["name"] == "realHostGate")
    assert host["status"] == bw1.FAIL
    assert host["details"]["deny"]["hookFailure"] is True


def test_powershell_snapshot_warning_plus_fail_open_sentinel_fails(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(fail_open=True, snapshot_warning=True),
        temp_parent=root,
    )

    assert status == bw1.FAIL
    host = next(phase for phase in result["phases"] if phase["name"] == "realHostGate")
    assert host["details"]["deny"]["sentinel"]["present"] is True
    assert host["details"]["deny"]["sentinel"]["valid"] is False


def test_explicit_unavailable_shell_without_command_attempt_is_unsupported(tmp_path: Path) -> None:
    events = [
        {
            "type": "turn.failed",
            "error": {"code": "shell_unavailable", "message": "shell tool unavailable"},
        }
    ]
    probe = {
        "returncode": 1,
        "events": events,
        "stderr": "",
        "hookFailure": False,
    }

    status, details = bw1._evaluate_host_probe(
        "deny",
        probe,
        tmp_path,
        bw1.DENY_SENTINEL,
        f"echo {bw1.DENY_PROBE} > {bw1.DENY_SENTINEL}",
        expected_present=False,
    )

    assert status == bw1.UNSUPPORTED
    assert details["commandAttempted"] is False


def test_snapshot_warning_only_without_command_attempt_fails(tmp_path: Path) -> None:
    events = [
        {"type": "thread.started", "thread_id": "stub"},
        {"type": "turn.completed", "usage": {}},
    ]
    warning = (
        "Failed to create shell snapshot for powershell: "
        "Shell snapshot not supported yet for PowerShell"
    )
    probe = {
        "returncode": 0,
        "events": events,
        "stderr": warning,
        "hookFailure": False,
    }

    status, details = bw1._evaluate_host_probe(
        "deny",
        probe,
        tmp_path,
        bw1.DENY_SENTINEL,
        f"echo {bw1.DENY_PROBE} > {bw1.DENY_SENTINEL}",
        expected_present=False,
    )

    assert status == bw1.FAIL
    assert "explicit fatal unavailable-tool event" in details["reason"]


def test_structured_hook_block_is_an_attempt_not_a_hook_process_failure(tmp_path: Path) -> None:
    events = [
        {
            "type": "item.completed",
            "item": {
                "id": "message",
                "type": "agent_message",
                "text": "Command blocked by PreToolUse hook: `PREFLIGHT_SYNTHETIC_FIXTURE`.",
            },
        },
        {"type": "turn.completed", "usage": {}},
    ]
    stderr = (
        "ERROR router: Command blocked by PreToolUse hook: PREFLIGHT_SYNTHETIC_FIXTURE\n"
        "WARN mcp: failed to initialize MCP client during shutdown"
    )
    probe = {
        "returncode": 0,
        "events": events,
        "stderr": stderr,
        "hookFailure": bw1._hook_failure(events, stderr),
    }

    status, details = bw1._evaluate_host_probe(
        "deny",
        probe,
        tmp_path,
        bw1.DENY_SENTINEL,
        f"echo {bw1.DENY_PROBE} > {bw1.DENY_SENTINEL}",
        expected_present=False,
    )

    assert probe["hookFailure"] is False
    assert status == bw1.PASS
    assert details["commandAttempted"] is True
    assert details["commandAttemptEvidence"] == "hook_block"


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


@pytest.mark.parametrize("observed_model", ["gpt-5.6-terra", "gpt-5.5"])
def test_guardian_explanation_explicit_model_mismatch_is_fail(
    short_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    observed_model: str,
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(observed_model=observed_model),
        temp_parent=root,
    )

    assert status == bw1.FAIL
    explain = next(phase for phase in result["phases"] if phase["name"] == "guardianContextAndExplain")
    assert explain["status"] == bw1.FAIL
    assert explain["details"]["requestedModel"] == "gpt-5.6-sol"
    assert explain["details"]["acceptedModelIdentifier"] is None
    assert explain["details"]["observedModel"] == observed_model


def test_guardian_explanation_all_gpt_5_6_candidates_unsupported(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(unsupported_models=bw1.GPT_5_6_CANDIDATES),
        temp_parent=root,
    )

    assert status == bw1.UNSUPPORTED
    explain = next(phase for phase in result["phases"] if phase["name"] == "guardianContextAndExplain")
    assert explain["details"]["requestedModel"] == "gpt-5.6"
    assert explain["details"]["acceptedModelIdentifier"] is None
    assert explain["details"]["observedModel"] is None
    assert len(explain["details"]["modelAttempts"]) == 2
    assert "all GPT-5.6 candidates are unsupported" in explain["details"]["reason"]


def test_guardian_explanation_accepts_gpt_5_6_sol_without_model_field(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(observed_model=None),
        temp_parent=root,
    )

    assert status == bw1.PASS
    explain = next(phase for phase in result["phases"] if phase["name"] == "guardianContextAndExplain")
    assert explain["details"]["requestedModel"] == "gpt-5.6-sol"
    assert explain["details"]["acceptedModelIdentifier"] == "gpt-5.6-sol"
    assert explain["details"]["observedModel"] is None
    assert explain["details"]["modelSelection"] == "accepted-unobserved"


def test_guardian_explanation_uses_second_candidate_only_after_sol_is_unsupported(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(unsupported_models=("gpt-5.6-sol",), observed_model=None),
        temp_parent=root,
    )

    assert status == bw1.PASS
    explain = next(phase for phase in result["phases"] if phase["name"] == "guardianContextAndExplain")
    assert explain["details"]["requestedModel"] == "gpt-5.6"
    assert explain["details"]["acceptedModelIdentifier"] == "gpt-5.6"
    assert [attempt["requestedModel"] for attempt in explain["details"]["modelAttempts"]] == [
        "gpt-5.6-sol",
        "gpt-5.6",
    ]


def test_fixture_command_attempt_is_derived_from_jsonl_and_fails_gate(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _make_repository(short_root)
    monkeypatch.setattr(bw1, "_mcp_handshake", _handshake)

    status, _evidence, result = bw1.verify_bw1(
        root,
        codex_executable="codex-stub",
        runner=_stub_runner(fixture_attempt=True),
        temp_parent=root,
    )

    assert status == bw1.FAIL
    assert result["fixtureCommandsExecuted"] == 1
    fixture = next(phase for phase in result["phases"] if phase["name"] == "fixtureCommandExecution")
    assert fixture["status"] == bw1.FAIL
    assert fixture["details"]["attempts"][0]["evidenceFile"] == "mcp-codex.jsonl"


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


def test_command_execution_lifecycle_is_counted_as_one_attempt() -> None:
    events = [
        {
            "type": "item.started",
            "item": {
                "id": "command-1",
                "type": "command_execution",
                "command": "echo probe",
                "status": "in_progress",
            },
        },
        {
            "type": "item.completed",
            "item": {
                "id": "command-1",
                "type": "command_execution",
                "command": "echo probe",
                "status": "completed",
                "exit_code": 0,
            },
        },
    ]

    attempts = bw1._command_attempts(events)

    assert attempts == [
        {
            "id": "command-1",
            "type": "command_execution",
            "command": "echo probe",
            "status": "completed",
            "exit_code": 0,
        }
    ]


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
    probe_name = "unicode-probe.txt"
    (repository / probe_name).write_bytes("UNICODE_PROBE\r\n".encode())

    present = bw1.validate_sentinel(
        repository,
        probe_name,
        expected_present=True,
        expected_text="UNICODE_PROBE\n",
    )
    deny = bw1.validate_sentinel(repository, bw1.DENY_SENTINEL, expected_present=False)

    assert present["present"] is True
    assert present["contentDigest"].startswith("sha256:")
    assert deny == {"name": bw1.DENY_SENTINEL, "present": False}


def test_sentinel_validator_rejects_wrong_contents_and_fail_open(tmp_path: Path) -> None:
    probe_name = "probe.txt"
    (tmp_path / probe_name).write_text("wrong\n", encoding="utf-8")
    (tmp_path / bw1.DENY_SENTINEL).write_text("executed\n", encoding="utf-8")

    with pytest.raises(bw1.VerificationError, match="contents"):
        bw1.validate_sentinel(
            tmp_path,
            probe_name,
            expected_present=True,
            expected_text="expected\n",
        )
    with pytest.raises(bw1.VerificationError, match="presence"):
        bw1.validate_sentinel(tmp_path, bw1.DENY_SENTINEL, expected_present=False)


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([bw1.PASS, bw1.PASS], bw1.PASS),
        ([bw1.PASS, bw1.UNSUPPORTED], bw1.UNSUPPORTED),
        ([bw1.UNSUPPORTED, bw1.FAIL], bw1.FAIL),
    ],
)
def test_phase_aggregation_prioritizes_fail_then_unsupported(statuses: list[str], expected: str) -> None:
    phases = [bw1.PhaseResult(f"phase-{index}", status, {}) for index, status in enumerate(statuses)]
    assert bw1._aggregate_status(phases) == expected


def test_mcp_tool_call_validator_rejects_hostile_arguments(tmp_path: Path) -> None:
    corpus = tmp_path / "case"
    corpus.mkdir()
    hostile = {
        "type": "mcp_tool_call",
        "tool": "preflight_check",
        "arguments": {"cwd": str(corpus), "command": "npm install && payload", "format": "json"},
    }

    assert bw1._is_exact_preflight_call(hostile, corpus.resolve()) is False


def test_mcp_tool_call_lifecycle_is_counted_once() -> None:
    arguments = {"cwd": "C:/fixture", "command": bw1.PLANNED_COMMAND, "format": "json"}
    events = [
        {
            "type": "item.started",
            "item": {
                "id": "mcp-1",
                "type": "mcp_tool_call",
                "tool": "preflight_check",
                "arguments": arguments,
                "status": "in_progress",
            },
        },
        {
            "type": "item.completed",
            "item": {
                "id": "mcp-1",
                "type": "mcp_tool_call",
                "tool": "preflight_check",
                "arguments": arguments,
                "status": "completed",
                "result": {"decision": "BLOCK"},
            },
        },
    ]

    calls = bw1._mcp_tool_calls(events)

    assert len(calls) == 1
    assert calls[0]["status"] == "completed"
    assert calls[0]["result"] == {"decision": "BLOCK"}


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
