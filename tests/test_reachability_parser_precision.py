from pathlib import Path

import pytest

from codex_preflight_core.preflight import run_preflight
from codex_preflight_core.reachability.command_parser import parse_reachable_command
from codex_preflight_core.report.markdown_renderer import render_markdown_report


def write_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def graph_files(report: dict) -> set[str]:
    return {node["file"] for node in report["executionGraph"]["nodes"] if node["file"]}


def finding_rules(report: dict) -> set[str]:
    return {finding["ruleId"] for finding in report["findings"]}


@pytest.mark.parametrize("command", ['bash -c "./scripts/install.sh"', 'sh -c "./scripts/install.sh"'])
def test_shell_c_reaches_inner_local_script(tmp_path: Path, command: str) -> None:
    write_file(tmp_path / "scripts" / "install.sh", "curl https://example.invalid/install.sh\n")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert "scripts/install.sh" in graph_files(report)
    assert "SHELL_DOWNLOAD_CAPABILITY" in finding_rules(report)
    assert report["decision"] == "ASK_USER"


@pytest.mark.parametrize("command", ["python -u scripts/setup.py", "python3 -u scripts/setup.py"])
def test_python_flags_reach_script_target(tmp_path: Path, command: str) -> None:
    write_file(tmp_path / "scripts" / "setup.py", "import subprocess\nsubprocess.run(['echo', 'static'])\n")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert "scripts/setup.py" in graph_files(report)
    assert "PYTHON_SUBPROCESS_EXEC" in finding_rules(report)


def test_python_module_form_reaches_module_file(tmp_path: Path) -> None:
    write_file(tmp_path / "tools" / "setup.py", "import requests\nrequests.get('https://example.invalid')\n")

    report = run_preflight(tmp_path, "python -m tools.setup", use_cache=False)

    assert "tools/setup.py" in graph_files(report)
    assert "PYTHON_NETWORK_ACCESS" in finding_rules(report)


def test_missing_python_module_form_reports_uncertainty(tmp_path: Path) -> None:
    report = run_preflight(tmp_path, "python -m tools.missing", use_cache=False)

    assert "SCRIPT_TARGET_MISSING" in finding_rules(report)
    assert report["decision"] == "ASK_USER"


@pytest.mark.parametrize(
    "command",
    [
        "python -X dev scripts/setup.py",
        "python -Xdev scripts/setup.py",
        "python -W ignore scripts/setup.py",
        "python -Wignore scripts/setup.py",
        "python3 -X dev scripts/setup.py",
        "python3 -W ignore scripts/setup.py",
    ],
)
def test_python_value_flags_continue_to_script_target(tmp_path: Path, command: str) -> None:
    write_file(tmp_path / "scripts" / "setup.py", "import subprocess\nsubprocess.run(['echo', 'static'])\n")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert "scripts/setup.py" in graph_files(report)
    assert "PYTHON_SUBPROCESS_EXEC" in finding_rules(report)


def test_python_inline_c_does_not_treat_following_args_as_script_target(tmp_path: Path) -> None:
    write_file(tmp_path / "scripts" / "setup.py", "import subprocess\nsubprocess.run(['echo', 'static'])\n")

    report = run_preflight(tmp_path, 'python -c "print(\'inline\')" scripts/setup.py', use_cache=False)

    assert "scripts/setup.py" not in graph_files(report)


def test_node_flags_reach_preload_and_main_script(tmp_path: Path) -> None:
    write_file(tmp_path / "preload.js", "const child_process = require('child_process'); child_process.exec('echo')\n")
    write_file(tmp_path / "tools" / "install.js", "fetch('https://example.invalid')\n")

    report = run_preflight(
        tmp_path,
        "node --require ./preload.js --trace-warnings tools/install.js",
        use_cache=False,
    )

    assert {"preload.js", "tools/install.js"} <= graph_files(report)
    assert {"JS_CHILD_PROCESS_EXEC", "JS_NETWORK_ACCESS"} <= finding_rules(report)


@pytest.mark.parametrize(
    "command",
    [
        "env NODE_ENV=production bash scripts/install.sh",
        "env -i PATH=/usr/bin python scripts/setup.py",
    ],
)
def test_env_wrapper_reaches_underlying_command(tmp_path: Path, command: str) -> None:
    write_file(tmp_path / "scripts" / "install.sh", "curl https://example.invalid/install.sh\n")
    write_file(tmp_path / "scripts" / "setup.py", "import os\nos.environ.get('NODE_ENV')\n")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert graph_files(report) & {"scripts/install.sh", "scripts/setup.py"}
    assert finding_rules(report) & {"SHELL_DOWNLOAD_CAPABILITY", "PYTHON_ENV_ACCESS"}


def test_npm_run_with_forwarded_args_reaches_package_script(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"build": "node tools/build.js"}}')
    write_file(
        tmp_path / "tools" / "build.js",
        "const child_process = require('child_process'); child_process.spawn('echo')\n",
    )

    report = run_preflight(tmp_path, "npm run build -- --flag", use_cache=False)

    assert "tools/build.js" in graph_files(report)
    assert "JS_CHILD_PROCESS_EXEC" in finding_rules(report)


@pytest.mark.parametrize("command", ["pnpm exec some-tool", "yarn dlx some-tool", "npx some-tool"])
def test_external_package_execution_reports_uncertainty(tmp_path: Path, command: str) -> None:
    report = run_preflight(tmp_path, command, use_cache=False)

    assert "SCRIPT_EXTERNAL_PACKAGE_EXECUTION" in finding_rules(report)
    assert report["decision"] == "ASK_USER"


def test_bun_run_reaches_package_script(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"build": "node tools/build.js"}}')
    write_file(tmp_path / "tools" / "build.js", "fetch('https://example.invalid')\n")

    report = run_preflight(tmp_path, "bun run build", use_cache=False)

    assert "tools/build.js" in graph_files(report)
    assert "JS_NETWORK_ACCESS" in finding_rules(report)


def test_deno_run_reaches_local_script(tmp_path: Path) -> None:
    write_file(tmp_path / "scripts" / "setup.ts", "fetch('https://example.invalid')\n")

    report = run_preflight(tmp_path, "deno run scripts/setup.ts", use_cache=False)

    assert "scripts/setup.ts" in graph_files(report)


@pytest.mark.parametrize("command", ["just setup", "task install"])
def test_task_runner_without_static_parser_reports_uncertainty(tmp_path: Path, command: str) -> None:
    write_file(tmp_path / "justfile", "setup:\n  bash scripts/install.sh\n")
    write_file(tmp_path / "Taskfile.yml", "tasks:\n  install:\n    cmds:\n      - bash scripts/install.sh\n")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert "SCRIPT_TASK_RUNNER_UNRESOLVED" in finding_rules(report)
    assert report["decision"] == "ASK_USER"


@pytest.mark.parametrize(
    "command",
    [
        r"powershell -File .\scripts\setup.ps1",
        r'powershell -Command ".\scripts\setup.ps1"',
        "pwsh -File ./scripts/setup.ps1",
    ],
)
def test_powershell_forms_reach_local_script(tmp_path: Path, command: str) -> None:
    write_file(tmp_path / "scripts" / "setup.ps1", "curl https://example.invalid\n")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert "scripts/setup.ps1" in graph_files(report)
    assert "SHELL_DOWNLOAD_CAPABILITY" in finding_rules(report)


@pytest.mark.parametrize(
    ("command", "normalized_path"),
    [
        (r"powershell -File C:\Users\me\setup.ps1", "C:/Users/me/setup.ps1"),
        (r'powershell -Command "C:\Users\me\setup.ps1"', "C:/Users/me/setup.ps1"),
        (r"cmd /c C:\Temp\setup.bat", "C:/Temp/setup.bat"),
    ],
)
def test_windows_drive_absolute_paths_are_outside_repo(
    tmp_path: Path,
    command: str,
    normalized_path: str,
) -> None:
    report = run_preflight(tmp_path, command, use_cache=False)

    assert "SCRIPT_TARGET_OUTSIDE_REPO" in finding_rules(report)
    assert "SCRIPT_TARGET_MISSING" not in finding_rules(report)
    assert normalized_path not in graph_files(report)
    assert report["decision"] == "ASK_USER"


@pytest.mark.parametrize(
    "command",
    [
        r"powershell -File C:\Users\me\setup.ps1",
        r'powershell -Command "C:\Users\me\setup.ps1"',
        r"cmd /c C:\Temp\setup.bat",
    ],
)
def test_parser_does_not_emit_windows_drive_paths_as_local_targets(command: str) -> None:
    parsed = parse_reachable_command(command)

    assert not parsed.local_paths
    assert [item.rule_id for item in parsed.uncertainties] == ["SCRIPT_TARGET_OUTSIDE_REPO"]


@pytest.mark.parametrize("command", [r"cmd /c scripts\setup.bat", r"cmd.exe /c scripts\setup.bat"])
def test_cmd_c_reaches_batch_script(tmp_path: Path, command: str) -> None:
    write_file(tmp_path / "scripts" / "setup.bat", "curl https://example.invalid\n")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert "scripts/setup.bat" in graph_files(report)
    assert "SHELL_DOWNLOAD_CAPABILITY" in finding_rules(report)


def test_cli_reports_shell_c_execution_chain_in_json(tmp_path: Path) -> None:
    write_file(tmp_path / "scripts" / "install.sh", "curl https://example.invalid/install.sh\n")

    report = run_preflight(tmp_path, 'bash -c "./scripts/install.sh"', use_cache=False)

    assert report["executionGraph"]["entryCommand"] == 'bash -c "./scripts/install.sh"'
    assert "scripts/install.sh" in graph_files(report)


def test_markdown_reports_env_wrapper_execution_chain(tmp_path: Path) -> None:
    write_file(tmp_path / "scripts" / "install.sh", "curl https://example.invalid/install.sh\n")

    report = run_preflight(tmp_path, "env NODE_ENV=production bash scripts/install.sh", use_cache=False)
    markdown = render_markdown_report(report)

    assert "## Execution Chain" in markdown
    assert "scripts/install.sh" in markdown
