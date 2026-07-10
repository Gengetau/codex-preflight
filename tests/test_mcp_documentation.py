from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from jsonschema import validate

from codex_preflight_mcp.contract import MCP_SAFETY_METADATA
from codex_preflight_mcp.errors import McpErrorCode
from codex_preflight_mcp.server import corpus_scan, preflight_check, tool_definitions

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "mcp"
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def load_json(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def tools_by_name() -> dict[str, dict]:
    return {tool["name"]: tool for tool in tool_definitions()}


def test_documented_tool_names_and_requests_match_runtime_schemas() -> None:
    tools = tools_by_name()
    assert set(tools) == {"preflight_check", "corpus_scan"}

    for filename in ("preflight-check-request.json", "corpus-scan-request.json"):
        request = load_json(filename)
        assert request["tool"] in tools
        validate(instance=request["arguments"], schema=tools[request["tool"]]["inputSchema"])


def test_success_examples_match_stable_contracts(tmp_path: Path) -> None:
    preflight = load_json("preflight-check-response.json")
    corpus = load_json("corpus-scan-response.json")
    required_preflight = {
        "mcpSchemaVersion",
        "tool",
        "schemaVersion",
        "decision",
        "riskScore",
        "command",
        "commandScope",
        "repo",
        "summary",
        "reason",
        "agentInstruction",
        "findings",
        "executionGraph",
        "reportLimits",
        "cache",
        "safety",
    }

    assert required_preflight <= preflight.keys()
    assert preflight["mcpSchemaVersion"] == "1.0"
    assert preflight["tool"] == "preflight_check"
    assert preflight["safety"] == MCP_SAFETY_METADATA
    assert corpus["mcpSchemaVersion"] == "1.0"
    assert corpus["tool"] == "corpus_scan"
    assert corpus["safety"] == MCP_SAFETY_METADATA
    assert corpus["cases"][0]["passed"] is True

    actual_preflight = preflight_check(cwd=str(tmp_path), command="python -m pytest")
    actual_preflight["repo"] = preflight["repo"]
    assert actual_preflight == preflight
    assert corpus_scan(case_id="nested-node-child-process") == corpus


def test_error_example_uses_stable_v023_error_contract() -> None:
    example = load_json("cwd-url-error.json")
    detail = example["error"]

    assert example["isError"] is True
    assert detail["code"] == McpErrorCode.CWD_URL_NOT_ALLOWED.value
    assert set(detail) == {"code", "message", "remediation", "retryable", "field", "safetyBoundary"}
    assert detail["field"] == "cwd"
    assert detail["safetyBoundary"]


def test_python_examples_are_valid_and_call_only_documented_tools() -> None:
    sources = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(EXAMPLES.glob("*_client.py"))
    }

    assert set(sources) == {"corpus_scan_client.py", "preflight_check_client.py"}
    for filename, source in sources.items():
        ast.parse(source, filename=filename)
        assert "StdioServerParameters" in source
        assert "codex_preflight_mcp.server" in source
        assert "remote_repository_scan" not in source
        assert "trust_approve" not in source
        assert "trust_revoke" not in source
    assert re.search(r'call_tool\(\s*"preflight_check"', sources["preflight_check_client.py"])
    assert re.search(r'call_tool\(\s*"corpus_scan"', sources["corpus_scan_client.py"])


def test_generic_configuration_has_no_shell_wrapper_or_secrets() -> None:
    config = load_json("client-config.json")["mcpServers"]["codex-preflight"]
    serialized = json.dumps(config).lower()

    assert config == {"command": "codex-preflight-mcp", "args": []}
    assert not any(token in serialized for token in ("token", "secret", "api_key", "powershell", "bash -c"))


def test_integration_docs_cover_install_startup_boundaries_and_examples() -> None:
    text = (ROOT / "docs" / "mcp-client-examples.md").read_text(encoding="utf-8")

    for required in (
        'python -m pip install "codex-preflight[mcp]"',
        'python -m pip install -e ".[mcp]"',
        'python -m pip install -e ".[dev,mcp]"',
        "codex-preflight-mcp --list-tools",
        "stdio transport",
        "preflight_check",
        "corpus_scan",
        "evidenceTrust",
        "treat-as-data",
        "local-path",
        "Unavailable capabilities",
    ):
        assert required in text
    assert "not provide remote repository MCP scanning" in text
    assert "Only `preflight_check` and `corpus_scan` are available" in text


def test_internal_markdown_links_resolve() -> None:
    markdown_files = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    broken: list[str] = []
    for markdown in markdown_files:
        for target in MARKDOWN_LINK.findall(markdown.read_text(encoding="utf-8")):
            target = target.strip().split(maxsplit=1)[0]
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_text = target.split("#", 1)[0]
            if not path_text:
                continue
            resolved = (markdown.parent / path_text).resolve()
            if not resolved.exists():
                broken.append(f"{markdown.relative_to(ROOT).as_posix()} -> {target}")
    assert not broken, "Broken internal Markdown links:\n" + "\n".join(broken)


def test_marketplace_and_version_references_are_consistent() -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    release_history = (ROOT / "docs" / "release-history.md").read_text(encoding="utf-8")
    marketplace_check = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sync_marketplace_plugin.py"), "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert release_history.startswith(f"# Release History\n\n## v{version}")
    assert marketplace_check.returncode == 0, marketplace_check.stdout + marketplace_check.stderr
