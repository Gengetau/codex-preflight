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


def test_documented_tool_names_and_requests_match_runtime_schemas(monkeypatch) -> None:
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", raising=False)
    monkeypatch.delenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", raising=False)
    tools = tools_by_name()
    assert set(tools) == {"preflight_check", "corpus_scan"}

    for filename in ("preflight-check-request.json", "corpus-scan-request.json"):
        request = load_json(filename)
        assert request["tool"] in tools
        validate(instance=request["arguments"], schema=tools[request["tool"]]["inputSchema"])

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN", "1")
    enabled_tools = tools_by_name()
    assert set(enabled_tools) == {"preflight_check", "corpus_scan", "remote_repository_scan"}
    remote_request = load_json("remote-repository-scan-request.json")
    validate(
        instance=remote_request["arguments"],
        schema=enabled_tools[remote_request["tool"]]["inputSchema"],
    )

    monkeypatch.setenv("CODEX_PREFLIGHT_ENABLE_TRUST_READ", "1")
    combined_tools = tools_by_name()
    assert set(combined_tools) == {
        "preflight_check",
        "corpus_scan",
        "remote_repository_scan",
        "trust_list",
    }
    trust_request = load_json("trust-list-request.json")
    validate(
        instance=trust_request["arguments"],
        schema=combined_tools[trust_request["tool"]]["inputSchema"],
    )


def test_success_examples_match_stable_contracts(tmp_path: Path) -> None:
    preflight = load_json("preflight-check-response.json")
    corpus = load_json("corpus-scan-response.json")
    remote = load_json("remote-repository-scan-response.json")
    trust = load_json("trust-list-response.json")
    required_preflight = {
        "mcpSchemaVersion",
        "tool",
        "schemaVersion",
        "decision",
        "riskScore",
        "command",
        "commandScope",
        "policyExplanation",
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
    assert corpus["cases"][0]["negativeControl"] is False
    assert corpus["groups"][0]["category"] == "reachability"
    assert remote["mcpSchemaVersion"] == "1.0"
    assert remote["tool"] == "remote_repository_scan"
    assert remote["safety"]["networkAccess"] is True
    assert remote["safety"]["remoteRepositoryAccess"] is True
    assert remote["safety"]["trustMutationAllowed"] is False
    assert remote["remoteProvenance"]["cleanupStatus"] == "removed"
    assert remote["remoteProvenance"]["redirectsFollowed"] == 0
    assert remote["remoteProvenance"]["confirmationConsumed"] is True
    assert remote["repo"]["path"] == remote["remoteProvenance"]["canonicalUrl"]
    assert set(trust) == {
        "auditEventId",
        "entries",
        "mcpSchemaVersion",
        "pagination",
        "runtimeIdentity",
        "safety",
        "schemaVersion",
        "sourceType",
        "tool",
        "trustMutationAllowed",
        "trustReadOnly",
    }
    assert trust["tool"] == "trust_list"
    assert trust["schemaVersion"] == "trust-list/v1"
    assert trust["runtimeIdentity"]["identityStatus"] == "unavailable"
    assert trust["safety"]["rawRepoIdReturned"] is False
    assert trust["safety"]["approvedCommandReturned"] is False
    serialized_trust = json.dumps(trust)
    assert "C:/" not in serialized_trust
    assert "https://" not in serialized_trust

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

    remote = load_json("remote-confirmation-required.json")["error"]
    assert remote["code"] == McpErrorCode.REMOTE_CONFIRMATION_REQUIRED.value
    assert remote["field"] == "confirmationToken"
    assert remote["context"]["expiresInSeconds"] == 300
    assert remote["context"]["trustCreated"] is False


def test_python_examples_are_valid_and_call_only_documented_tools() -> None:
    sources = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(EXAMPLES.glob("*_client.py"))
    }

    assert set(sources) == {
        "corpus_scan_client.py",
        "preflight_check_client.py",
        "remote_repository_scan_client.py",
        "trust_list_client.py",
        "trust_mutation_client.py",
    }
    for filename, source in sources.items():
        ast.parse(source, filename=filename)
        assert "StdioServerParameters" in source
        assert "codex_preflight_mcp.server" in source
    assert re.search(r'call_tool\(\s*"preflight_check"', sources["preflight_check_client.py"])
    assert re.search(r'call_tool\(\s*"corpus_scan"', sources["corpus_scan_client.py"])
    remote = sources["remote_repository_scan_client.py"]
    assert re.search(r'call_tool\(\s*"remote_repository_scan"', remote)
    assert 'CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN": "1"' in remote
    assert "input(" in remote
    assert '!= "CONFIRM"' in remote
    assert "confirmationToken" in remote
    trust = sources["trust_list_client.py"]
    assert re.search(r'call_tool\(\s*"trust_list"', trust)
    assert 'CODEX_PREFLIGHT_ENABLE_TRUST_READ": "1"' in trust
    assert "trust_approve" not in trust
    assert "trust_revoke" not in trust
    mutation = sources["trust_mutation_client.py"]
    assert re.search(r'call_tool\(\s*"trust_approve"', mutation)
    assert 'CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION": "1"' in mutation
    assert "confirmationToken" in mutation
    assert "input(" in mutation
    assert '!= "CONFIRM"' in mutation
    assert "automatic confirmation" in mutation


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
        "MCP_REMOTE_CONFIRMATION_REQUIRED",
        "CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN",
        "CODEX_PREFLIGHT_ENABLE_TRUST_READ",
        "trust-list/v1",
        "Unavailable capabilities",
    ):
        assert required in text
    assert "Default inventory" in text
    assert "Remote-only inventory" in text
    assert "Trust-read-only inventory" in text
    assert "adds only `remote_repository_scan`" in text


def test_codex_plugin_docs_cover_supported_paths_and_explicit_prerequisite() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    plugin = (ROOT / "docs" / "plugin.md").read_text(encoding="utf-8")
    integration = (ROOT / "docs" / "mcp-client-examples.md").read_text(encoding="utf-8")
    combined = "\n".join((readme, plugin, integration))

    for required in (
        'python -m pip install "codex-preflight[mcp]"',
        'python -m pip install --upgrade "codex-preflight[mcp]"',
        "mcp>=1.3.0",
        "instruction-capable",
        "instruction-incompatible",
        "safety contract",
        "codex plugin marketplace add",
        "Plugin installation and Python package installation are separate",
        "Standalone Codex MCP configuration",
        "Source-checkout development",
        "ChatGPT desktop app, Codex CLI, and IDE extension share MCP configuration",
        "start a new Codex session",
        "codex-preflight mcp config --client codex",
        "codex-preflight mcp doctor --client codex",
        "does not install packages",
    ):
        assert required in combined

    assert "remote_repository_scan" in combined
    assert "trust-mutation MCP tools" in combined
    assert "trust_list" in combined
    assert "CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN" in combined
    assert "CODEX_PREFLIGHT_ENABLE_TRUST_READ" in combined
    assert "one-time" in combined
    assert "confirmation" in combined
    assert "default" in combined.lower()
    assert "one-click" not in combined.lower()


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
