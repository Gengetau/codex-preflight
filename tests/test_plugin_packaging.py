import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / ".codex-plugin" / "plugin.json"
SKILL = ROOT / "skills" / "codex-preflight" / "SKILL.md"
MCP_CONFIG = ROOT / ".mcp.json"
HOOK_CONFIG = ROOT / "hooks" / "hooks.json"
MCP_LAUNCHER = ROOT / "scripts" / "launch-mcp.mjs"


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_plugin_manifest_exists_and_has_required_fields() -> None:
    assert MANIFEST.is_file()
    manifest = load_manifest()

    for field in ("name", "version", "description", "author", "interface"):
        assert field in manifest
    assert manifest["name"] == "codex-preflight"
    assert manifest["author"]["name"] == "Gengetau"
    assert manifest["skills"] == "./skills/"
    assert manifest["mcpServers"] == "./.mcp.json"


def test_plugin_manifest_version_matches_python_package() -> None:
    manifest = load_manifest()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    core_init = (ROOT / "codex_preflight_core" / "__init__.py").read_text(encoding="utf-8")

    assert manifest["version"] == pyproject["project"]["version"]
    assert f'__version__ = "{manifest["version"]}"' in core_init


def test_declared_skill_exists_and_contains_operational_guidance() -> None:
    assert SKILL.is_file()
    text = SKILL.read_text(encoding="utf-8")

    assert "codex-preflight preflight" in text
    for decision in ("ALLOW", "WARN", "ASK_USER", "BLOCK"):
        assert decision in text
    assert len(text.strip()) > 500


def test_manifest_declares_only_real_components() -> None:
    manifest = load_manifest()

    assert manifest["mcpServers"] == "./.mcp.json"
    assert "apps" not in manifest
    assert "hooks" not in manifest
    assert json.loads(MCP_CONFIG.read_text(encoding="utf-8")) == {
        "mcpServers": {
            "codex-preflight": {
                "command": "node",
                "args": ["./scripts/launch-mcp.mjs"],
                "cwd": ".",
            }
        }
    }
    assert MCP_LAUNCHER.is_file()
    assert not (ROOT / ".app.json").exists()


def test_mcp_launcher_uses_explicit_python_environment() -> None:
    node = shutil.which("node")
    if node is None:
        return

    env = os.environ.copy()
    env["CODEX_PREFLIGHT_PYTHON"] = sys.executable
    result = subprocess.run(
        [node, str(MCP_LAUNCHER), "--list-tools"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert '"preflight_check"' in result.stdout
    assert '"corpus_scan"' in result.stdout


def test_mcp_launcher_fails_closed_for_invalid_explicit_python(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        return

    env = os.environ.copy()
    env["CODEX_PREFLIGHT_PYTHON"] = str(tmp_path / "missing-python")
    result = subprocess.run(
        [node, str(MCP_LAUNCHER), "--list-tools"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "could not find Python with codex-preflight[mcp]==" in result.stderr


def test_default_plugin_hook_uses_bounded_supported_command_shape() -> None:
    hooks = json.loads(HOOK_CONFIG.read_text(encoding="utf-8"))
    groups = hooks["hooks"]["PreToolUse"]

    assert len(groups) == 1
    assert groups[0]["matcher"] == "^Bash$"
    assert groups[0]["hooks"] == [
        {
            "type": "command",
            "command": "codex-preflight-hook",
            "commandWindows": "codex-preflight-hook.exe",
            "timeout": 30,
            "statusMessage": "Running Codex Preflight",
        }
    ]


def test_hook_console_entry_point_is_packaged() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["scripts"]["codex-preflight-hook"] == (
        "codex_preflight_guardian.pre_tool_use:main"
    )
    assert "codex_preflight_guardian*" in pyproject["tool"]["setuptools"]["packages"]["find"]["include"]


def test_manifest_has_marketplace_ready_presentation_metadata() -> None:
    manifest = load_manifest()
    interface = manifest["interface"]

    assert manifest["homepage"].startswith("https://github.com/Gengetau/codex-preflight")
    assert manifest["repository"] == "https://github.com/Gengetau/codex-preflight"
    assert "command-safety" in manifest["keywords"]
    assert interface["displayName"] == "Codex Preflight"
    assert interface["category"] == "Productivity"
    assert interface["brandColor"].startswith("#")
    assert interface["websiteURL"] == "https://github.com/Gengetau/codex-preflight"
    assert len(interface["defaultPrompt"]) <= 3
    assert all(0 < len(prompt) <= 128 for prompt in interface["defaultPrompt"])
    assert {"Static analysis", "Local-first", "Command gating"} <= set(interface["capabilities"])


def test_plugin_files_have_no_placeholders_or_chinese_text() -> None:
    paths = [MANIFEST, MCP_CONFIG, HOOK_CONFIG, SKILL, ROOT / "docs" / "plugin.md"]
    todo_marker = "TO" + "DO"
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert f"[{todo_marker}" not in text
        assert f"{todo_marker}:" not in text
        assert not any(ord(char) > 127 for char in text)
