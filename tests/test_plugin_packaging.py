import hashlib
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
HOOK_LAUNCHER = ROOT / "scripts" / "launch-hook.mjs"
RUNTIME_LAUNCHER = ROOT / "scripts" / "runtime-launcher.mjs"
RUNTIME_ROOT = ROOT / "runtime"
RUNTIME_MANIFEST = RUNTIME_ROOT / "runtime-manifest.json"


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    assert HOOK_LAUNCHER.is_file()
    assert RUNTIME_LAUNCHER.is_file()
    assert RUNTIME_MANIFEST.is_file()
    assert not (ROOT / ".app.json").exists()


def test_runtime_manifest_is_version_bound_and_digest_checked() -> None:
    plugin = load_manifest()
    runtime = json.loads(RUNTIME_MANIFEST.read_text(encoding="utf-8"))

    assert runtime["schemaVersion"] == "codex-preflight-runtime/v1"
    assert runtime["pluginVersion"] == plugin["version"]
    assert isinstance(runtime["runtimes"], dict)
    for runtime_id, entry in runtime["runtimes"].items():
        assert runtime_id in {"windows-x64", "linux-x64", "macos-x64", "macos-arm64"}
        assert set(entry) == {"path", "sha256"}
        executable = (RUNTIME_ROOT / entry["path"]).resolve()
        assert RUNTIME_ROOT.resolve() in executable.parents
        assert executable.is_file()
        assert entry["sha256"] == _sha256(executable)


def test_mcp_launcher_supports_explicit_development_runtime() -> None:
    node = shutil.which("node")
    if node is None:
        return

    env = os.environ.copy()
    env["CODEX_PREFLIGHT_ALLOW_DEV_RUNTIME"] = "1"
    env["CODEX_PREFLIGHT_DEV_PYTHON"] = sys.executable
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


def test_launcher_has_no_implicit_user_python_fallback() -> None:
    text = RUNTIME_LAUNCHER.read_text(encoding="utf-8")

    assert "CODEX_PREFLIGHT_PYTHON" not in text
    assert "CODEX_PREFLIGHT_ALLOW_DEV_RUNTIME" in text
    assert "CODEX_PREFLIGHT_DEV_PYTHON" in text
    assert "runtime-manifest.json" in text
    assert "sha256" in text


def test_default_plugin_hook_uses_plugin_root_runtime_launcher() -> None:
    hooks = json.loads(HOOK_CONFIG.read_text(encoding="utf-8"))
    groups = hooks["hooks"]["PreToolUse"]

    assert len(groups) == 1
    assert groups[0]["matcher"] == "^Bash$"
    assert groups[0]["hooks"] == [
        {
            "type": "command",
            "command": 'node "$PLUGIN_ROOT/scripts/launch-hook.mjs"',
            "commandWindows": 'node "%PLUGIN_ROOT%\\scripts\\launch-hook.mjs"',
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
    paths = [
        MANIFEST,
        MCP_CONFIG,
        HOOK_CONFIG,
        MCP_LAUNCHER,
        HOOK_LAUNCHER,
        RUNTIME_LAUNCHER,
        RUNTIME_MANIFEST,
        SKILL,
        ROOT / "docs" / "plugin.md",
    ]
    todo_marker = "TO" + "DO"
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert f"[{todo_marker}" not in text
        assert f"{todo_marker}:" not in text
        assert not any(ord(char) > 127 for char in text)
