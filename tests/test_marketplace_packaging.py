import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
ROOT_PLUGIN = ROOT
MARKETPLACE_PLUGIN = ROOT / "plugins" / "codex-preflight"
SYNC_SCRIPT = ROOT / "scripts" / "sync_marketplace_plugin.py"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _file_map(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(item for item in root.rglob("*") if item.is_file())
    }


def test_marketplace_manifest_exists_and_uses_supported_shape() -> None:
    assert MARKETPLACE.is_file()
    manifest = load_json(MARKETPLACE)

    assert manifest["name"] == "codex-preflight"
    assert manifest["interface"]["displayName"] == "Codex Preflight"
    assert isinstance(manifest["plugins"], list)
    assert len(manifest["plugins"]) == 1

    entry = manifest["plugins"][0]
    assert entry == {
        "name": "codex-preflight",
        "source": {
            "source": "local",
            "path": "./plugins/codex-preflight",
        },
        "policy": {
            "installation": "AVAILABLE",
            "authentication": "ON_INSTALL",
        },
        "category": "Productivity",
    }


def test_marketplace_entry_points_to_real_plugin_root() -> None:
    entry = load_json(MARKETPLACE)["plugins"][0]
    source_path = entry["source"]["path"]

    assert source_path.startswith("./")
    assert not source_path.startswith("../")

    plugin_root = ROOT / source_path.removeprefix("./")
    plugin_manifest = load_json(plugin_root / ".codex-plugin" / "plugin.json")

    assert plugin_root == MARKETPLACE_PLUGIN
    assert plugin_manifest["name"] == "codex-preflight"
    assert (plugin_root / "skills" / "codex-preflight" / "SKILL.md").is_file()
    assert (plugin_root / ".mcp.json").is_file()
    assert (plugin_root / "scripts" / "launch-mcp.mjs").is_file()
    assert (plugin_root / "scripts" / "launch-hook.mjs").is_file()
    assert (plugin_root / "scripts" / "runtime-launcher.mjs").is_file()
    assert (plugin_root / "runtime" / "runtime-manifest.json").is_file()


def test_marketplace_plugin_package_matches_root_plugin_package() -> None:
    assert (ROOT_PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8") == (
        MARKETPLACE_PLUGIN / ".codex-plugin" / "plugin.json"
    ).read_text(encoding="utf-8")
    assert (ROOT_PLUGIN / "skills" / "codex-preflight" / "SKILL.md").read_text(encoding="utf-8") == (
        MARKETPLACE_PLUGIN / "skills" / "codex-preflight" / "SKILL.md"
    ).read_text(encoding="utf-8")
    assert (ROOT_PLUGIN / ".mcp.json").read_bytes() == (MARKETPLACE_PLUGIN / ".mcp.json").read_bytes()
    assert (ROOT_PLUGIN / "hooks" / "hooks.json").read_bytes() == (
        MARKETPLACE_PLUGIN / "hooks" / "hooks.json"
    ).read_bytes()
    for name in ("launch-mcp.mjs", "launch-hook.mjs", "runtime-launcher.mjs"):
        assert (ROOT_PLUGIN / "scripts" / name).read_bytes() == (
            MARKETPLACE_PLUGIN / "scripts" / name
        ).read_bytes()
    assert _file_map(ROOT_PLUGIN / "runtime") == _file_map(MARKETPLACE_PLUGIN / "runtime")


def test_marketplace_plugin_copy_is_synced_by_helper() -> None:
    result = subprocess.run(
        [sys.executable, str(SYNC_SCRIPT), "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_marketplace_declares_only_the_real_local_mcp_integration() -> None:
    marketplace = MARKETPLACE.read_text(encoding="utf-8")
    root_manifest = load_json(ROOT_PLUGIN / ".codex-plugin" / "plugin.json")
    marketplace_manifest = load_json(MARKETPLACE_PLUGIN / ".codex-plugin" / "plugin.json")

    assert "git@github.com" not in marketplace
    assert "ssh://" not in marketplace
    assert "https://github.com/Gengetau/codex-preflight" not in marketplace
    for manifest in (root_manifest, marketplace_manifest):
        assert manifest["mcpServers"] == "./.mcp.json"
        assert "apps" not in manifest
        assert "hooks" not in manifest
    mcp_config = load_json(MARKETPLACE_PLUGIN / ".mcp.json")
    assert mcp_config == {
        "mcpServers": {
            "codex-preflight": {
                "command": "node",
                "args": ["./scripts/launch-mcp.mjs"],
                "cwd": ".",
            }
        }
    }
    serialized = json.dumps(mcp_config).lower()
    assert not any(token in serialized for token in ("http://", "https://", "bash", "powershell", "cmd /c", "token"))
    assert not (MARKETPLACE_PLUGIN / ".app.json").exists()


def test_legacy_nested_marketplace_plugin_copy_is_absent() -> None:
    legacy = ROOT / ".agents" / "plugins" / "plugins" / "codex-preflight"
    assert not any(path.is_file() for path in legacy.rglob("*"))


def test_marketplace_docs_cover_two_path_install_and_stale_snapshot_repair() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    plugin_docs = (ROOT / "docs" / "plugin.md").read_text(encoding="utf-8")

    for text in (readme, plugin_docs):
        assert "--sparse .agents/plugins" in text
        assert "--sparse plugins/codex-preflight" in text

    assert "path does not exist or is not a directory" in plugin_docs
    assert "codex plugin marketplace remove codex-preflight" in plugin_docs
    assert "codex plugin add codex-preflight@codex-preflight" in plugin_docs


def test_marketplace_files_have_no_placeholders_or_chinese_text() -> None:
    todo_marker = "TO" + "DO"
    paths = [
        MARKETPLACE,
        MARKETPLACE_PLUGIN / ".codex-plugin" / "plugin.json",
        MARKETPLACE_PLUGIN / ".mcp.json",
        MARKETPLACE_PLUGIN / "scripts" / "launch-mcp.mjs",
        MARKETPLACE_PLUGIN / "scripts" / "launch-hook.mjs",
        MARKETPLACE_PLUGIN / "scripts" / "runtime-launcher.mjs",
        MARKETPLACE_PLUGIN / "runtime" / "runtime-manifest.json",
        MARKETPLACE_PLUGIN / "skills" / "codex-preflight" / "SKILL.md",
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert f"[{todo_marker}" not in text
        assert f"{todo_marker}:" not in text
        assert not any(ord(char) > 127 for char in text)
