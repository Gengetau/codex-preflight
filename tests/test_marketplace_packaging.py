import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_ROOT = ROOT / ".agents" / "plugins"
MARKETPLACE = MARKETPLACE_ROOT / "marketplace.json"
ROOT_PLUGIN = ROOT
MARKETPLACE_PLUGIN = MARKETPLACE_ROOT / "plugins" / "codex-preflight"
SYNC_SCRIPT = ROOT / "scripts" / "sync_marketplace_plugin.py"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


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

    plugin_root = MARKETPLACE_ROOT / source_path.removeprefix("./")
    plugin_manifest = load_json(plugin_root / ".codex-plugin" / "plugin.json")

    assert plugin_root == MARKETPLACE_PLUGIN
    assert plugin_manifest["name"] == "codex-preflight"
    assert (plugin_root / "skills" / "codex-preflight" / "SKILL.md").is_file()


def test_marketplace_plugin_package_matches_root_plugin_package() -> None:
    assert (ROOT_PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8") == (
        MARKETPLACE_PLUGIN / ".codex-plugin" / "plugin.json"
    ).read_text(encoding="utf-8")
    assert (ROOT_PLUGIN / "skills" / "codex-preflight" / "SKILL.md").read_text(encoding="utf-8") == (
        MARKETPLACE_PLUGIN / "skills" / "codex-preflight" / "SKILL.md"
    ).read_text(encoding="utf-8")


def test_marketplace_plugin_copy_is_synced_by_helper() -> None:
    result = subprocess.run(
        [sys.executable, str(SYNC_SCRIPT), "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_marketplace_does_not_declare_fake_integrations_or_ssh_sources() -> None:
    marketplace = MARKETPLACE.read_text(encoding="utf-8")
    root_manifest = load_json(ROOT_PLUGIN / ".codex-plugin" / "plugin.json")
    marketplace_manifest = load_json(MARKETPLACE_PLUGIN / ".codex-plugin" / "plugin.json")

    assert "git@github.com" not in marketplace
    assert "ssh://" not in marketplace
    assert "https://github.com/Gengetau/codex-preflight" not in marketplace
    for manifest in (root_manifest, marketplace_manifest):
        assert "mcpServers" not in manifest
        assert "apps" not in manifest
        assert "hooks" not in manifest
    assert not (MARKETPLACE_PLUGIN / ".mcp.json").exists()
    assert not (MARKETPLACE_PLUGIN / ".app.json").exists()


def test_marketplace_files_have_no_placeholders_or_chinese_text() -> None:
    todo_marker = "TO" + "DO"
    paths = [
        MARKETPLACE,
        MARKETPLACE_PLUGIN / ".codex-plugin" / "plugin.json",
        MARKETPLACE_PLUGIN / "skills" / "codex-preflight" / "SKILL.md",
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert f"[{todo_marker}" not in text
        assert f"{todo_marker}:" not in text
        assert not any(ord(char) > 127 for char in text)
