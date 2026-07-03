import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / ".codex-plugin" / "plugin.json"
SKILL = ROOT / "skills" / "codex-preflight" / "SKILL.md"


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

    assert "mcpServers" not in manifest
    assert "apps" not in manifest
    assert "hooks" not in manifest
    assert not (ROOT / ".mcp.json").exists()
    assert not (ROOT / ".app.json").exists()


def test_plugin_files_have_no_placeholders_or_chinese_text() -> None:
    paths = [MANIFEST, SKILL, ROOT / "docs" / "plugin.md"]
    todo_marker = "TO" + "DO"
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert f"[{todo_marker}" not in text
        assert f"{todo_marker}:" not in text
        assert not any(ord(char) > 127 for char in text)
