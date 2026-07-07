import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_process_document_exists() -> None:
    path = ROOT / "docs" / "release-process.md"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "git tag -a" in text
    assert "-F /tmp/codex-preflight-release-notes.md" in text
    assert "Do not delete or recreate already-pushed tags" in text


def test_release_notes_template_exists() -> None:
    path = ROOT / "docs" / "templates" / "release-notes.md"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    for heading in (
        "Release theme",
        "Changed",
        "Safety / security impact",
        "Validation",
        "Compatibility",
        "Not included",
    ):
        assert heading in text


def test_stabilization_summary_exists() -> None:
    path = ROOT / "docs" / "0.1.x-stabilization.md"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "0.1.x" in text
    assert "Stable Interfaces" in text
    assert "Intentional Non-Inclusions" in text
    assert "Known Limitations" in text


def test_all_version_files_match_pyproject() -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    core_init = (ROOT / "codex_preflight_core" / "__init__.py").read_text(encoding="utf-8")
    mcp_init = (ROOT / "codex_preflight_mcp" / "__init__.py").read_text(encoding="utf-8")
    root_manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    marketplace_manifest = json.loads(
        (
            ROOT
            / ".agents"
            / "plugins"
            / "plugins"
            / "codex-preflight"
            / ".codex-plugin"
            / "plugin.json"
        ).read_text(encoding="utf-8")
    )

    assert f'__version__ = "{version}"' in core_init
    assert f'__version__ = "{version}"' in mcp_init
    assert root_manifest["version"] == version
    assert marketplace_manifest["version"] == version


def test_release_process_prefers_release_notes_over_rewriting_old_tags() -> None:
    text = (ROOT / "docs" / "release-process.md").read_text(encoding="utf-8")
    assert "Do not delete or recreate already-pushed tags" in text
    assert "GitHub Release notes" in text
