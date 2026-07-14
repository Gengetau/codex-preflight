import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sync_marketplace_plugin.py"


def test_sync_script_exists() -> None:
    assert SCRIPT.is_file()


def test_check_mode_passes_when_copy_is_fresh(tmp_path: Path) -> None:
    layout = _make_layout(tmp_path)
    before = _snapshot(layout)

    result = _run_sync(layout, "--check")

    assert result.returncode == 0
    assert "up to date" in result.stdout
    assert _snapshot(layout) == before


def test_check_mode_fails_when_manifest_copy_is_stale(tmp_path: Path) -> None:
    layout = _make_layout(tmp_path)
    _marketplace_manifest(layout).write_text('{"name": "stale"}\n', encoding="utf-8")

    result = _run_sync(layout, "--check")

    assert result.returncode == 1
    assert "stale:" in result.stdout
    assert ".codex-plugin" in result.stdout


def test_check_mode_fails_when_mcp_copy_is_stale(tmp_path: Path) -> None:
    layout = _make_layout(tmp_path)
    _marketplace_mcp(layout).write_text('{"codex-preflight": {"command": "stale"}}\n', encoding="utf-8")

    result = _run_sync(layout, "--check")

    assert result.returncode == 1
    assert "stale:" in result.stdout
    assert ".mcp.json" in result.stdout


def test_check_mode_fails_when_hook_copy_is_stale(tmp_path: Path) -> None:
    layout = _make_layout(tmp_path)
    _marketplace_hook(layout).write_text('{"hooks": {}}\n', encoding="utf-8")

    result = _run_sync(layout, "--check")

    assert result.returncode == 1
    assert "stale:" in result.stdout
    assert "hooks/hooks.json" in result.stdout.replace("\\", "/")


def test_normal_mode_updates_stale_copy(tmp_path: Path) -> None:
    layout = _make_layout(tmp_path)
    _marketplace_manifest(layout).write_text('{"name": "stale"}\n', encoding="utf-8")
    _marketplace_mcp(layout).write_text('{"codex-preflight": {"command": "stale"}}\n', encoding="utf-8")
    _marketplace_skill(layout).write_text("stale skill\n", encoding="utf-8")
    _marketplace_hook(layout).write_text('{"hooks": {}}\n', encoding="utf-8")

    result = _run_sync(layout)

    assert result.returncode == 0
    assert "synced:" in result.stdout
    assert _marketplace_manifest(layout).read_text(encoding="utf-8") == _root_manifest(layout).read_text(
        encoding="utf-8"
    )
    assert _marketplace_skill(layout).read_text(encoding="utf-8") == _root_skill(layout).read_text(encoding="utf-8")
    assert _marketplace_mcp(layout).read_bytes() == _root_mcp(layout).read_bytes()
    assert _marketplace_hook(layout).read_bytes() == _root_hook(layout).read_bytes()


def test_only_intended_files_are_copied(tmp_path: Path) -> None:
    layout = _make_layout(tmp_path)
    marketplace_before = (layout / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8")
    (layout / ".codex-plugin" / "extra.json").write_text("{}", encoding="utf-8")
    (layout / "skills" / "other").mkdir(parents=True)
    (layout / "skills" / "other" / "SKILL.md").write_text("other skill", encoding="utf-8")

    result = _run_sync(layout)

    assert result.returncode == 0
    assert (layout / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8") == marketplace_before
    assert _marketplace_mcp(layout).read_bytes() == _root_mcp(layout).read_bytes()
    assert _marketplace_hook(layout).read_bytes() == _root_hook(layout).read_bytes()
    assert not (layout / ".agents" / "plugins" / "plugins" / "codex-preflight" / ".app.json").exists()
    assert not (
        layout / ".agents" / "plugins" / "plugins" / "codex-preflight" / ".codex-plugin" / "extra.json"
    ).exists()
    assert not (
        layout / ".agents" / "plugins" / "plugins" / "codex-preflight" / "skills" / "other" / "SKILL.md"
    ).exists()


def _run_sync(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _make_layout(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _copy_text(ROOT / ".codex-plugin" / "plugin.json", _root_manifest(root))
    _copy_text(ROOT / ".mcp.json", _root_mcp(root))
    _copy_text(ROOT / "skills" / "codex-preflight" / "SKILL.md", _root_skill(root))
    _copy_text(ROOT / "hooks" / "hooks.json", _root_hook(root))
    _copy_text(ROOT / ".agents" / "plugins" / "marketplace.json", root / ".agents" / "plugins" / "marketplace.json")
    _copy_text(ROOT / ".codex-plugin" / "plugin.json", _marketplace_manifest(root))
    _copy_text(ROOT / ".mcp.json", _marketplace_mcp(root))
    _copy_text(ROOT / "skills" / "codex-preflight" / "SKILL.md", _marketplace_skill(root))
    _copy_text(ROOT / "hooks" / "hooks.json", _marketplace_hook(root))
    return root


def _copy_text(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")


def _snapshot(root: Path) -> dict[str, str]:
    return {
        "manifest": _marketplace_manifest(root).read_text(encoding="utf-8"),
        "mcp": _marketplace_mcp(root).read_text(encoding="utf-8"),
        "skill": _marketplace_skill(root).read_text(encoding="utf-8"),
        "hook": _marketplace_hook(root).read_text(encoding="utf-8"),
        "marketplace": (root / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8"),
    }


def _root_manifest(root: Path) -> Path:
    return root / ".codex-plugin" / "plugin.json"


def _root_skill(root: Path) -> Path:
    return root / "skills" / "codex-preflight" / "SKILL.md"


def _root_mcp(root: Path) -> Path:
    return root / ".mcp.json"


def _root_hook(root: Path) -> Path:
    return root / "hooks" / "hooks.json"


def _marketplace_manifest(root: Path) -> Path:
    return root / ".agents" / "plugins" / "plugins" / "codex-preflight" / ".codex-plugin" / "plugin.json"


def _marketplace_skill(root: Path) -> Path:
    return root / ".agents" / "plugins" / "plugins" / "codex-preflight" / "skills" / "codex-preflight" / "SKILL.md"


def _marketplace_mcp(root: Path) -> Path:
    return root / ".agents" / "plugins" / "plugins" / "codex-preflight" / ".mcp.json"


def _marketplace_hook(root: Path) -> Path:
    return root / ".agents" / "plugins" / "plugins" / "codex-preflight" / "hooks" / "hooks.json"
