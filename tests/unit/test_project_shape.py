import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_project_declares_cli_security_tool_metadata() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["name"] == "codex-preflight"
    assert pyproject["project"]["requires-python"] == ">=3.12"
    assert pyproject["project"]["scripts"]["codex-preflight"] == "codex_preflight_cli.main:app"


def test_project_does_not_depend_on_web_frameworks() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = {dependency.lower() for dependency in pyproject["project"]["dependencies"]}

    assert all("fastapi" not in dependency for dependency in dependencies)
    assert all("flask" not in dependency for dependency in dependencies)
    assert all("django" not in dependency for dependency in dependencies)


def test_readme_states_local_first_preflight_goal() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "local-first" in readme
    assert "pre-execution" in readme
    assert "Codex" in readme
