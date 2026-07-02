from typer.testing import CliRunner

from codex_preflight_cli.main import app


def test_root_help_lists_loop_zero_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "preflight" in result.output
    assert "exec" in result.output
    assert "rules" in result.output
    assert "trust" in result.output
    assert "cache" in result.output


def test_preflight_placeholder_returns_scanner_error() -> None:
    result = CliRunner().invoke(
        app,
        ["preflight", "--cwd", ".", "--command", "pnpm install", "--format", "json", "--no-cache"],
    )

    assert result.exit_code in {0, 10, 20, 30}
    assert '"schemaVersion"' in result.output
