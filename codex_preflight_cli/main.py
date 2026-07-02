import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer

from codex_preflight_cli.exec_wrapper import run_checked_command
from codex_preflight_core import __version__
from codex_preflight_core.cache.paths import scan_cache_path, trust_cache_path
from codex_preflight_core.cache.scan_cache import ScanCache
from codex_preflight_core.cache.trust_cache import TrustCache
from codex_preflight_core.command.classifier import classify_command
from codex_preflight_core.policy.decision import EXIT_CODES, Decision
from codex_preflight_core.preflight import run_preflight
from codex_preflight_core.repo.fingerprint import compute_critical_fingerprint
from codex_preflight_core.repo.identity import resolve_repo_identity
from codex_preflight_core.repo.temp_clone import clone_repo_to_temp
from codex_preflight_core.report.markdown_renderer import render_markdown_report
from codex_preflight_core.scanner.engine import list_rule_ids

app = typer.Typer(
    help="Local-first pre-execution repository risk scanner for Codex-style agents.",
    no_args_is_help=True,
)
rules_app = typer.Typer(help="Inspect static scanner rules.")
trust_app = typer.Typer(help="Manage local command trust approvals.")
cache_app = typer.Typer(help="Manage local scan cache.")

app.add_typer(rules_app, name="rules")
app.add_typer(trust_app, name="trust")
app.add_typer(cache_app, name="cache")


@app.callback()
def root(
    version: Annotated[
        bool,
        typer.Option("--version", help="Show the Codex Preflight version and exit."),
    ] = False,
) -> None:
    if version:
        typer.echo(f"codex-preflight {__version__}")
        raise typer.Exit()


@app.command()
def preflight(
    cwd: Annotated[
        str | None,
        typer.Option("--cwd", help="Local repository path to scan."),
    ] = None,
    repo: Annotated[
        str | None,
        typer.Option("--repo", help="GitHub repository URL to clone and scan."),
    ] = None,
    command: Annotated[
        str,
        typer.Option("--command", help="Planned command to evaluate."),
    ] = "",
    format: Annotated[
        str,
        typer.Option("--format", help="Report format: json or markdown."),
    ] = "json",
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Optional report output path."),
    ] = None,
    no_cache: Annotated[
        bool,
        typer.Option("--no-cache", help="Disable scan cache lookup and storage."),
    ] = False,
    keep_temp: Annotated[
        bool,
        typer.Option("--keep-temp", help="Keep temporary clone for debugging."),
    ] = False,
    temp_dir: Annotated[
        Path | None,
        typer.Option("--temp-dir", help="Directory to create temporary clones under."),
    ] = None,
) -> None:
    """Evaluate whether a planned command should run."""
    if not cwd and not repo:
        cwd = "."
    if repo:
        with clone_repo_to_temp(repo, keep_temp=keep_temp, temp_dir=temp_dir) as cloned:
            report = run_preflight(cloned, command, use_cache=not no_cache)
    else:
        report = run_preflight(Path(cwd or "."), command, use_cache=not no_cache)
    rendered = json.dumps(report, indent=2) if format == "json" else render_markdown_report(report)
    if output:
        output.write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered)
    raise typer.Exit(EXIT_CODES[Decision(report["decision"])])


@app.command(name="exec")
def exec_command(
    command: Annotated[
        list[str],
        typer.Argument(help="Command to run after preflight allows it."),
    ],
    cwd: Annotated[
        Path,
        typer.Option("--cwd", help="Local repository path to scan and run in."),
    ] = Path("."),
    format: Annotated[
        str,
        typer.Option("--format", help="Blocked report format: json or markdown."),
    ] = "markdown",
) -> None:
    """Wrap command execution with a preflight check."""
    raise typer.Exit(run_checked_command(cwd, command, report_format=format))


@rules_app.command("list")
def list_rules() -> None:
    """List available scanner rules."""
    for rule_id in list_rule_ids():
        typer.echo(rule_id)


@trust_app.command("list")
def list_trust() -> None:
    """List local trust approvals."""
    typer.echo(json.dumps(TrustCache(trust_cache_path()).list(), indent=2))


@trust_app.command("approve")
def approve_trust(
    cwd: Annotated[str, typer.Option("--cwd", help="Repository path to approve.")],
    command: Annotated[str, typer.Option("--command", help="Command to approve.")],
    ttl: Annotated[str, typer.Option("--ttl", help="Trust duration.")] = "7d",
) -> None:
    """Approve a scoped command for a repository."""
    identity = resolve_repo_identity(Path(cwd))
    fingerprint = compute_critical_fingerprint(identity.path)
    classification = classify_command(command)
    TrustCache(trust_cache_path()).approve(
        repo_id=identity.repo_id,
        path=identity.path,
        remote_url=identity.remote_url,
        head_commit=identity.head_commit,
        critical_fingerprint=fingerprint,
        command_scope=classification.scope.value,
        approved_command=command,
        expires_at=datetime.now(UTC) + _parse_ttl(ttl),
        policy_version="default-v1",
        ruleset_version="2026.07.02",
    )
    typer.echo("Trust approval stored.")


@trust_app.command("revoke")
def revoke_trust(
    cwd: Annotated[str, typer.Option("--cwd", help="Repository path to revoke.")],
) -> None:
    """Revoke trust approvals for a repository."""
    identity = resolve_repo_identity(Path(cwd))
    TrustCache(trust_cache_path()).revoke(identity.path)
    typer.echo("Trust approvals revoked.")


@cache_app.command("clear")
def clear_cache() -> None:
    """Clear local scan cache."""
    ScanCache(scan_cache_path()).clear()
    typer.echo("Scan cache cleared.")


def _parse_ttl(value: str) -> timedelta:
    unit = value[-1]
    amount = int(value[:-1])
    if unit == "d":
        return timedelta(days=amount)
    if unit == "h":
        return timedelta(hours=amount)
    raise typer.BadParameter("TTL must use h or d, such as 12h or 7d.")


if __name__ == "__main__":
    sys.exit(app())
