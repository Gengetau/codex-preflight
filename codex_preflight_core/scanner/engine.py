from pathlib import Path

from codex_preflight_core.repo.collector import collect_critical_files
from codex_preflight_core.rules.agent_instructions import AgentInstructionRule
from codex_preflight_core.rules.base import Rule
from codex_preflight_core.rules.docker import DockerRule
from codex_preflight_core.rules.github_actions import GitHubActionsRule
from codex_preflight_core.rules.mcp_config import McpConfigRule
from codex_preflight_core.rules.package_json import PackageJsonRule
from codex_preflight_core.rules.python_setup import PythonSetupRule
from codex_preflight_core.rules.readme_link_poisoning import ReadmeLinkPoisoningRule
from codex_preflight_core.rules.rust_go import RustGoEcosystemRule
from codex_preflight_core.rules.secrets import SecretRule
from codex_preflight_core.rules.shell_patterns import ShellPatternRule
from codex_preflight_core.scanner.finding import Finding
from codex_preflight_core.scanner.safe_reader import read_text_safely

DEFAULT_RULES: tuple[Rule, ...] = (
    PackageJsonRule(),
    ShellPatternRule(),
    SecretRule(),
    GitHubActionsRule(),
    McpConfigRule(),
    PythonSetupRule(),
    AgentInstructionRule(),
    ReadmeLinkPoisoningRule(),
    DockerRule(),
    RustGoEcosystemRule(),
)


def scan_repository(root: Path, rules: tuple[Rule, ...] = DEFAULT_RULES, command: str | None = None) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for relative in collect_critical_files(root, command=command):
        result = read_text_safely(root, relative)
        if result.text is None:
            continue
        for rule in rules:
            findings.extend(rule.scan(root, relative, result.text))
    return findings


def list_rule_ids(rules: tuple[Rule, ...] = DEFAULT_RULES) -> list[str]:
    ids: list[str] = []
    for rule in rules:
        ids.extend(rule.rule_ids)
    return sorted(set(ids))
