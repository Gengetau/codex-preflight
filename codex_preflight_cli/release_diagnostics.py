from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from codex_preflight_core.repo.safe_path import (
    SafePathError,
    hold_directory_nofollow,
    local_absolute_path,
    open_regular_file_nofollow,
    read_text_file_nofollow,
)

SCHEMA_VERSION = "release-readiness/v1"
MCP_INSTALL_COMMAND = 'python -m pip install "codex-preflight[mcp]"'
MAX_DIAGNOSTIC_FILE_SIZE = 2 * 1024 * 1024
OPTIONAL_FLAGS = (
    "CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN",
    "CODEX_PREFLIGHT_ENABLE_TRUST_READ",
    "CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION",
)
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_RELEASE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)
_TRUSTED_PACKAGE_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ReleaseCheck:
    check_id: str
    status: str
    detail: str
    remediation: str | None = None
    evidence: Mapping[str, Any] | None = None

    @property
    def passed(self) -> bool:
        return self.status != "FAIL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "status": self.status,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": dict(self.evidence) if self.evidence is not None else None,
        }


GitRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]
ToolRunner = Callable[[Sequence[str], Mapping[str, str]], subprocess.CompletedProcess[str]]
GithubFetcher = Callable[[str], tuple[int, Mapping[str, Any] | None]]


def verify_release_readiness(
    root: Path,
    *,
    expected_version: str | None = None,
    expected_commit: str | None = None,
    tag: str | None = None,
    github_repo: str | None = None,
    merged_branch: str | None = None,
    python_version: tuple[int, int] | None = None,
    executable_finder: Callable[[str], str | None] = shutil.which,
    runtime_finder: Callable[[str], object | None] = find_spec,
    git_runner: GitRunner | None = None,
    tool_runner: ToolRunner | None = None,
    github_fetcher: GithubFetcher | None = None,
) -> dict[str, Any]:
    root = Path(os.path.abspath(root))
    run_git = git_runner or _run_git
    run_tool = tool_runner or _run_tool
    version = expected_version or _project_version(root)
    checks: list[ReleaseCheck] = []
    checks.append(_check_python(python_version))
    git_path = executable_finder("git")
    checks.append(_check_git(git_path))
    checks.append(_check_optional_mcp(runtime_finder))
    root_check = _check_target_root(root)
    checks.append(root_check)
    commit, commit_check = _check_repository_commit(
        root,
        expected_commit or "HEAD",
        run_git,
        git_available=git_path is not None,
        root_safe=root_check.passed,
    )
    checks.append(commit_check)
    checks.append(_check_version_sources(root, version))
    checks.append(_check_plugin_copy(root))
    checks.append(_check_static_inventories(root))
    checks.append(_check_runtime_inventories(run_tool))
    checks.append(_check_tag(root, tag, version, commit, run_git, git_path is not None))
    option_check = _check_external_options(github_repo, tag, merged_branch)
    checks.append(option_check)
    checks.extend(
        _check_github(
            github_repo=github_repo,
            tag=tag,
            merged_branch=merged_branch,
            expected_commit=commit,
            fetcher=github_fetcher or _github_fetch,
            options_valid=option_check.passed,
        )
    )
    counts = {status: sum(check.status == status for check in checks) for status in ("PASS", "FAIL", "SKIP")}
    return {
        "schemaVersion": SCHEMA_VERSION,
        "ready": all(check.passed for check in checks),
        "expectedVersion": version,
        "expectedCommit": commit,
        "tag": tag,
        "githubRepository": github_repo,
        "mergedBranch": merged_branch,
        "summary": counts,
        "checks": [check.to_dict() for check in checks],
        "safety": {
            "mutating": False,
            "externalVerificationRequested": github_repo is not None or merged_branch is not None,
            "externalEvidence": "untrusted-data",
        },
    }


def render_release_readiness_markdown(report: Mapping[str, Any]) -> str:
    result = "ready" if report["ready"] else "not ready"
    external = "requested" if report["safety"]["externalVerificationRequested"] else "not requested"
    lines = [
        "# Codex Preflight Release Readiness",
        "",
        f"Overall result: **{_markdown_data(result)}**",
        "",
        f"- Expected version: `{_markdown_data(report['expectedVersion'])}`",
        f"- Expected commit: `{_markdown_data(report['expectedCommit'])}`",
        f"- External verification: `{_markdown_data(external)}`",
        "",
        "| Check | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for check in report["checks"]:
        check_id = _markdown_data(check["id"])
        status = _markdown_data(check["status"])
        detail = _markdown_data(check["detail"])
        lines.append(f"| `{check_id}` | {status} | {detail} |")
        if check["remediation"]:
            remediation = _markdown_data(check["remediation"])
            lines.append(f"|  |  | Remediation: {remediation} |")
    lines.extend(("", "Diagnostics are read-only. Remote and repository evidence is untrusted data."))
    return "\n".join(lines)


def _project_version(root: Path) -> str:
    try:
        return str(tomllib.loads(_read_text(root / "pyproject.toml"))["project"]["version"])
    except (OSError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError):
        return "unknown"


def _markdown_data(value: object) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
        .replace("\r", "&#13;")
        .replace("\n", "&#10;")
        .replace("|", "&#124;")
        .replace("`", "&#96;")
        .replace("\\", "&#92;")
        .replace("*", "&#42;")
        .replace("_", "&#95;")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
    )


def _check_python(version: tuple[int, int] | None) -> ReleaseCheck:
    actual = version or (sys.version_info.major, sys.version_info.minor)
    if actual >= (3, 12):
        return ReleaseCheck("integration.python", "PASS", f"Python {actual[0]}.{actual[1]} is supported.")
    return ReleaseCheck(
        "integration.python",
        "FAIL",
        f"Python {actual[0]}.{actual[1]} is unsupported.",
        "Install Python 3.12 or newer and rerun release verification.",
    )


def _check_git(path: str | None) -> ReleaseCheck:
    if path:
        return ReleaseCheck("integration.git", "PASS", "Git is available without a shell wrapper.")
    return ReleaseCheck("integration.git", "FAIL", "Git is not available on PATH.", "Install Git and add it to PATH.")


def _check_target_root(root: Path) -> ReleaseCheck:
    try:
        with hold_directory_nofollow(root):
            pass
    except (OSError, SafePathError):
        return ReleaseCheck(
            "repository.root",
            "FAIL",
            "The target root is missing, inaccessible, or uses an unsafe link/reparse path.",
            "Pass an existing local repository directory with no symbolic-link or reparse-point components.",
        )
    return ReleaseCheck("repository.root", "PASS", "The target root is a no-follow local directory.")


def _check_repository_commit(
    root: Path,
    requested: str,
    runner: GitRunner,
    *,
    git_available: bool,
    root_safe: bool,
) -> tuple[str | None, ReleaseCheck]:
    remediation = "Pass an exact valid commit or ref in a Git repository rooted at --root."
    if not root_safe:
        return None, ReleaseCheck(
            "git.repository-commit",
            "FAIL",
            "Repository and commit resolution was skipped because the target root is unsafe.",
            remediation,
        )
    if not git_available:
        return None, ReleaseCheck(
            "git.repository-commit",
            "FAIL",
            "Repository and commit resolution requires Git on PATH.",
            remediation,
        )
    try:
        top = runner(("git", "rev-parse", "--show-toplevel"), root)
        resolved = runner(
            ("git", "rev-parse", "--verify", "--end-of-options", f"{requested}^{{commit}}"),
            root,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, ReleaseCheck(
            "git.repository-commit",
            "FAIL",
            f"Read-only repository resolution failed with {type(error).__name__}.",
            remediation,
        )
    commit = resolved.stdout.strip().lower()
    try:
        exact_root = local_absolute_path(top.stdout.strip())
        same_root = os.path.normcase(str(exact_root)) == os.path.normcase(str(root))
    except (OSError, SafePathError, ValueError):
        same_root = False
    if top.returncode != 0 or resolved.returncode != 0 or not same_root or not _COMMIT_SHA.fullmatch(commit):
        return None, ReleaseCheck(
            "git.repository-commit",
            "FAIL",
            "The target is not the exact Git worktree root or the requested commit/ref is unresolved.",
            remediation,
            {"requested": requested, "canonicalCommit": None},
        )
    return commit, ReleaseCheck(
        "git.repository-commit",
        "PASS",
        "The exact Git worktree root and requested commit/ref resolved canonically.",
        evidence={"canonicalCommit": commit},
    )


def _check_optional_mcp(runtime_finder: Callable[[str], object | None]) -> ReleaseCheck:
    try:
        available = runtime_finder("mcp") is not None
    except Exception:
        available = False
    if available:
        return ReleaseCheck("integration.mcp-runtime", "PASS", "The optional MCP runtime is installed.")
    return ReleaseCheck(
        "integration.mcp-runtime",
        "SKIP",
        "The optional MCP runtime is not installed; static inventory verification still ran.",
        f"Run `{MCP_INSTALL_COMMAND}` to enable runtime MCP smoke validation. No package was installed automatically.",
    )


def _check_version_sources(root: Path, expected: str) -> ReleaseCheck:
    values: dict[str, str] = {}
    errors: list[str] = []
    readers: tuple[tuple[str, Path, Callable[[Path], str]], ...] = (
        ("pyproject.toml", root / "pyproject.toml", _read_pyproject_version),
        ("codex_preflight_core/__init__.py", root / "codex_preflight_core/__init__.py", _read_init_version),
        ("codex_preflight_mcp/__init__.py", root / "codex_preflight_mcp/__init__.py", _read_init_version),
        (".codex-plugin/plugin.json", root / ".codex-plugin/plugin.json", _read_manifest_version),
        (
            ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json",
            root / ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json",
            _read_manifest_version,
        ),
    )
    for name, path, reader in readers:
        try:
            values[name] = reader(path)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError):
            errors.append(name)
    mismatched = sorted(name for name, value in values.items() if value != expected)
    expected_valid = _RELEASE_VERSION.fullmatch(expected) is not None
    if errors or mismatched or not expected_valid:
        return ReleaseCheck(
            "version.sources",
            "FAIL",
            "Version sources are missing, invalid, or inconsistent.",
            "Align all Python, package, root-plugin, and marketplace-plugin version sources.",
            {
                "expected": expected,
                "expectedValid": expected_valid,
                "values": values,
                "invalid": sorted(errors),
                "mismatched": mismatched,
            },
        )
    return ReleaseCheck("version.sources", "PASS", f"All five version sources equal {expected}.", evidence=values)


def _check_plugin_copy(root: Path) -> ReleaseCheck:
    pairs = (
        (".codex-plugin/plugin.json", ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json"),
        (".mcp.json", ".agents/plugins/plugins/codex-preflight/.mcp.json"),
        ("skills/codex-preflight/SKILL.md", ".agents/plugins/plugins/codex-preflight/skills/codex-preflight/SKILL.md"),
    )
    stale: list[str] = []
    for source_name, destination_name in pairs:
        try:
            matches = _read_bytes(root / source_name) == _read_bytes(root / destination_name)
        except (OSError, SafePathError):
            matches = False
        if not matches:
            stale.append(destination_name)
    if stale:
        return ReleaseCheck(
            "plugin.copy",
            "FAIL",
            "The marketplace plugin copy is missing or stale.",
            "Run `python scripts/sync_marketplace_plugin.py`, inspect the diff, then rerun with `--check`.",
            {"stale": stale},
        )
    return ReleaseCheck("plugin.copy", "PASS", "All three marketplace plugin-copy files match their sources.")


def _check_static_inventories(root: Path) -> ReleaseCheck:
    try:
        groups = _parse_target_inventory_groups(_read_text(root / "codex_preflight_mcp/server.py"))
    except (OSError, SafePathError, SyntaxError, ValueError):
        return ReleaseCheck(
            "mcp.inventory.static",
            "FAIL",
            "The target MCP inventory source is missing, unsafe, invalid, or not statically recognizable.",
            "Restore the exact statically recognizable MCP tool_definitions inventory contract.",
        )
    mismatches: list[dict[str, Any]] = []
    for flags, expected in _inventory_matrix():
        actual = list(groups["base"])
        for enabled, group in zip(flags, ("remote", "trust_read", "trust_mutation"), strict=True):
            if enabled:
                actual.extend(groups[group])
        if actual != expected:
            mismatches.append({"flags": list(flags), "expected": expected, "actual": actual})
    if mismatches:
        return ReleaseCheck(
            "mcp.inventory.static",
            "FAIL",
            "One or more static MCP authority inventories drifted.",
            "Restore the exact ordered eight-way MCP inventory contract.",
            {"mismatches": mismatches},
        )
    return ReleaseCheck("mcp.inventory.static", "PASS", "All eight static MCP inventories match exactly.")


def _check_runtime_inventories(runner: ToolRunner) -> ReleaseCheck:
    mismatches: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for flags, expected in _inventory_matrix():
        environment = dict(os.environ)
        for name in OPTIONAL_FLAGS:
            environment.pop(name, None)
        for name, enabled in zip(OPTIONAL_FLAGS, flags, strict=True):
            if enabled:
                environment[name] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONSAFEPATH"] = "1"
        environment["PYTHONPATH"] = str(_TRUSTED_PACKAGE_ROOT)
        try:
            result = runner(
                (sys.executable, "-P", "-m", "codex_preflight_mcp.server", "--list-tools"),
                environment,
            )
        except (OSError, subprocess.SubprocessError) as error:
            failures.append({"flags": list(flags), "error": type(error).__name__})
            continue
        if result.returncode != 0:
            failures.append({"flags": list(flags), "exitCode": result.returncode})
            continue
        try:
            actual = [item["name"] for item in json.loads(result.stdout)]
        except (json.JSONDecodeError, KeyError, TypeError):
            actual = []
        if actual != expected:
            mismatches.append({"flags": list(flags), "expected": expected, "actual": actual})
    if failures or mismatches:
        return ReleaseCheck(
            "mcp.inventory.runtime",
            "FAIL",
            "One or more runtime MCP inventory probes failed or drifted.",
            "Run `python -m codex_preflight_mcp.server --list-tools` for each supported authority combination.",
            {"failures": failures, "mismatches": mismatches},
        )
    return ReleaseCheck("mcp.inventory.runtime", "PASS", "All eight runtime MCP inventories match exactly.")


def _parse_target_inventory_groups(source: str) -> dict[str, tuple[str, ...]]:
    module = ast.parse(source)
    functions = [
        node for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "tool_definitions"
    ]
    if len(functions) != 1:
        raise ValueError("tool_definitions must be unique")
    function = functions[0]
    groups: dict[str, tuple[str, ...]] = {}
    conditional_names = {
        "remote_scan_enabled": "remote",
        "trust_read_enabled": "trust_read",
        "trust_mutation_enabled": "trust_mutation",
    }
    for statement in function.body:
        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
                raise ValueError("unexpected inventory assignment")
            if statement.targets[0].id != "tools" or "base" in groups:
                raise ValueError("unexpected inventory assignment")
            groups["base"] = _inventory_names(statement.value)
        elif isinstance(statement, ast.If):
            if not isinstance(statement.test, ast.Call) or statement.test.args or statement.test.keywords:
                raise ValueError("dynamic inventory condition")
            if not isinstance(statement.test.func, ast.Name):
                raise ValueError("dynamic inventory condition")
            group = conditional_names.get(statement.test.func.id)
            if group is None or group in groups or statement.orelse:
                raise ValueError("unexpected inventory condition")
            groups[group] = _inventory_names(statement)
        elif isinstance(statement, ast.Return):
            if not isinstance(statement.value, ast.Name) or statement.value.id != "tools":
                raise ValueError("unexpected inventory return")
        else:
            raise ValueError("unexpected inventory statement")
    if set(groups) != {"base", "remote", "trust_read", "trust_mutation"}:
        raise ValueError("incomplete inventory groups")
    return groups


def _inventory_names(node: ast.AST) -> tuple[str, ...]:
    names: list[str] = []
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.Dict):
            continue
        for key, value in zip(candidate.keys, candidate.values, strict=True):
            if isinstance(key, ast.Constant) and key.value == "name":
                if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                    raise ValueError("dynamic tool name")
                names.append(value.value)
    if not names or len(names) != len(set(names)):
        raise ValueError("missing or duplicate tool names")
    return tuple(names)


def _check_tag(
    root: Path,
    tag: str | None,
    version: str,
    commit: str | None,
    runner: GitRunner,
    git_available: bool,
) -> ReleaseCheck:
    if tag is None:
        return ReleaseCheck("git.tag-target", "SKIP", "No tag was requested for local target verification.")
    if tag != f"v{version}":
        return ReleaseCheck(
            "git.tag-target",
            "FAIL",
            f"Tag {tag} does not match expected version {version}.",
            f"Pass the exact release tag `v{version}`; never move an existing tag.",
        )
    if not git_available:
        return ReleaseCheck("git.tag-target", "FAIL", "Tag target could not be checked because Git is missing.")
    if commit is None:
        return ReleaseCheck(
            "git.tag-target",
            "FAIL",
            "Tag target verification requires a canonically resolved expected commit.",
            "Resolve the repository commit before verifying the annotated release tag.",
        )
    try:
        object_type = runner(("git", "cat-file", "-t", tag), root)
        result = runner(("git", "rev-parse", "--verify", f"{tag}^{{commit}}"), root)
    except (OSError, subprocess.SubprocessError) as error:
        return ReleaseCheck(
            "git.tag-target",
            "FAIL",
            f"Read-only tag verification failed with {type(error).__name__}.",
            "Confirm Git access and retry; no tag was created or changed.",
        )
    actual = result.stdout.strip().lower() if result.returncode == 0 else None
    annotated = object_type.returncode == 0 and object_type.stdout.strip() == "tag"
    if not annotated or actual != commit or not isinstance(actual, str) or not _COMMIT_SHA.fullmatch(actual):
        return ReleaseCheck(
            "git.tag-target",
            "FAIL",
            f"Tag {tag} is not annotated or does not resolve to the expected commit.",
            "Do not move an existing tag; require an annotated release tag and investigate the target mismatch.",
            {"expected": commit, "actual": actual, "annotated": annotated},
        )
    return ReleaseCheck("git.tag-target", "PASS", f"Annotated tag {tag} resolves to the expected commit.")


def _check_external_options(
    github_repo: str | None,
    tag: str | None,
    merged_branch: str | None,
) -> ReleaseCheck:
    if merged_branch is not None and github_repo is None:
        return ReleaseCheck(
            "options.external",
            "FAIL",
            "--merged-branch requires --github-repo.",
            "Add `--github-repo OWNER/NAME` or remove `--merged-branch`.",
        )
    if github_repo is not None and not _REPOSITORY.fullmatch(github_repo):
        return ReleaseCheck(
            "options.external",
            "FAIL",
            "The GitHub repository must use exact owner/name syntax.",
            "Pass a public GitHub repository as `--github-repo OWNER/NAME`.",
        )
    if github_repo is not None and tag is None and merged_branch is None:
        return ReleaseCheck(
            "options.external",
            "FAIL",
            "--github-repo requires at least --tag or --merged-branch.",
            "Select the published tag, merged branch, or both for explicit read-only verification.",
        )
    return ReleaseCheck("options.external", "PASS", "External verification option dependencies are valid.")


def _check_github(
    *,
    github_repo: str | None,
    tag: str | None,
    merged_branch: str | None,
    expected_commit: str | None,
    fetcher: GithubFetcher,
    options_valid: bool,
) -> list[ReleaseCheck]:
    if github_repo is None:
        return [
            ReleaseCheck("github.repository-access", "SKIP", "GitHub repository verification was not requested."),
            ReleaseCheck("github.release-target", "SKIP", "GitHub Release verification was not requested."),
            ReleaseCheck("github.branch-cleanup", "SKIP", "GitHub branch cleanup verification was not requested."),
        ]
    if not options_valid:
        return [
            ReleaseCheck("github.repository-access", "SKIP", "Invalid external options prevented GitHub access."),
            ReleaseCheck("github.release-target", "SKIP", "Invalid external options prevented Release access."),
            ReleaseCheck("github.branch-cleanup", "SKIP", "Invalid external options prevented branch access."),
        ]
    repository_check = _github_repository_check(github_repo, fetcher)
    if not repository_check.passed:
        return [
            repository_check,
            ReleaseCheck(
                "github.release-target",
                "FAIL",
                "Release state is untrusted because repository access failed.",
            ),
            ReleaseCheck(
                "github.branch-cleanup",
                "FAIL",
                "Branch state is untrusted because repository access failed.",
            ),
        ]
    release_check = _github_release_check(github_repo, tag, expected_commit, fetcher)
    branch_check = _github_branch_check(github_repo, merged_branch, fetcher)
    return [repository_check, release_check, branch_check]


def _github_repository_check(repo: str, fetcher: GithubFetcher) -> ReleaseCheck:
    try:
        status, payload = fetcher(f"/repos/{repo}")
    except Exception as error:
        return _external_failure("github.repository-access", error)
    accessible = (
        status == 200
        and payload is not None
        and isinstance(payload.get("full_name"), str)
        and payload["full_name"].lower() == repo.lower()
        and payload.get("private") is False
    )
    if not accessible:
        return ReleaseCheck(
            "github.repository-access",
            "FAIL",
            "The public GitHub repository could not be positively identified.",
            "Confirm the public OWNER/NAME and API access before interpreting Release or branch state.",
            {"source": "github-api-untrusted-data", "status": status},
        )
    return ReleaseCheck(
        "github.repository-access",
        "PASS",
        "The public GitHub repository was positively identified.",
        evidence={"source": "github-api-untrusted-data", "repository": payload["full_name"]},
    )


def _github_release_check(repo: str, tag: str | None, expected: str | None, fetcher: GithubFetcher) -> ReleaseCheck:
    if tag is None:
        return ReleaseCheck("github.release-target", "SKIP", "No tag was supplied for GitHub Release verification.")
    if expected is None:
        return ReleaseCheck(
            "github.release-target",
            "FAIL",
            "GitHub Release verification requires a canonically resolved expected commit.",
        )
    path = f"/repos/{repo}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    try:
        status, payload = fetcher(path)
    except Exception as error:
        return _external_failure("github.release-target", error)
    if status != 200 or payload is None:
        return ReleaseCheck(
            "github.release-target",
            "FAIL",
            f"GitHub Release metadata for {tag} is unavailable.",
            "Publish the matching non-draft, non-prerelease Release, then rerun verification.",
        )
    try:
        actual = _github_tag_target(repo, tag, fetcher)
    except Exception as error:
        return _external_failure("github.release-target", error)
    matches = (
        payload.get("tag_name") == tag
        and actual == expected
        and payload.get("draft") is False
        and payload.get("prerelease") is False
    )
    evidence = {
        "source": "github-api-untrusted-data",
        "tag": payload.get("tag_name"),
        "tagTarget": actual,
        "releaseTargetCommitish": payload.get("target_commitish"),
        "draft": payload.get("draft"),
        "prerelease": payload.get("prerelease"),
    }
    if not matches:
        return ReleaseCheck(
            "github.release-target",
            "FAIL",
            "GitHub Release metadata does not match the expected published release.",
            "Do not move tags or silently republish; stop and inspect the Release target and state.",
            evidence,
        )
    return ReleaseCheck(
        "github.release-target",
        "PASS",
        "GitHub Release target and publication state match.",
        evidence=evidence,
    )


def _github_tag_target(repo: str, tag: str, fetcher: GithubFetcher) -> str | None:
    reference = urllib.parse.quote(f"tags/{tag}", safe="/")
    status, payload = fetcher(f"/repos/{repo}/git/ref/{reference}")
    if status != 200 or payload is None:
        return None
    target = payload.get("object")
    if not isinstance(target, Mapping) or target.get("type") != "tag":
        return None
    for _ in range(5):
        if not isinstance(target, Mapping):
            return None
        target_type = target.get("type")
        target_sha = target.get("sha")
        if target_type == "commit":
            if isinstance(target_sha, str) and _COMMIT_SHA.fullmatch(target_sha):
                return target_sha
            return None
        if target_type != "tag" or not isinstance(target_sha, str):
            return None
        status, payload = fetcher(f"/repos/{repo}/git/tags/{urllib.parse.quote(target_sha, safe='')}")
        if status != 200 or payload is None:
            return None
        target = payload.get("object")
    return None


def _github_branch_check(repo: str, branch: str | None, fetcher: GithubFetcher) -> ReleaseCheck:
    if branch is None:
        return ReleaseCheck("github.branch-cleanup", "SKIP", "No merged branch was supplied for cleanup verification.")
    path = f"/repos/{repo}/branches/{urllib.parse.quote(branch, safe='')}"
    try:
        status, payload = fetcher(path)
    except Exception as error:
        return _external_failure("github.branch-cleanup", error)
    if status == 404:
        return ReleaseCheck("github.branch-cleanup", "PASS", "The merged implementation branch is absent on GitHub.")
    if status == 200:
        return ReleaseCheck(
            "github.branch-cleanup",
            "FAIL",
            "The merged implementation branch still exists on GitHub.",
            "Delete the merged branch through the authorized release workflow, then rerun this read-only check.",
            {"source": "github-api-untrusted-data", "branch": branch, "present": True},
        )
    return ReleaseCheck(
        "github.branch-cleanup",
        "FAIL",
        "GitHub branch cleanup state could not be determined.",
        "Confirm API access and rerun the read-only verification.",
        {"source": "github-api-untrusted-data", "status": status, "payloadPresent": payload is not None},
    )


def _external_failure(check_id: str, error: Exception) -> ReleaseCheck:
    return ReleaseCheck(
        check_id,
        "FAIL",
        f"Read-only GitHub verification failed with {type(error).__name__}.",
        "Confirm bounded public GitHub API access and retry; no release state was changed.",
    )


def _inventory_matrix() -> tuple[tuple[tuple[bool, bool, bool], list[str]], ...]:
    rows: list[tuple[tuple[bool, bool, bool], list[str]]] = []
    for remote, trust_read, mutation in (
        (False, False, False),
        (True, False, False),
        (False, True, False),
        (False, False, True),
        (True, True, False),
        (True, False, True),
        (False, True, True),
        (True, True, True),
    ):
        names = ["preflight_check", "corpus_scan"]
        if remote:
            names.append("remote_repository_scan")
        if trust_read:
            names.append("trust_list")
        if mutation:
            names.extend(("trust_approve", "trust_revoke"))
        rows.append(((remote, trust_read, mutation), names))
    return tuple(rows)


def _run_git(argv: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["GIT_NO_LAZY_FETCH"] = "1"
    return subprocess.run(
        list(argv),
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
        env=environment,
    )


def _run_tool(argv: Sequence[str], environment: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
        env=dict(environment),
    )


def _github_fetch(path: str) -> tuple[int, Mapping[str, Any] | None]:
    url = f"https://api.github.com{path}"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "codex-preflight-release-verify"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if urllib.parse.urlparse(response.geturl()).hostname != "api.github.com":
                raise OSError("unexpected GitHub API redirect")
            payload = json.loads(response.read().decode("utf-8"))
            return response.status, payload if isinstance(payload, dict) else None
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return 404, None
        raise OSError("GitHub API request failed") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OSError("GitHub API response was unavailable") from error


def _read_pyproject_version(path: Path) -> str:
    return str(tomllib.loads(_read_text(path))["project"]["version"])


def _read_init_version(path: Path) -> str:
    match = _VERSION.search(_read_text(path))
    if match is None:
        raise ValueError("missing version")
    return match.group(1)


def _read_manifest_version(path: Path) -> str:
    return str(json.loads(_read_text(path))["version"])


def _read_text(path: Path) -> str:
    return read_text_file_nofollow(path, max_bytes=MAX_DIAGNOSTIC_FILE_SIZE)


def _read_bytes(path: Path) -> bytes:
    with open_regular_file_nofollow(path) as handle:
        data = handle.read(MAX_DIAGNOSTIC_FILE_SIZE + 1)
    if len(data) > MAX_DIAGNOSTIC_FILE_SIZE:
        raise SafePathError("The file exceeds its safety limit.")
    return data
