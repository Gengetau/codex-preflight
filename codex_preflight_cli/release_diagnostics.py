from __future__ import annotations

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

SCHEMA_VERSION = "release-readiness/v1"
MCP_INSTALL_COMMAND = 'python -m pip install "codex-preflight[mcp]"'
OPTIONAL_FLAGS = (
    "CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN",
    "CODEX_PREFLIGHT_ENABLE_TRUST_READ",
    "CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION",
)
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_VERSION = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)


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
    root = root.resolve()
    run_git = git_runner or _run_git
    run_tool = tool_runner or _run_tool
    version = expected_version or _project_version(root)
    commit = _resolve_commit(root, expected_commit or "HEAD", run_git)
    checks: list[ReleaseCheck] = []
    checks.append(_check_python(python_version))
    git_path = executable_finder("git")
    checks.append(_check_git(git_path))
    checks.append(_check_optional_mcp(runtime_finder))
    checks.append(_check_version_sources(root, version))
    checks.append(_check_plugin_copy(root))
    checks.append(_check_static_inventories())
    checks.append(_check_runtime_inventories(root, run_tool))
    checks.append(_check_tag(root, tag, version, commit, run_git, git_path is not None))
    checks.extend(
        _check_github(
            github_repo=github_repo,
            tag=tag,
            merged_branch=merged_branch,
            expected_commit=commit,
            fetcher=github_fetcher or _github_fetch,
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
            "externalVerificationRequested": github_repo is not None,
            "externalEvidence": "untrusted-data",
        },
    }


def render_release_readiness_markdown(report: Mapping[str, Any]) -> str:
    result = "ready" if report["ready"] else "not ready"
    external = "requested" if report["safety"]["externalVerificationRequested"] else "not requested"
    lines = [
        "# Codex Preflight Release Readiness",
        "",
        f"Overall result: **{result}**",
        "",
        f"- Expected version: `{report['expectedVersion']}`",
        f"- Expected commit: `{report['expectedCommit']}`",
        f"- External verification: `{external}`",
        "",
        "| Check | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for check in report["checks"]:
        detail = str(check["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{check['id']}` | {check['status']} | {detail} |")
        if check["remediation"]:
            remediation = str(check["remediation"]).replace("\n", " ")
            lines.append(f"|  |  | Remediation: {remediation} |")
    lines.extend(("", "Diagnostics are read-only. Remote and repository evidence is untrusted data."))
    return "\n".join(lines)


def _project_version(root: Path) -> str:
    try:
        return str(tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError):
        return "unknown"


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
    if errors or mismatched:
        return ReleaseCheck(
            "version.sources",
            "FAIL",
            "Version sources are missing, invalid, or inconsistent.",
            "Align all Python, package, root-plugin, and marketplace-plugin version sources.",
            {"expected": expected, "values": values, "invalid": sorted(errors), "mismatched": mismatched},
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
            matches = (root / source_name).read_bytes() == (root / destination_name).read_bytes()
        except OSError:
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


def _check_static_inventories() -> ReleaseCheck:
    from codex_preflight_mcp.server import tool_definitions

    mismatches: list[dict[str, Any]] = []
    original = {name: os.environ.get(name) for name in OPTIONAL_FLAGS}
    try:
        for flags, expected in _inventory_matrix():
            _apply_flags(flags)
            actual = [tool["name"] for tool in tool_definitions()]
            if actual != expected:
                mismatches.append({"flags": list(flags), "expected": expected, "actual": actual})
    finally:
        _restore_flags(original)
    if mismatches:
        return ReleaseCheck(
            "mcp.inventory.static",
            "FAIL",
            "One or more static MCP authority inventories drifted.",
            "Restore the exact ordered eight-way MCP inventory contract.",
            {"mismatches": mismatches},
        )
    return ReleaseCheck("mcp.inventory.static", "PASS", "All eight static MCP inventories match exactly.")


def _check_runtime_inventories(root: Path, runner: ToolRunner) -> ReleaseCheck:
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
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            str(root) if not existing_pythonpath else os.pathsep.join((str(root), existing_pythonpath))
        )
        try:
            result = runner((sys.executable, "-m", "codex_preflight_mcp.server", "--list-tools"), environment)
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


def _check_tag(
    root: Path,
    tag: str | None,
    version: str,
    commit: str,
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
    try:
        result = runner(("git", "rev-parse", f"{tag}^{{}}"), root)
    except (OSError, subprocess.SubprocessError) as error:
        return ReleaseCheck(
            "git.tag-target",
            "FAIL",
            f"Read-only tag verification failed with {type(error).__name__}.",
            "Confirm Git access and retry; no tag was created or changed.",
        )
    actual = result.stdout.strip() if result.returncode == 0 else None
    if actual != commit:
        return ReleaseCheck(
            "git.tag-target",
            "FAIL",
            f"Tag {tag} does not resolve to the expected commit.",
            "Do not move an existing tag; stop release closeout and investigate the target mismatch.",
            {"expected": commit, "actual": actual},
        )
    return ReleaseCheck("git.tag-target", "PASS", f"Tag {tag} resolves to the expected commit.")


def _check_github(
    *,
    github_repo: str | None,
    tag: str | None,
    merged_branch: str | None,
    expected_commit: str,
    fetcher: GithubFetcher,
) -> list[ReleaseCheck]:
    if github_repo is None:
        return [
            ReleaseCheck("github.release-target", "SKIP", "GitHub Release verification was not requested."),
            ReleaseCheck("github.branch-cleanup", "SKIP", "GitHub branch cleanup verification was not requested."),
        ]
    if not _REPOSITORY.fullmatch(github_repo):
        failure = ReleaseCheck(
            "github.release-target",
            "FAIL",
            "The GitHub repository must use exact owner/name syntax.",
            "Pass a public GitHub repository as `--github-repo OWNER/NAME`.",
        )
        return [failure, ReleaseCheck("github.branch-cleanup", "FAIL", failure.detail, failure.remediation)]
    release_check = _github_release_check(github_repo, tag, expected_commit, fetcher)
    branch_check = _github_branch_check(github_repo, merged_branch, fetcher)
    return [release_check, branch_check]


def _github_release_check(repo: str, tag: str | None, expected: str, fetcher: GithubFetcher) -> ReleaseCheck:
    if tag is None:
        return ReleaseCheck("github.release-target", "SKIP", "No tag was supplied for GitHub Release verification.")
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


def _github_tag_target(repo: str, tag: str, fetcher: GithubFetcher) -> object | None:
    reference = urllib.parse.quote(f"tags/{tag}", safe="/")
    status, payload = fetcher(f"/repos/{repo}/git/ref/{reference}")
    if status != 200 or payload is None:
        return None
    target = payload.get("object")
    for _ in range(5):
        if not isinstance(target, Mapping):
            return None
        target_type = target.get("type")
        target_sha = target.get("sha")
        if target_type == "commit":
            return target_sha
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


def _apply_flags(flags: tuple[bool, bool, bool]) -> None:
    for name, enabled in zip(OPTIONAL_FLAGS, flags, strict=True):
        if enabled:
            os.environ[name] = "1"
        else:
            os.environ.pop(name, None)


def _restore_flags(original: Mapping[str, str | None]) -> None:
    for name, value in original.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _resolve_commit(root: Path, value: str, runner: GitRunner) -> str:
    try:
        result = runner(("git", "rev-parse", f"{value}^{{commit}}"), root)
    except (OSError, subprocess.SubprocessError):
        return value
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else value


def _run_git(argv: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), cwd=cwd, text=True, capture_output=True, check=False, timeout=10)


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
    return str(tomllib.loads(path.read_text(encoding="utf-8"))["project"]["version"])


def _read_init_version(path: Path) -> str:
    match = _VERSION.search(path.read_text(encoding="utf-8"))
    if match is None:
        raise ValueError("missing version")
    return match.group(1)


def _read_manifest_version(path: Path) -> str:
    return str(json.loads(path.read_text(encoding="utf-8"))["version"])
