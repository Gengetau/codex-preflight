from __future__ import annotations

import ast
import hashlib
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
from types import MappingProxyType
from typing import Any

from codex_preflight_core.repo.safe_path import (
    SafePathError,
    hold_directory_nofollow,
    local_absolute_path,
    open_regular_file_nofollow,
)

SCHEMA_VERSION = "release-readiness/v1"
MCP_INSTALL_COMMAND = 'python -m pip install "codex-preflight[mcp]"'
MAX_DIAGNOSTIC_FILE_SIZE = 2 * 1024 * 1024
MAX_GITHUB_RESPONSE_SIZE = 1024 * 1024
OPTIONAL_FLAGS = (
    "CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN",
    "CODEX_PREFLIGHT_ENABLE_TRUST_READ",
    "CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION",
)
_REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_RELEASE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_GIT_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DYNAMIC_NAMESPACE_NAMES = frozenset(
    {"__import__", "compile", "delattr", "eval", "exec", "globals", "locals", "setattr", "vars"}
)
_MAPPING_MUTATION_METHODS = frozenset(
    {"__delitem__", "__setitem__", "clear", "pop", "popitem", "setdefault", "update"}
)
_OS_ENVIRONMENT_MUTATORS = frozenset({"putenv", "unsetenv"})
_PROTECTED_SERVER_SYMBOLS = frozenset(
    {
        "_record_registration_state",
        "_register_mcp_tools",
        "_runtime_services",
        "create_mcp_server",
        "remote_scan_enabled",
        "tool_definitions",
        "trust_mutation_enabled",
        "trust_read_enabled",
    }
)
_CONSUMED_TARGET_FILES = (
    "pyproject.toml",
    "codex_preflight_core/__init__.py",
    "codex_preflight_mcp/__init__.py",
    "codex_preflight_mcp/server.py",
    ".codex-plugin/plugin.json",
    ".mcp.json",
    "skills/codex-preflight/SKILL.md",
    ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json",
    ".agents/plugins/plugins/codex-preflight/.mcp.json",
    ".agents/plugins/plugins/codex-preflight/skills/codex-preflight/SKILL.md",
)
_TRUSTED_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_RUNTIME_PROBE = (
    "import json; import codex_preflight_core as core; import codex_preflight_mcp as package; "
    "import codex_preflight_mcp.server as server; "
    "inert = type('_ReleaseInventoryService', (), {'record_registration_state': lambda self: None}); "
    "server.default_trust_read_service = inert; server.default_trust_mutation_service = inert; "
    "mcp = server.create_mcp_server(); "
    "tools = [{'name': tool.name} for tool in mcp._tool_manager.list_tools()]; "
    "print(json.dumps({'moduleFile': server.__file__, 'tools': tools, "
    "'versions': {'core': core.__version__, 'mcp': package.__version__}}))"
)


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
FileSnapshot = Mapping[str, bytes]


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
    trusted_package_root: Path | None = None,
) -> dict[str, Any]:
    root = Path(os.path.abspath(root))
    run_tool = tool_runner or _run_tool
    checks: list[ReleaseCheck] = []
    checks.append(_check_python(python_version))
    root_check = _check_target_root(root)
    git_executable, git_check = _resolve_git_executable(
        executable_finder("git"),
        root,
        root_safe=root_check.passed,
    )
    run_git = _pin_git_runner(git_runner or _run_git, git_executable)
    checks.append(git_check)
    mcp_runtime_check = _check_optional_mcp(runtime_finder)
    checks.append(mcp_runtime_check)
    checks.append(root_check)
    commit, snapshot, commit_check = _check_repository_commit(
        root,
        expected_commit or "HEAD",
        run_git,
        git_available=git_executable is not None,
        root_safe=root_check.passed,
    )
    checks.append(commit_check)
    version = expected_version or _project_version(snapshot)
    checks.append(_check_version_sources(snapshot, version))
    checks.append(_check_plugin_copy(snapshot))
    checks.append(_check_static_inventories(snapshot))
    if mcp_runtime_check.status == "PASS":
        checks.append(
            _check_runtime_inventories(
                root,
                run_tool,
                trusted_package_root or _TRUSTED_PACKAGE_ROOT,
                version,
            )
        )
    else:
        checks.append(_skip_runtime_inventories())
    checks.append(_check_tag(root, tag, version, commit, run_git, git_executable is not None))
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


def _project_version(snapshot: FileSnapshot) -> str:
    try:
        return _read_pyproject_version(snapshot["pyproject.toml"])
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


def _resolve_git_executable(
    discovered: str | None,
    root: Path,
    *,
    root_safe: bool,
) -> tuple[Path | None, ReleaseCheck]:
    remediation = "Install Git outside the target checkout and expose its executable on PATH."
    if not discovered:
        return None, ReleaseCheck("integration.git", "FAIL", "Git is not available on PATH.", remediation)
    try:
        candidate = Path(discovered)
        if not candidate.is_absolute():
            candidate = Path(os.path.abspath(candidate))
        executable = candidate.resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise OSError("Git path is not an executable file")
        target = root.resolve(strict=True) if root_safe else root
    except (OSError, RuntimeError, ValueError):
        return None, ReleaseCheck(
            "integration.git",
            "FAIL",
            "The discovered Git executable could not be resolved canonically.",
            remediation,
        )
    if _path_is_within(executable, target):
        return None, ReleaseCheck(
            "integration.git",
            "FAIL",
            "The discovered Git executable is inside the target checkout and was rejected.",
            remediation,
            {"insideTarget": True},
        )
    return executable, ReleaseCheck(
        "integration.git",
        "PASS",
        "Git is pinned to one canonical executable outside the target checkout.",
        evidence={"executable": str(executable), "insideTarget": False},
    )


def _pin_git_runner(runner: GitRunner, executable: Path | None) -> GitRunner:
    def run(argv: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        if executable is None:
            raise OSError("Git executable is unavailable")
        if not argv or argv[0] != "git":
            raise ValueError("Git command must use the internal placeholder")
        return runner((str(executable), *argv[1:]), cwd)

    return run


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
) -> tuple[str | None, FileSnapshot, ReleaseCheck]:
    empty_snapshot: FileSnapshot = MappingProxyType({})
    remediation = "Pass an exact valid commit or ref in a Git repository rooted at --root."
    if not root_safe:
        return None, empty_snapshot, ReleaseCheck(
            "git.repository-commit",
            "FAIL",
            "Repository and commit resolution was skipped because the target root is unsafe.",
            remediation,
        )
    if not git_available:
        return None, empty_snapshot, ReleaseCheck(
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
        head = runner(
            ("git", "rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"),
            root,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, empty_snapshot, ReleaseCheck(
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
    head_commit = head.stdout.strip().lower()
    if (
        top.returncode != 0
        or resolved.returncode != 0
        or head.returncode != 0
        or not same_root
        or not _COMMIT_SHA.fullmatch(commit)
        or not _COMMIT_SHA.fullmatch(head_commit)
        or head_commit != commit
    ):
        return None, empty_snapshot, ReleaseCheck(
            "git.repository-commit",
            "FAIL",
            "The target root and HEAD must match the requested commit/ref.",
            "Check out the expected commit and retry from its worktree root.",
            {
                "requested": requested,
                "canonicalCommit": commit if _COMMIT_SHA.fullmatch(commit) else None,
                "headCommit": head_commit if _COMMIT_SHA.fullmatch(head_commit) else None,
            },
        )

    mismatched: list[str] = []
    invalid: list[str] = []
    invalid_entries: dict[str, str] = {}
    snapshot: dict[str, bytes] = {}
    for relative_name in _CONSUMED_TARGET_FILES:
        try:
            result = runner(
                ("git", "ls-tree", "-z", "--full-tree", commit, "--", relative_name),
                root,
            )
            mode, object_type, object_id, entry_path = _parse_git_tree_entry(result.stdout)
            data = _read_bytes(root / relative_name)
        except (OSError, SafePathError, subprocess.SubprocessError, ValueError):
            invalid.append(relative_name)
            continue
        if result.returncode != 0 or not _GIT_OBJECT_ID.fullmatch(object_id) or entry_path != relative_name:
            invalid.append(relative_name)
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            invalid_entries[relative_name] = f"{mode} {object_type}"
            continue
        if not _git_blob_matches(data, object_id):
            mismatched.append(relative_name)
            continue
        snapshot[relative_name] = data
    if invalid or invalid_entries or mismatched:
        return None, empty_snapshot, ReleaseCheck(
            "git.repository-commit",
            "FAIL",
            "One or more consumed target files do not match the requested commit blobs.",
            "Restore every consumed target file from the expected commit and retry.",
            {
                "requested": requested,
                "canonicalCommit": commit,
                "headCommit": head_commit,
                "invalidFiles": sorted(invalid),
                "invalidEntries": dict(sorted(invalid_entries.items())),
                "mismatchedFiles": sorted(mismatched),
            },
        )
    immutable_snapshot: FileSnapshot = MappingProxyType(snapshot)
    return commit, immutable_snapshot, ReleaseCheck(
        "git.repository-commit",
        "PASS",
        "HEAD equals the requested canonical commit and every consumed file matches its commit blob.",
        evidence={
            "canonicalCommit": commit,
            "headCommit": head_commit,
            "consumedFilesMatchedCommit": True,
            "consumedFileModes": "regular-blob-only",
            "immutableSnapshot": True,
            "consumedFiles": list(_CONSUMED_TARGET_FILES),
        },
    )


def _parse_git_tree_entry(value: str) -> tuple[str, str, str, str]:
    entries = value.removesuffix("\0").split("\0") if value else []
    if len(entries) != 1 or "\t" not in entries[0]:
        raise ValueError("expected one exact tree entry")
    metadata, path = entries[0].split("\t", 1)
    fields = metadata.split()
    if len(fields) != 3:
        raise ValueError("invalid tree entry metadata")
    mode, object_type, object_id = fields
    return mode, object_type, object_id.lower(), path


def _git_blob_id(data: bytes, object_id_length: int) -> str:
    algorithm = hashlib.sha1 if object_id_length == 40 else hashlib.sha256
    header = f"blob {len(data)}\0".encode("ascii")
    return algorithm(header + data).hexdigest()


def _git_blob_matches(data: bytes, object_id: str) -> bool:
    candidates = (data, data.replace(b"\r\n", b"\n"))
    return any(_git_blob_id(candidate, len(object_id)) == object_id for candidate in candidates)


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
        (
            "The optional MCP runtime is not installed; static inventory verification still ran "
            "and runtime probing was skipped."
        ),
        f"Run `{MCP_INSTALL_COMMAND}` to enable runtime MCP smoke validation. No package was installed automatically.",
    )


def _skip_runtime_inventories() -> ReleaseCheck:
    return ReleaseCheck(
        "mcp.inventory.runtime",
        "SKIP",
        "Runtime MCP inventory probing was skipped because the optional MCP runtime is not installed.",
        f"Run `{MCP_INSTALL_COMMAND}` to enable all eight actual FastMCP Tool Manager inventory checks.",
        {"runtimeAvailable": False, "probeInvoked": False},
    )


def _check_version_sources(snapshot: FileSnapshot, expected: str) -> ReleaseCheck:
    values: dict[str, str] = {}
    errors: list[str] = []
    readers: tuple[tuple[str, Callable[[bytes], str]], ...] = (
        ("pyproject.toml", _read_pyproject_version),
        ("codex_preflight_core/__init__.py", _read_init_version),
        ("codex_preflight_mcp/__init__.py", _read_init_version),
        (".codex-plugin/plugin.json", _read_manifest_version),
        (
            ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json",
            _read_manifest_version,
        ),
    )
    for name, reader in readers:
        try:
            values[name] = reader(snapshot[name])
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


def _check_plugin_copy(snapshot: FileSnapshot) -> ReleaseCheck:
    pairs = (
        (".codex-plugin/plugin.json", ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json"),
        (".mcp.json", ".agents/plugins/plugins/codex-preflight/.mcp.json"),
        ("skills/codex-preflight/SKILL.md", ".agents/plugins/plugins/codex-preflight/skills/codex-preflight/SKILL.md"),
    )
    stale: list[str] = []
    for source_name, destination_name in pairs:
        try:
            matches = snapshot[source_name] == snapshot[destination_name]
        except KeyError:
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


def _check_static_inventories(snapshot: FileSnapshot) -> ReleaseCheck:
    try:
        groups = _parse_target_inventory_groups(_snapshot_text(snapshot, "codex_preflight_mcp/server.py"))
    except (KeyError, UnicodeError, SyntaxError, ValueError):
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


def _check_runtime_inventories(
    target_root: Path,
    runner: ToolRunner,
    trusted_package_root: Path,
    expected_version: str,
) -> ReleaseCheck:
    remediation = (
        "Invoke release verification from a trusted Codex Preflight package root that is filesystem-isolated "
        "from the target checkout."
    )
    try:
        trusted_root = trusted_package_root.resolve(strict=True)
        target = target_root.resolve(strict=True)
    except OSError:
        return ReleaseCheck(
            "mcp.inventory.runtime",
            "FAIL",
            "The trusted runtime package root could not be resolved.",
            remediation,
        )
    if _path_is_within(trusted_root, target):
        return ReleaseCheck(
            "mcp.inventory.runtime",
            "FAIL",
            "The runtime package overlaps the target checkout, so no runtime probe was executed.",
            remediation,
            {"provenanceVerified": False, "overlapsTarget": True},
        )
    mismatches: list[dict[str, Any]] = []
    version_mismatches: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    module_files: set[str] = set()
    runtime_versions: set[tuple[str, str]] = set()
    for flags, expected in _inventory_matrix():
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.upper().startswith("PYTHON")
        }
        for name in OPTIONAL_FLAGS:
            environment.pop(name, None)
        for name, enabled in zip(OPTIONAL_FLAGS, flags, strict=True):
            if enabled:
                environment[name] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONNOUSERSITE"] = "1"
        environment["PYTHONSAFEPATH"] = "1"
        environment["PYTHONPATH"] = str(trusted_root)
        try:
            result = runner(
                (sys.executable, "-P", "-c", _RUNTIME_PROBE),
                environment,
            )
        except (OSError, subprocess.SubprocessError) as error:
            failures.append({"flags": list(flags), "error": type(error).__name__})
            continue
        if result.returncode != 0:
            failures.append({"flags": list(flags), "exitCode": result.returncode})
            continue
        try:
            payload = json.loads(result.stdout)
            module_file = Path(payload["moduleFile"]).resolve(strict=True)
            tools = payload["tools"]
            actual = [item["name"] for item in tools]
            versions = payload["versions"]
            actual_versions = {"core": versions["core"], "mcp": versions["mcp"]}
            if not all(isinstance(value, str) for value in actual_versions.values()):
                raise TypeError("runtime versions must be strings")
            provenance_valid = _path_is_within(module_file, trusted_root) and not _path_is_within(
                module_file,
                target,
            )
        except (json.JSONDecodeError, KeyError, OSError, TypeError):
            actual = []
            provenance_valid = False
            module_file = None
        if not provenance_valid:
            failures.append({"flags": list(flags), "error": "untrusted-module-provenance"})
            continue
        module_files.add(str(module_file))
        runtime_versions.add((actual_versions["core"], actual_versions["mcp"]))
        if actual != expected:
            mismatches.append({"flags": list(flags), "expected": expected, "actual": actual})
        expected_versions = {"core": expected_version, "mcp": expected_version}
        if actual_versions != expected_versions:
            version_mismatches.append(
                {"flags": list(flags), "expected": expected_versions, "actual": actual_versions}
            )
    if failures or mismatches or version_mismatches:
        return ReleaseCheck(
            "mcp.inventory.runtime",
            "FAIL",
            "One or more actual FastMCP registry probes failed, drifted, used an unexpected version, "
            "or used untrusted module provenance.",
            remediation,
            {
                "failures": failures,
                "mismatches": mismatches,
                "versionMismatches": version_mismatches,
            },
        )
    return ReleaseCheck(
        "mcp.inventory.runtime",
        "PASS",
        "All eight actual FastMCP registries and trusted runtime versions match with verified module "
        "provenance outside the target.",
        evidence={
            "provenanceVerified": True,
            "overlapsTarget": False,
            "registrySource": "FastMCP ToolManager",
            "runtimePackageRoot": str(trusted_root),
            "moduleFiles": sorted(module_files),
            "runtimeVersions": [
                {"core": core, "mcp": mcp}
                for core, mcp in sorted(runtime_versions)
            ],
        },
    )


def _parse_target_inventory_groups(source: str) -> dict[str, tuple[str, ...]]:
    module = ast.parse(source)
    _reject_dynamic_namespace_mutation(
        module,
        protect_os=True,
        protected_attributes=_PROTECTED_SERVER_SYMBOLS,
    )
    functions = [
        node for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "tool_definitions"
    ]
    if len(functions) != 1:
        raise ValueError("tool_definitions must be unique")
    if _recursive_binding_count(module, "tool_definitions") != 1:
        raise ValueError("tool_definitions must not be rebound")
    function = functions[0]
    if isinstance(function, ast.AsyncFunctionDef) or function.decorator_list or function.args.args:
        raise ValueError("unexpected tool_definitions signature")
    if function.args.posonlyargs or function.args.kwonlyargs or function.args.vararg or function.args.kwarg:
        raise ValueError("unexpected tool_definitions signature")
    if len(function.body) != 5:
        raise ValueError("tool_definitions must contain exactly five ordered statements")

    assignment, *conditions, returned = function.body
    if (
        not isinstance(assignment, ast.Assign)
        or len(assignment.targets) != 1
        or not isinstance(assignment.targets[0], ast.Name)
        or assignment.targets[0].id != "tools"
    ):
        raise ValueError("unexpected inventory assignment")
    if not isinstance(returned, ast.Return) or not isinstance(returned.value, ast.Name):
        raise ValueError("tool_definitions must end with return tools")
    if returned.value.id != "tools":
        raise ValueError("tool_definitions must end with return tools")

    groups = {"base": _inventory_collection_names(assignment.value)}
    expected_conditions = (
        ("remote_scan_enabled", "remote", "append"),
        ("trust_read_enabled", "trust_read", "append"),
        ("trust_mutation_enabled", "trust_mutation", "extend"),
    )
    for statement, (helper, group, method) in zip(conditions, expected_conditions, strict=True):
        groups[group] = _parse_inventory_condition(statement, helper, method)
    for (helper, _group, _method), flag in zip(expected_conditions, OPTIONAL_FLAGS, strict=True):
        _validate_enablement_helper(module, helper, flag)
    return groups


def _parse_inventory_condition(statement: ast.stmt, helper: str, method: str) -> tuple[str, ...]:
    if not isinstance(statement, ast.If) or statement.orelse:
        raise ValueError("unexpected inventory condition")
    if not isinstance(statement.test, ast.Call) or statement.test.args or statement.test.keywords:
        raise ValueError("dynamic inventory condition")
    if not isinstance(statement.test.func, ast.Name) or statement.test.func.id != helper:
        raise ValueError("unexpected inventory condition")
    if len(statement.body) != 1 or not isinstance(statement.body[0], ast.Expr):
        raise ValueError("unexpected inventory condition body")
    call = statement.body[0].value
    if not isinstance(call, ast.Call) or len(call.args) != 1 or call.keywords:
        raise ValueError("unexpected inventory mutation")
    if not isinstance(call.func, ast.Attribute) or call.func.attr != method:
        raise ValueError("unexpected inventory mutation")
    if not isinstance(call.func.value, ast.Name) or call.func.value.id != "tools":
        raise ValueError("unexpected inventory mutation")
    argument = call.args[0]
    if method == "append":
        return (_inventory_dict_name(argument),)
    return _inventory_collection_names(argument)


def _inventory_collection_names(node: ast.AST) -> tuple[str, ...]:
    if not isinstance(node, ast.List):
        raise ValueError("inventory collection must be a literal list")
    names = [_inventory_dict_name(item) for item in node.elts]
    if not names or len(names) != len(set(names)):
        raise ValueError("missing or duplicate tool names")
    return tuple(names)


def _inventory_dict_name(node: ast.AST) -> str:
    if not isinstance(node, ast.Dict):
        raise ValueError("inventory item must be a dictionary literal")
    _validate_inventory_literal(node)
    names: list[str] = []
    for key, value in zip(node.keys, node.values, strict=True):
        if isinstance(key, ast.Constant) and key.value == "name":
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                raise ValueError("dynamic tool name")
            names.append(value.value)
    if len(names) != 1:
        raise ValueError("inventory item must have one literal name")
    return names[0]


def _validate_inventory_literal(node: ast.AST) -> None:
    if isinstance(node, ast.Constant):
        return
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        return
    if isinstance(node, (ast.List, ast.Tuple)):
        for item in node.elts:
            _validate_inventory_literal(item)
        return
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                raise ValueError("inventory dictionary unpacking is not allowed")
            _validate_inventory_literal(key)
            _validate_inventory_literal(value)
        return
    raise ValueError("dynamic inventory literal expression")


def _validate_enablement_helper(module: ast.Module, name: str, flag: str) -> None:
    functions = [
        node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if len(functions) != 1:
        raise ValueError("enablement helper must be unique")
    if _recursive_binding_count(module, name) != 1:
        raise ValueError("enablement helper must not be rebound")
    function = functions[0]
    if isinstance(function, ast.AsyncFunctionDef):
        raise ValueError("enablement helper must be synchronous")
    if function.decorator_list or function.args.args or function.args.posonlyargs or function.args.kwonlyargs:
        raise ValueError("unexpected enablement helper signature")
    if function.args.vararg or function.args.kwarg or len(function.body) != 1:
        raise ValueError("unexpected enablement helper signature")
    statement = function.body[0]
    if not isinstance(statement, ast.Return):
        raise ValueError("enablement helper must contain one return")
    expected = ast.parse(f'os.environ.get("{flag}") == "1"', mode="eval").body
    if ast.dump(statement.value, include_attributes=False) != ast.dump(expected, include_attributes=False):
        raise ValueError("enablement helper semantics drifted")


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
    if github_repo is not None and not _valid_repository(github_repo):
        return ReleaseCheck(
            "options.external",
            "FAIL",
            "The GitHub repository must use exact owner/name syntax.",
            "Pass a public GitHub repository as `--github-repo OWNER/NAME`.",
        )
    if merged_branch is not None and not _valid_branch(merged_branch):
        return ReleaseCheck(
            "options.external",
            "FAIL",
            "The merged branch must be a non-empty canonical Git branch name.",
            "Pass the exact merged branch name without ref syntax, whitespace, or invalid Git characters.",
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
    arguments = list(argv)
    if not arguments or not Path(arguments[0]).is_absolute():
        raise ValueError("Git subprocesses require a pinned absolute executable")
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith("GIT_")
    }
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        arguments,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


def _github_fetch(path: str) -> tuple[int, Mapping[str, Any] | None]:
    url = f"https://api.github.com{path}"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "codex-preflight-release-verify"},
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            if urllib.parse.urlparse(response.geturl()).hostname != "api.github.com":
                raise OSError("unexpected GitHub API redirect")
            body = response.read(MAX_GITHUB_RESPONSE_SIZE + 1)
            if len(body) > MAX_GITHUB_RESPONSE_SIZE:
                raise OSError("GitHub API response exceeded the safety limit")
            payload = json.loads(body.decode("utf-8"))
            return response.status, payload if isinstance(payload, dict) else None
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return 404, None
        raise OSError("GitHub API request failed") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OSError("GitHub API response was unavailable") from error


def _read_pyproject_version(data: bytes) -> str:
    return str(tomllib.loads(data.decode("utf-8"))["project"]["version"])


def _read_init_version(data: bytes) -> str:
    module = ast.parse(data.decode("utf-8"))
    _validate_version_module_ast(module)
    _reject_dynamic_namespace_mutation(module, protected_attributes=frozenset({"__version__"}))
    if _recursive_binding_count(module, "__version__") != 1:
        raise ValueError("version must have one assignment")
    bindings = [statement for statement in module.body if _statement_binds_name(statement, "__version__")]
    if len(bindings) != 1 or not isinstance(bindings[0], ast.Assign):
        raise ValueError("version must have one top-level assignment")
    assignment = bindings[0]
    if len(assignment.targets) != 1 or not isinstance(assignment.targets[0], ast.Name):
        raise ValueError("version assignment must be simple")
    value = assignment.value
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        raise ValueError("version assignment must be a literal string")
    return value.value


def _validate_version_module_ast(module: ast.Module) -> None:
    for statement in module.body:
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
        ):
            raise ValueError("version modules allow only static literal assignments")
        _validate_static_literal(statement.value)


def _validate_static_literal(node: ast.AST) -> None:
    if isinstance(node, ast.Constant):
        return
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for item in node.elts:
            _validate_static_literal(item)
        return
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                raise ValueError("literal dictionary unpacking is not allowed")
            _validate_static_literal(key)
            _validate_static_literal(value)
        return
    raise ValueError("version module assignment must be a static literal")


def _valid_repository(value: str) -> bool:
    parts = value.split("/")
    if len(parts) != 2:
        return False
    owner, repository = parts
    return (
        1 <= len(owner) <= 39
        and 1 <= len(repository) <= 100
        and owner not in {".", ".."}
        and repository not in {".", ".."}
        and _REPOSITORY_COMPONENT.fullmatch(owner) is not None
        and _REPOSITORY_COMPONENT.fullmatch(repository) is not None
    )


def _valid_branch(value: str) -> bool:
    if not value or value != value.strip() or len(value) > 255:
        return False
    if value.startswith("-"):
        return False
    if value in {"@", ".", ".."} or value.startswith(("/", ".")) or value.endswith(("/", ".")):
        return False
    if "//" in value or ".." in value or "@{" in value:
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    if any(character in " ~^:?*[\\" for character in value):
        return False
    return all(
        component and not component.startswith(".") and not component.endswith(".lock")
        for component in value.split("/")
    )


def _path_is_within(candidate: Path, container: Path) -> bool:
    try:
        common = os.path.commonpath((str(candidate), str(container)))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(str(container))


def _recursive_binding_count(module: ast.Module, name: str) -> int:
    count = 0
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            count += 1
        elif isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del)):
            count += 1
        elif isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) == name:
            count += 1
    return count


def _reject_dynamic_namespace_mutation(
    module: ast.Module,
    *,
    protect_os: bool = False,
    protected_attributes: frozenset[str] = frozenset(),
) -> None:
    if protect_os:
        os_imports = [
            alias
            for statement in module.body
            if isinstance(statement, ast.Import)
            for alias in statement.names
            if alias.name == "os" and alias.asname is None
        ]
        if len(os_imports) != 1 or _recursive_binding_count(module, "os") != 1:
            raise ValueError("os dependency must have one direct import")
        if any(
            isinstance(node, ast.ImportFrom) and node.module == "os"
            or isinstance(node, ast.alias) and node.name == "os" and node.asname is not None
            for node in ast.walk(module)
        ):
            raise ValueError("os dependency aliases are not allowed")

    for node in ast.walk(module):
        if isinstance(node, ast.Name) and node.id in _DYNAMIC_NAMESPACE_NAMES | {"__builtins__"}:
            raise ValueError("dynamic namespace access is not allowed")
        if isinstance(node, ast.alias) and node.name in {"builtins", "importlib"}:
            raise ValueError("dynamic module namespace access is not allowed")
        if (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and node.module.split(".", 1)[0] in {"builtins", "importlib"}
        ):
            raise ValueError("dynamic module namespace access is not allowed")
        if isinstance(node, ast.Attribute) and node.attr in {"__dict__", "__globals__"}:
            raise ValueError("dynamic namespace attributes are not allowed")
        if isinstance(node, ast.Attribute) and node.attr in {"__delattr__", "__setattr__"}:
            raise ValueError("dynamic attribute mutation is not allowed")
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.attr in protected_attributes
        ):
            raise ValueError("indirect protected-symbol mutation is not allowed")
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "modules"
            and isinstance(node.value, ast.Name)
            and node.value.id == "sys"
        ):
            raise ValueError("sys.modules namespace access is not allowed")
        if protect_os and isinstance(node, (ast.Attribute, ast.Subscript)):
            if isinstance(node.ctx, (ast.Store, ast.Del)) and _ast_contains_name(node, "os"):
                raise ValueError("os dependency mutation is not allowed")
        if (
            protect_os
            and isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and _is_os_environ(node.value)
        ):
            raise ValueError("environment aliases are not allowed")
        if (
            protect_os
            and isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and (
                node.func.attr in _OS_ENVIRONMENT_MUTATORS
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                or node.func.attr in _MAPPING_MUTATION_METHODS
                and _is_os_environ(node.func.value)
            )
        ):
            raise ValueError("environment mutation is not allowed")


def _ast_contains_name(node: ast.AST, name: str) -> bool:
    return any(isinstance(item, ast.Name) and item.id == name for item in ast.walk(node))


def _is_os_environ(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    )


def _statement_binds_name(statement: ast.stmt, name: str) -> bool:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return statement.name == name
    if isinstance(statement, ast.Assign):
        return any(_target_binds_name(target, name) for target in statement.targets)
    if isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        return _target_binds_name(statement.target, name)
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        return any((alias.asname or alias.name.split(".")[0]) == name for alias in statement.names)
    return False


def _target_binds_name(target: ast.AST, name: str) -> bool:
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_binds_name(item, name) for item in target.elts)
    if isinstance(target, ast.Starred):
        return _target_binds_name(target.value, name)
    return False


def _read_manifest_version(data: bytes) -> str:
    return str(json.loads(data.decode("utf-8"))["version"])


def _snapshot_text(snapshot: FileSnapshot, name: str) -> str:
    return snapshot[name].decode("utf-8")


def _read_bytes(path: Path) -> bytes:
    with open_regular_file_nofollow(path) as handle:
        data = handle.read(MAX_DIAGNOSTIC_FILE_SIZE + 1)
    if len(data) > MAX_DIAGNOSTIC_FILE_SIZE:
        raise SafePathError("The file exceeds its safety limit.")
    return data
