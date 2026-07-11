from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from codex_preflight_mcp.remote_policy import RemoteTarget, ResourceLimits

_OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")
_TEMP_PREFIX = "cpf-r-"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_GIT_HARDENING = [
    "-c",
    "protocol.ext.allow=never",
    "-c",
    "protocol.file.allow=never",
    "-c",
    "protocol.ssh.allow=never",
    "-c",
    "http.followRedirects=false",
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
    "-c",
    "submodule.recurse=false",
    "-c",
    "filter.lfs.smudge=",
    "-c",
    "filter.lfs.process=",
    "-c",
    "filter.lfs.required=false",
    "-c",
    "diff.external=",
]


@dataclass
class RemoteOperationError(RuntimeError):
    code: str
    message: str
    retryable: bool = False

    def __post_init__(self) -> None:
        RuntimeError.__init__(self, self.message)

    def __str__(self) -> str:
        return self.message


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


CommandRunner = Callable[..., bytes]
Scanner = Callable[[Path, dict[str, object], int, CancellationToken], dict[str, Any]]
Resolver = Callable[[str, int], tuple[str, ...]]
Cleanup = Callable[[Path, Path], None]


@dataclass(frozen=True)
class RemoteDependencies:
    resolver: Resolver = None  # type: ignore[assignment]
    command_runner: CommandRunner = None  # type: ignore[assignment]
    scanner: Scanner = None  # type: ignore[assignment]
    cleanup: Cleanup = None  # type: ignore[assignment]
    temp_parent: Path | None = None
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        object.__setattr__(self, "resolver", self.resolver or resolve_public_addresses)
        object.__setattr__(self, "command_runner", self.command_runner or run_command)
        object.__setattr__(self, "scanner", self.scanner or run_scan_worker)
        object.__setattr__(self, "cleanup", self.cleanup or safe_cleanup)


_GLOBAL_OPERATION_SLOTS = threading.BoundedSemaphore(2)
_REPOSITORY_LOCKS: dict[str, threading.Lock] = {}
_REPOSITORY_LOCKS_GUARD = threading.Lock()


def resolve_public_addresses(
    host: str,
    timeout: int,
    *,
    getaddrinfo: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
) -> tuple[str, ...]:
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(
        getaddrinfo,
        host,
        443,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    try:
        answers = future.result(timeout=timeout)
    except FutureTimeoutError as error:
        raise RemoteOperationError("MCP_REMOTE_TIMEOUT", "GitHub DNS resolution timed out.", True) from error
    except OSError as error:
        raise RemoteOperationError(
            "MCP_REMOTE_ADDRESS_NOT_ALLOWED",
            "GitHub DNS resolution failed closed.",
            True,
        ) from error
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    addresses: list[str] = []
    for answer in answers:
        try:
            address = str(answer[4][0])
            parsed = ipaddress.ip_address(address)
        except (IndexError, TypeError, ValueError) as error:
            raise _address_error() from error
        effective = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
        candidate = effective or parsed
        if (
            not candidate.is_global
            or candidate.is_multicast
            or candidate.is_reserved
            or candidate.is_unspecified
            or candidate.is_loopback
            or candidate.is_link_local
            or candidate.is_private
        ):
            raise _address_error()
        normalized = str(parsed)
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise _address_error()
    return tuple(addresses)


def run_remote_operation(
    *,
    target: RemoteTarget,
    requested_ref: str,
    challenge_id: str,
    limits: ResourceLimits,
    dependencies: RemoteDependencies | None = None,
    cancellation: CancellationToken | None = None,
) -> dict[str, Any]:
    deps = dependencies or RemoteDependencies()
    token = cancellation or CancellationToken()
    _check_cancelled(token)
    started = deps.clock()
    deadline = started + limits.total_timeout_seconds
    with _operation_slot(target.canonical_url):
        parent = (deps.temp_parent or Path(tempfile.gettempdir())).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        operation_root = _create_operation_root(parent)
        result: dict[str, Any] | None = None
        pending_error: BaseException | None = None
        try:
            result = _execute_operation(
                target=target,
                requested_ref=requested_ref,
                challenge_id=challenge_id,
                limits=limits,
                deps=deps,
                cancellation=token,
                operation_root=operation_root,
                deadline=deadline,
                started=started,
            )
        except BaseException as error:
            pending_error = error
        try:
            deps.cleanup(operation_root, parent)
        except BaseException as cleanup_error:
            raise RemoteOperationError(
                "MCP_REMOTE_CLEANUP_FAILED",
                "The remote operation could not verify complete temporary cleanup.",
            ) from cleanup_error
        if pending_error is not None:
            raise pending_error
        if result is None:
            raise RemoteOperationError("MCP_REMOTE_SCAN_FAILED", "The remote scan produced no result.")
        result["remoteProvenance"]["cleanupStatus"] = "removed"
        result["remoteProvenance"]["operationTiming"]["totalMilliseconds"] = int(
            (deps.clock() - started) * 1000
        )
        return result


def _execute_operation(
    *,
    target: RemoteTarget,
    requested_ref: str,
    challenge_id: str,
    limits: ResourceLimits,
    deps: RemoteDependencies,
    cancellation: CancellationToken,
    operation_root: Path,
    deadline: float,
    started: float,
) -> dict[str, Any]:
    _check_deadline(deps.clock, deadline)
    bare_repo = operation_root / "objects.git"
    scan_root = operation_root / "scan"
    hooks = operation_root / "empty-hooks"
    templates = operation_root / "empty-templates"
    for directory in (scan_root, hooks, templates):
        directory.mkdir()
    environment = git_environment(operation_root)
    git = ["git", *_GIT_HARDENING, "-c", f"core.hooksPath={hooks}", "-c", f"init.templateDir={templates}"]
    deps.command_runner(
        [*git, "init", "--bare", str(bare_repo)],
        cwd=None,
        env=environment,
        timeout=min(limits.git_timeout_seconds, _remaining(deps.clock, deadline)),
        monitor_root=operation_root,
        limits=limits,
        cancellation=cancellation,
    )
    _check_deadline(deps.clock, deadline)
    deps.resolver("github.com", limits.dns_timeout_seconds)
    deps.command_runner(
        [
            *git,
            "-C",
            str(bare_repo),
            "fetch",
            "--depth=1",
            "--no-tags",
            "--recurse-submodules=no",
            f"{target.canonical_url}.git",
            requested_ref,
        ],
        cwd=None,
        env=environment,
        timeout=min(limits.git_timeout_seconds, _remaining(deps.clock, deadline)),
        monitor_root=operation_root,
        limits=limits,
        cancellation=cancellation,
    )
    resolved_commit = deps.command_runner(
        [*git, "-C", str(bare_repo), "rev-parse", "--verify", "FETCH_HEAD^{commit}"],
        cwd=None,
        env=environment,
        timeout=min(limits.git_timeout_seconds, _remaining(deps.clock, deadline)),
        monitor_root=operation_root,
        limits=limits,
        cancellation=cancellation,
    ).decode("ascii", "strict").strip().lower()
    if not _OBJECT_ID.fullmatch(resolved_commit):
        raise RemoteOperationError(
            "MCP_REMOTE_REF_NOT_FOUND",
            "The requested ref did not resolve to an immutable commit.",
        )
    if _OBJECT_ID.fullmatch(requested_ref.lower()) and requested_ref.lower() != resolved_commit:
        raise RemoteOperationError(
            "MCP_REMOTE_REF_NOT_FOUND",
            "The requested immutable commit did not match the fetched commit.",
        )
    tree_output = deps.command_runner(
        [*git, "-C", str(bare_repo), "ls-tree", "-r", "-z", "-l", resolved_commit],
        cwd=None,
        env=environment,
        timeout=min(limits.git_timeout_seconds, _remaining(deps.clock, deadline)),
        monitor_root=operation_root,
        limits=limits,
        cancellation=cancellation,
    )
    usage = _materialize_tree(
        tree_output,
        bare_repo=bare_repo,
        scan_root=scan_root,
        git=git,
        environment=environment,
        operation_root=operation_root,
        limits=limits,
        dependencies=deps,
        cancellation=cancellation,
        deadline=deadline,
    )
    _check_deadline(deps.clock, deadline)
    source_metadata: dict[str, object] = {
        "sourceType": "remote",
        "cloneUrl": target.canonical_url,
        "requestedRef": requested_ref,
        "resolvedCommit": resolved_commit,
        "remoteUrl": target.canonical_url,
    }
    report = deps.scanner(
        scan_root,
        source_metadata,
        min(limits.scan_timeout_seconds, _remaining(deps.clock, deadline)),
        cancellation,
    )
    if not isinstance(report, dict):
        raise RemoteOperationError("MCP_REMOTE_SCAN_FAILED", "The remote static scan result was invalid.")
    repo = report.setdefault("repo", {})
    if not isinstance(repo, dict):
        raise RemoteOperationError("MCP_REMOTE_SCAN_FAILED", "The remote report repository metadata was invalid.")
    repo.update(
        {
            "path": target.canonical_url,
            "sourceType": "remote",
            "cloneUrl": target.canonical_url,
            "requestedRef": requested_ref,
            "resolvedCommit": resolved_commit,
            "remoteUrl": target.canonical_url,
            "headCommit": resolved_commit,
        }
    )
    git_bytes = directory_size(bare_repo)
    if git_bytes > limits.max_git_bytes:
        raise _limit_error()
    skipped_symlinks = usage.pop("skippedSymlinks")
    skipped_submodules = usage.pop("skippedSubmodules")
    skipped_lfs_pointers = usage.pop("skippedLfsPointers")
    report["remoteProvenance"] = {
        "requestedUrl": target.requested_url,
        "canonicalUrl": target.canonical_url,
        "requestedRef": requested_ref,
        "resolvedCommit": resolved_commit,
        "sourceType": "remote",
        "hostPolicyVersion": "github-public-v1",
        "resourceLimitProfile": "remote-bounded-v1",
        "resourceLimits": limits.to_dict(),
        "resourceUsage": {**usage, "gitBytes": git_bytes},
        "confirmationChallengeId": challenge_id,
        "confirmationConsumed": True,
        "redirectsFollowed": 0,
        "cacheStatus": "not-checked",
        "cleanupStatus": "pending",
        "operationTiming": {"totalMilliseconds": int((deps.clock() - started) * 1000)},
        "complete": True,
        "skippedSymlinks": skipped_symlinks,
        "skippedSubmodules": skipped_submodules,
        "skippedLfsPointers": skipped_lfs_pointers,
    }
    return report


def _materialize_tree(
    tree_output: bytes,
    *,
    bare_repo: Path,
    scan_root: Path,
    git: list[str],
    environment: dict[str, str],
    operation_root: Path,
    limits: ResourceLimits,
    dependencies: RemoteDependencies,
    cancellation: CancellationToken,
    deadline: float,
) -> dict[str, int]:
    records = [record for record in tree_output.split(b"\0") if record]
    if len(records) > limits.max_files:
        raise _limit_error()
    seen: set[str] = set()
    materialized_bytes = 0
    materialized_files = 0
    max_depth = 0
    skipped_symlinks = 0
    skipped_submodules = 0
    skipped_lfs = 0
    for raw_record in records:
        _check_cancelled(cancellation)
        _check_deadline(dependencies.clock, deadline)
        try:
            metadata, raw_path = raw_record.split(b"\t", 1)
            mode, object_type, object_id, raw_size = metadata.decode("ascii").split(" ")
            path_text = raw_path.decode("utf-8", "strict")
        except (UnicodeError, ValueError) as error:
            raise _tree_error() from error
        if not _OBJECT_ID.fullmatch(object_id):
            raise _tree_error()
        relative_path = validate_tree_path(path_text, limits, seen)
        max_depth = max(max_depth, len(relative_path.parts))
        if mode == "160000" and object_type == "commit":
            skipped_submodules += 1
            continue
        if mode == "120000" and object_type == "blob":
            skipped_symlinks += 1
            continue
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise _tree_error()
        try:
            size = int(raw_size)
        except ValueError as error:
            raise _tree_error() from error
        if size < 0 or size > limits.max_single_file_bytes:
            raise _limit_error()
        materialized_bytes += size
        materialized_files += 1
        if materialized_bytes > limits.max_materialized_bytes or materialized_files > limits.max_files:
            raise _limit_error()
        content = dependencies.command_runner(
            [*git, "-C", str(bare_repo), "cat-file", "blob", object_id],
            cwd=None,
            env=environment,
            timeout=min(limits.git_timeout_seconds, _remaining(dependencies.clock, deadline)),
            monitor_root=operation_root,
            limits=limits,
            cancellation=cancellation,
        )
        if len(content) != size:
            raise RemoteOperationError(
                "MCP_REMOTE_ACQUISITION_FAILED",
                "A fetched Git object did not match its declared size.",
            )
        if content.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
            skipped_lfs += 1
            continue
        destination = scan_root.joinpath(*relative_path.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.parent.resolve().is_relative_to(scan_root.resolve()):
            raise _tree_error()
        try:
            with destination.open("xb") as output:
                output.write(content)
            destination.chmod(0o600)
        except OSError as error:
            raise RemoteOperationError(
                "MCP_REMOTE_ACQUISITION_FAILED",
                "A bounded Git object could not be materialized safely.",
            ) from error
    return {
        "materializedBytes": materialized_bytes,
        "materializedFiles": materialized_files,
        "maxPathDepth": max_depth,
        "skippedSymlinks": skipped_symlinks,
        "skippedSubmodules": skipped_submodules,
        "skippedLfsPointers": skipped_lfs,
    }


def validate_tree_path(value: str, limits: ResourceLimits, seen: set[str]) -> PurePosixPath:
    if not value or _CONTROL.search(value) or "\\" in value:
        raise _tree_error()
    path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        raise _tree_error()
    if len(path.parts) > limits.max_path_depth or any(part in {"", ".", ".."} for part in path.parts):
        raise _tree_error()
    for part in path.parts:
        stem = part.split(".", 1)[0].upper()
        if ":" in part or part.endswith((".", " ")) or stem in _WINDOWS_RESERVED:
            raise _tree_error()
    collision_key = unicodedata.normalize("NFC", path.as_posix()).casefold()
    if collision_key in seen:
        raise _tree_error()
    seen.add(collision_key)
    return path


def git_environment(operation_root: Path) -> dict[str, str]:
    environment: dict[str, str] = {}
    for name in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        if value := os.environ.get(name):
            environment[name] = value
    temp = operation_root / "process-temp"
    home = operation_root / "process-home"
    config = operation_root / "process-config"
    for directory in (temp, home, config):
        directory.mkdir(exist_ok=True)
    environment.update(
        {
            "TEMP": str(temp),
            "TMP": str(temp),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(config),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CEILING_DIRECTORIES": str(operation_root),
            "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def run_command(
    args: list[str],
    *,
    cwd: Path | None,
    env: dict[str, str],
    timeout: int,
    monitor_root: Path,
    limits: ResourceLimits,
    cancellation: CancellationToken,
) -> bytes:
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    try:
        process = subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name != "nt",
            creationflags=creationflags,
        )
    except OSError as error:
        raise RemoteOperationError(
            "MCP_REMOTE_ACQUISITION_FAILED",
            "The bounded subprocess could not be started.",
            True,
        ) from error
    started = time.monotonic()
    while True:
        try:
            stdout, stderr = process.communicate(timeout=0.1)
            break
        except subprocess.TimeoutExpired:
            if cancellation.cancelled:
                terminate_process_tree(process)
                raise RemoteOperationError(
                    "MCP_REMOTE_CANCELLED", "The remote operation was cancelled."
                ) from None
            if time.monotonic() - started > timeout:
                terminate_process_tree(process)
                raise RemoteOperationError(
                    "MCP_REMOTE_TIMEOUT", "The bounded subprocess timed out.", True
                ) from None
            if directory_size(monitor_root) > limits.max_git_bytes:
                terminate_process_tree(process)
                raise _limit_error() from None
    if process.returncode != 0:
        raise _classify_subprocess_failure(args, stderr)
    return stdout


def _classify_subprocess_failure(args: list[str], stderr: bytes) -> RemoteOperationError:
    diagnostic = stderr[:65536].lower()
    if "fetch" in args:
        if b"redirect" in diagnostic:
            return RemoteOperationError(
                "MCP_REMOTE_REDIRECT_NOT_ALLOWED",
                "The remote endpoint attempted an unauthorized redirect.",
            )
        if any(
            marker in diagnostic
            for marker in (
                b"authentication",
                b"authorization",
                b"could not read username",
                b"credential",
                b"terminal prompts disabled",
            )
        ):
            return RemoteOperationError(
                "MCP_REMOTE_AUTH_NOT_ALLOWED",
                "The remote endpoint required authentication, which is not authorized.",
            )
        if any(
            marker in diagnostic
            for marker in (b"couldn't find remote ref", b"not our ref", b"remote ref does not exist")
        ):
            return RemoteOperationError(
                "MCP_REMOTE_REF_NOT_FOUND",
                "The requested remote ref was not found.",
            )
    return RemoteOperationError(
        "MCP_REMOTE_ACQUISITION_FAILED",
        "The bounded Git or scan subprocess failed without exposing remote output.",
        True,
    )


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        process.kill()
    except OSError:
        pass


def run_scan_worker(
    scan_root: Path,
    source_metadata: dict[str, object],
    timeout: int,
    cancellation: CancellationToken,
) -> dict[str, Any]:
    operation_root = scan_root.parent
    request_path = operation_root / "scan-request.json"
    result_path = operation_root / "scan-result.json"
    request_path.write_text(
        json.dumps({"scanRoot": str(scan_root), "sourceMetadata": source_metadata}, sort_keys=True),
        encoding="utf-8",
    )
    environment = git_environment(operation_root)
    environment.update(
        {
            "PYTHONPATH": str(Path(__file__).resolve().parent.parent),
            "PYTHONUTF8": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    try:
        run_command(
            [
                sys.executable,
                "-m",
                "codex_preflight_mcp.remote_scan_worker",
                str(request_path),
                str(result_path),
            ],
            cwd=operation_root,
            env=environment,
            timeout=timeout,
            monitor_root=operation_root,
            limits=ResourceLimits(),
            cancellation=cancellation,
        )
    except RemoteOperationError as error:
        if error.code in {
            "MCP_REMOTE_CANCELLED",
            "MCP_REMOTE_LIMIT_EXCEEDED",
            "MCP_REMOTE_TIMEOUT",
        }:
            raise
        raise RemoteOperationError(
            "MCP_REMOTE_SCAN_FAILED",
            "The isolated static scan worker failed without exposing repository output.",
            error.retryable,
        ) from error
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise RemoteOperationError("MCP_REMOTE_SCAN_FAILED", "The static scan worker result was invalid.") from error
    if not isinstance(result, dict):
        raise RemoteOperationError("MCP_REMOTE_SCAN_FAILED", "The static scan worker result was invalid.")
    return result


def safe_cleanup(target: Path, owned_parent: Path) -> None:
    try:
        resolved_parent = owned_parent.resolve(strict=True)
        resolved_target_parent = target.parent.resolve(strict=True)
    except OSError as error:
        raise RemoteOperationError(
            "MCP_REMOTE_CLEANUP_FAILED",
            "The temporary cleanup target could not be verified.",
        ) from error
    if (
        resolved_target_parent != resolved_parent
        or not target.name.startswith(_TEMP_PREFIX)
        or target.is_symlink()
        or bool(getattr(target, "is_junction", lambda: False)())
    ):
        raise RemoteOperationError(
            "MCP_REMOTE_CLEANUP_FAILED",
            "The temporary cleanup target was not owned by this operation.",
        )
    try:
        shutil.rmtree(target)
    except OSError as error:
        raise RemoteOperationError(
            "MCP_REMOTE_CLEANUP_FAILED",
            "The operation-owned temporary directory could not be removed.",
        ) from error
    if os.path.lexists(target):
        raise RemoteOperationError(
            "MCP_REMOTE_CLEANUP_FAILED",
            "The operation-owned temporary directory still exists after cleanup.",
        )


def _create_operation_root(parent: Path) -> Path:
    mode = 0o755 if os.name == "nt" else 0o700
    for _attempt in range(10):
        candidate = parent / f"{_TEMP_PREFIX}{secrets.token_hex(12)}"
        try:
            candidate.mkdir(mode=mode)
        except FileExistsError:
            continue
        except OSError as error:
            raise RemoteOperationError(
                "MCP_REMOTE_ACQUISITION_FAILED",
                "The isolated remote operation directory could not be created.",
            ) from error
        return candidate
    raise RemoteOperationError(
        "MCP_REMOTE_ACQUISITION_FAILED",
        "A unique isolated remote operation directory could not be allocated.",
    )


def directory_size(path: Path) -> int:
    total = 0
    try:
        for item in path.rglob("*"):
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
    except OSError as error:
        raise RemoteOperationError(
            "MCP_REMOTE_ACQUISITION_FAILED",
            "Temporary resource usage could not be measured safely.",
        ) from error
    return total


@contextmanager
def _operation_slot(canonical_url: str):
    if not _GLOBAL_OPERATION_SLOTS.acquire(blocking=False):
        raise _limit_error()
    with _REPOSITORY_LOCKS_GUARD:
        repository_lock = _REPOSITORY_LOCKS.setdefault(canonical_url, threading.Lock())
    if not repository_lock.acquire(blocking=False):
        _GLOBAL_OPERATION_SLOTS.release()
        raise _limit_error()
    try:
        yield
    finally:
        repository_lock.release()
        _GLOBAL_OPERATION_SLOTS.release()


def _remaining(clock: Callable[[], float], deadline: float) -> int:
    remaining = int(deadline - clock())
    if remaining <= 0:
        raise RemoteOperationError("MCP_REMOTE_TIMEOUT", "The total remote operation timed out.", True)
    return remaining


def _check_deadline(clock: Callable[[], float], deadline: float) -> None:
    if clock() > deadline:
        raise RemoteOperationError("MCP_REMOTE_TIMEOUT", "The total remote operation timed out.", True)


def _check_cancelled(cancellation: CancellationToken) -> None:
    if cancellation.cancelled:
        raise RemoteOperationError("MCP_REMOTE_CANCELLED", "The remote operation was cancelled.")


def _address_error() -> RemoteOperationError:
    return RemoteOperationError(
        "MCP_REMOTE_ADDRESS_NOT_ALLOWED",
        "GitHub DNS resolution included a non-public or unsupported address.",
    )


def _limit_error() -> RemoteOperationError:
    return RemoteOperationError(
        "MCP_REMOTE_LIMIT_EXCEEDED",
        "The remote repository exceeded the fixed resource profile.",
    )


def _tree_error() -> RemoteOperationError:
    return RemoteOperationError(
        "MCP_REMOTE_TREE_UNSAFE",
        "The remote Git tree contains an unsafe or ambiguous entry.",
    )
