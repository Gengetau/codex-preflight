from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$")
_FULL_COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_INVALID_REF = re.compile(r"[\\:*?\[\]~^\s]")


@dataclass(frozen=True)
class RemotePolicyError(ValueError):
    code: str
    message: str
    field: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class RemoteTarget:
    requested_url: str
    canonical_url: str
    owner: str
    repository: str


@dataclass(frozen=True)
class ResourceLimits:
    confirmation_expiry_seconds: int = 300
    dns_timeout_seconds: int = 5
    git_timeout_seconds: int = 60
    scan_timeout_seconds: int = 20
    total_timeout_seconds: int = 90
    max_git_bytes: int = 64 * 1024 * 1024
    max_materialized_bytes: int = 32 * 1024 * 1024
    max_files: int = 5000
    max_path_depth: int = 32
    max_single_file_bytes: int = 1024 * 1024
    max_concurrent_operations: int = 2
    max_concurrent_per_repository: int = 1
    max_redirects: int = 0

    def to_dict(self) -> dict[str, int]:
        values = asdict(self)
        return {
            "confirmationExpirySeconds": values["confirmation_expiry_seconds"],
            "dnsTimeoutSeconds": values["dns_timeout_seconds"],
            "gitTimeoutSeconds": values["git_timeout_seconds"],
            "scanTimeoutSeconds": values["scan_timeout_seconds"],
            "totalTimeoutSeconds": values["total_timeout_seconds"],
            "maxGitBytes": values["max_git_bytes"],
            "maxMaterializedBytes": values["max_materialized_bytes"],
            "maxFiles": values["max_files"],
            "maxPathDepth": values["max_path_depth"],
            "maxSingleFileBytes": values["max_single_file_bytes"],
            "maxConcurrentOperations": values["max_concurrent_operations"],
            "maxConcurrentPerRepository": values["max_concurrent_per_repository"],
            "maxRedirects": values["max_redirects"],
        }


def validate_github_repository_url(value: str) -> RemoteTarget:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _url_error()
    if _CONTROL.search(value) or "\\" in value or "%" in value:
        raise _url_error()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise _url_error() from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or parsed.netloc.lower() != "github.com"
    ):
        raise _url_error()
    path = parsed.path[:-1] if parsed.path.endswith("/") else parsed.path
    segments = path.split("/")
    if len(segments) != 3 or segments[0] != "":
        raise _url_error()
    owner, repository = segments[1:]
    if repository.endswith(".git"):
        repository = repository[:-4]
    if (
        not _OWNER.fullmatch(owner)
        or "--" in owner
        or not _REPOSITORY.fullmatch(repository)
        or repository in {".", ".."}
        or repository.endswith((".", "-"))
    ):
        raise _url_error()
    return RemoteTarget(
        requested_url=value,
        canonical_url=f"https://github.com/{owner}/{repository}",
        owner=owner,
        repository=repository,
    )


def validate_requested_ref(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 255:
        raise _ref_error()
    if _FULL_COMMIT.fullmatch(value):
        return value.lower()
    if (
        value.startswith(("-", "/", "."))
        or value.endswith(("/", "."))
        or _CONTROL.search(value)
        or _INVALID_REF.search(value)
        or ".." in value
        or "@{" in value
        or "//" in value
        or any(part.startswith(".") or part.endswith(".lock") for part in value.split("/"))
    ):
        raise _ref_error()
    return value


def _url_error() -> RemotePolicyError:
    return RemotePolicyError(
        "MCP_REMOTE_URL_INVALID",
        "remoteUrl must be a canonical public GitHub HTTPS repository URL without credentials or ports.",
        "remoteUrl",
    )


def _ref_error() -> RemotePolicyError:
    return RemotePolicyError(
        "MCP_REMOTE_REF_INVALID",
        "requestedRef must be an explicit safe branch, tag, full ref, or 40-hex commit.",
        "requestedRef",
    )
