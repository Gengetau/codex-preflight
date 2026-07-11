from __future__ import annotations

import pytest

from codex_preflight_mcp.remote_policy import (
    RemotePolicyError,
    ResourceLimits,
    validate_github_repository_url,
    validate_requested_ref,
)


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        ("https://github.com/Owner/Repo", "https://github.com/Owner/Repo"),
        ("https://github.com/Owner/Repo.git", "https://github.com/Owner/Repo"),
        ("https://github.com/Owner/Repo/", "https://github.com/Owner/Repo"),
    ],
)
def test_github_repository_url_canonicalization(value: str, canonical: str) -> None:
    target = validate_github_repository_url(value)

    assert target.requested_url == value
    assert target.canonical_url == canonical
    assert target.owner == "Owner"
    assert target.repository == "Repo"


@pytest.mark.parametrize(
    "value",
    [
        "http://github.com/owner/repo",
        "ssh://github.com/owner/repo",
        "git://github.com/owner/repo",
        "file:///owner/repo",
        "git@github.com:owner/repo",
        "github.com/owner/repo",
        "https://user@github.com/owner/repo",
        "https://github.com:444/owner/repo",
        "https://127.0.0.1/owner/repo",
        "https://localhost/owner/repo",
        "https://github.com./owner/repo",
        "https://example.com/owner/repo",
        "https://github.com/owner",
        "https://github.com/owner/repo/extra",
        "https://github.com/owner/../repo",
        "https://github.com/owner/repo?ref=main",
        "https://github.com/owner/repo?",
        "https://github.com/owner/repo#main",
        "https://github.com/owner/repo#",
        "https://github.com/owner%2frepo/name",
        "https:\\github.com\\owner\\repo",
        "https://github.com/-owner/repo",
        "https://github.com/owner-/repo",
        "https://github.com/owner/.git",
        "https://github.com/owner/repo..git",
    ],
)
def test_github_repository_url_rejects_noncanonical_and_unsafe_forms(value: str) -> None:
    with pytest.raises(RemotePolicyError) as caught:
        validate_github_repository_url(value)

    assert caught.value.field == "remoteUrl"


@pytest.mark.parametrize(
    "value",
    [
        "main",
        "v0.3.2",
        "refs/heads/main",
        "refs/tags/v0.3.2",
        "0123456789abcdef0123456789abcdef01234567",
    ],
)
def test_requested_ref_accepts_explicit_safe_forms(value: str) -> None:
    assert validate_requested_ref(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "-main",
        "+refs/heads/main",
        "@",
        "HEAD",
        "FETCH_HEAD",
        "refs/heads/*",
        "refs/heads/main..other",
        "refs/heads/main@{1}",
        "refs/heads/main:refs/heads/other",
        "refs/heads/../main",
        "refs\\heads\\main",
        "main branch",
        "main\nother",
    ],
)
def test_requested_ref_rejects_injection_and_ambiguous_forms(value: str) -> None:
    with pytest.raises(RemotePolicyError) as caught:
        validate_requested_ref(value)

    assert caught.value.field == "requestedRef"


def test_resource_profile_has_exact_authorized_limits() -> None:
    assert ResourceLimits().to_dict() == {
        "confirmationExpirySeconds": 300,
        "dnsTimeoutSeconds": 5,
        "gitTimeoutSeconds": 60,
        "scanTimeoutSeconds": 20,
        "totalTimeoutSeconds": 90,
        "maxGitBytes": 64 * 1024 * 1024,
        "maxMaterializedBytes": 32 * 1024 * 1024,
        "maxFiles": 5000,
        "maxPathDepth": 32,
        "maxSingleFileBytes": 1024 * 1024,
        "maxConcurrentOperations": 2,
        "maxConcurrentPerRepository": 1,
        "maxRedirects": 0,
    }
