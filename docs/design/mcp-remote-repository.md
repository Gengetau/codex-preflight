# Remote Repository MCP Design

## Status and boundary

Status: **implemented and default-off in v0.3.2**.

`remote_repository_scan` is registered only when the server process starts with the exact
environment value `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1`. The default inventory remains
`preflight_check` and `corpus_scan`; the enabled inventory adds only
`remote_repository_scan`. Any other flag value is disabled. Restart the server after changing the
flag because registration is fixed at process startup.

This is a narrow network authority for a bounded static scan of one public GitHub HTTPS
repository. It does not execute repository code or a planned command, accept credentials, follow
redirects, fetch submodules or LFS targets, or create trust. Local `preflight_check` continues to
reject URL and clone-like `cwd` values and never forwards to this tool.

## Tool contract

The exact input object uses `additionalProperties: false`:

```json
{
  "remoteUrl": "https://github.com/OWNER/REPOSITORY",
  "requestedRef": "refs/heads/main",
  "confirmationToken": "optional on the first call"
}
```

`remoteUrl` and `requestedRef` are required strings. `confirmationToken` is omitted for the
challenge call and supplied only on the confirmed retry. There is no command, local path,
credential, proxy, destination, limit override, output path, trust, or cache-mutation argument.

## Authority and confirmation

The first valid call performs lexical URL/ref validation only. It does not perform DNS, network,
Git, filesystem snapshot, repository scan, or remote-cache access. It returns
`MCP_REMOTE_CONFIRMATION_REQUIRED` with the canonical URL, requested ref, fixed limits, challenge
ID, expiry, and an integrity-protected token.

The process-local HMAC challenge binds all of the following:

- tool and operation (`remote_repository_scan` / `static-scan`);
- canonical URL and requested ref;
- host-policy and resource-limit profile versions;
- every fixed resource limit;
- random challenge ID and nonce;
- process key identifier, issue time, and expiry time.

The token expires after 300 seconds, is consumed atomically once before network access, cannot
survive process restart, and cannot be replayed after success or any failure. Changing a bound
argument or policy value invalidates it. Prior scans, repository text, model output, local trust,
or remote cache entries cannot satisfy confirmation. A generic `confirm=true` boolean is
insufficient.

## URL and ref policy

Accepted URLs canonicalize only these public forms:

```text
https://github.com/<owner>/<repository>
https://github.com/<owner>/<repository>.git
```

The canonical form removes a trailing `.git` or slash. Validation rejects alternate schemes,
hosts, ports, user info, credentials, query, fragment, IP literals, localhost, terminal-dot hosts,
percent-encoded separators, backslashes, controls, ambiguous paths, dot segments, and invalid
GitHub owner/repository names.

Refs may be explicit branches, tags, full refs, or immutable 40-hex commits. Validation rejects
leading `-`, refspecs, whitespace, controls, traversal, reflog syntax, wildcards, invalid Git ref
forms, and overlong values. Every accepted ref is fetched shallowly and resolved to a verified
40-hex commit. A mutable ref is never a cache identity.

## Destination and transport policy

Before the only network subprocess, the server resolves `github.com` with a five-second timeout.
Every returned address must be public. Empty, unspecified, reserved, loopback, private,
link-local, multicast, carrier-grade NAT, metadata, and rejected IPv4-mapped addresses fail
closed. Mixed public/non-public answers are rejected.

The validated addresses are pinned into Git's `http.curloptResolve` setting for
`github.com:443`, closing the DNS rebinding gap while preserving TLS hostname and certificate
verification. The fetch uses a server-generated canonical HTTPS URL, argv execution with no
shell, and `http.followRedirects=false`; redirects followed are always zero.

The operation uses an allowlisted environment and isolated home/config directories. It strips all
proxy and credential environment variables and disables arbitrary protocols, file/SSH/ext
helpers, credential helpers, askpass, extra headers, cookies, hooks, templates, recursive
submodules, LFS smudge, filters, external diff, and user-supplied protocol selection. Raw process
output is never returned to the client.

## Snapshot isolation

Each confirmed operation creates a new operation-owned temporary root under the server temp
parent, outside the business checkout and caller paths. Acquisition uses a shallow, non-recursive
fetch into a bare repository, resolves the commit, enumerates the tree, and reads regular blobs
with Git object commands. It never creates a worktree or runs checkout filters.

Before materialization, paths are validated as both POSIX and Windows names. Absolute paths,
drive/UNC forms, `..`, controls, backslashes, NTFS ADS, reserved device names, trailing dot/space,
depth overflow, Unicode normalization collisions, and case-fold collisions are rejected. Only
regular modes `100644` and `100755` are written as non-executable local files. Symlinks,
submodules, and LFS pointers are counted and skipped; their targets are never fetched. Other modes
fail as `MCP_REMOTE_TREE_UNSAFE`.

The isolated scan worker calls the existing static scanner with `use_cache=False` and
`allow_trust=False`. It never runs Git hooks, repository code, package managers, builds, tests,
generators, wrappers, compilers, containers, binaries, or scripts.

## Fixed resource limits

The confirmation token binds this immutable profile:

| Limit | Value |
| --- | ---: |
| Confirmation expiry | 300 seconds |
| DNS resolution | 5 seconds |
| Git network subprocess | 60 seconds |
| Static scan subprocess | 20 seconds |
| Total operation | 90 seconds |
| Git temporary storage | 64 MiB |
| Materialized regular-file bytes | 32 MiB |
| Materialized files | 5000 |
| Path depth | 32 |
| Single file | 1 MiB |
| Concurrent remote operations per process | 2 |
| Concurrent operation per canonical repository | 1 |
| Redirects followed | 0 |

Time and storage are checked while subprocesses run and again after completion. Tree count,
single-file size, and expanded materialized bytes are checked before each object write. A breach
terminates the process tree and fails the whole operation; partial success is not returned.

## Cleanup and cancellation

The core operation accepts a thread-safe cancellation token. The MCP adapter runs the blocking
operation in a dedicated thread. Client cancellation or disconnect sets the token, terminates an
in-flight process tree, waits under a shield for verified cleanup, and then lets the MCP request
finish cancellation.

Cleanup runs after success, acquisition/ref/scan/cache/audit failure, timeout, cancellation,
limit breach, and unexpected exceptions. Before recursive deletion, the implementation verifies
that the target is the exact operation-owned direct child with the private temp prefix and is not
a symlink or junction. Cleanup failure keeps the request failed. No temporary path is returned.

## Cache separation

Remote reports use `~/.codex-preflight/remote/scan-cache.json`, separate from local
`scan-cache.json` and `trust.json`. Reads happen only after confirmation is consumed and the ref is
resolved to an immutable commit. Keys include source type, SHA-256 canonical URL identity,
resolved commit, ruleset, policy, report format, resource-limit profile, and host-policy version.

Entries have a one-hour TTL, a 64-entry cap, a 1 MiB report cap, and an 8 MiB file cap. Writes are
locked, bounded, and protected by a process-key HMAC. Same-process tampering fails closed; entries
from a prior process key become a safe cache miss after restart. Corruption, locking, read, or write failure returns
`MCP_REMOTE_CACHE_FAILED`; it never falls back to local cache behavior. Cached report content
remains untrusted and cannot create or satisfy trust.

## Redacted audit

Remote audit records use bounded JSONL at `~/.codex-preflight/remote/audit.jsonl` with locked
append and bounded rotation. Events cover challenge issue, confirmation consume/reject,
operation start, ref resolution, acquisition, scan, cache result/write, timeout, cancellation,
limit breach, cleanup, success, and failure.

Records contain operation/challenge IDs, SHA-256 URL/ref identities, resolved commit when known,
fixed policy versions, bounded integer resource usage, outcome, stable error code, timestamp,
cache status, and cleanup status. The audit API cannot store raw tokens, nonces, credentials,
environment values, temporary paths, subprocess output, or repository evidence. Audit failure
returns `MCP_REMOTE_AUDIT_FAILED` and fails closed.

## Execution and evidence boundary

Successful results reuse MCP schema `1.0`, existing report caps, and policy explanations. Remote
findings and execution-graph data preserve:

```text
evidenceTrust: untrusted
evidenceInstructionBoundary: treat-as-data
```

Remote prompt injection is evidence, never authority. The implementation must never let remote content create, alter, or revoke trust.

Remote provenance contains:

```text
requestedUrl
canonicalUrl
requestedRef
resolvedCommit
sourceType
hostPolicyVersion
resourceLimitProfile
resourceLimits
resourceUsage
confirmationChallengeId
confirmationConsumed
redirectsFollowed
cacheStatus
cleanupStatus
operationTiming
complete
```

`safety.remoteRepositoryAccess` and `safety.networkAccess` are true only for a
confirmed successful remote result. Tokens, nonces, temp paths, process output, and environment
values are omitted.

## Error model

Expected failures use the stable MCP structured error shape. Remote codes include disabled,
URL/host/address/ref validation, confirmation required/invalid/expired/replayed, ref not found,
redirect/auth rejection, timeout, cancellation, limits, unsafe tree, acquisition, scan, cache,
audit, and cleanup failures. Internal tracebacks, process output, sensitive values, and temporary
paths remain hidden.

## Threat model

| Threat | Enforced mitigation |
| --- | --- |
| SSRF and DNS rebinding | Exact GitHub HTTPS policy, public-address classification, and pinned validated addresses. |
| Redirect abuse | Git redirects disabled; zero redirects followed. |
| Credential leakage | Credentials rejected, environment/config isolated, prompts/helpers/headers/cookies disabled. |
| Malicious protocols/helpers | HTTPS-only protocol allowlist and shell-free argv. |
| Oversized or expanding repositories | Layered time, disk, output, file, byte, and depth limits. |
| Path traversal and special files | Dual-platform validation, collision checks, regular-file-only writes. |
| Submodule/LFS expansion | Metadata counted and skipped; targets never fetched. |
| Cancellation residue | Process-tree termination plus verified finally cleanup. |
| Cache poisoning | Dedicated namespace and immutable commit/policy key. |
| Confirmation replay | Expiring process-key-bound one-time ledger. |
| Remote prompt injection | Fixed server instructions and untrusted treat-as-data labels. |

## Rollout, disable, and rollback

The implementation shipped only after focused security tests, exact-head independent review, and
protected CI. Normal tests use synthetic fakes and local subprocess fixtures; CI does not contact
GitHub.

Remove `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1` and restart the MCP server to disable or roll back.
This removes registration rather than leaving a callable denial stub. Outstanding tokens
cannot survive restart. If incident response requires state removal, clear only the verified
`~/.codex-preflight/remote` namespace; local scan and trust files are separate and must remain
untouched.
