# Remote Repository MCP Design

## Status and boundary

Status: **design-only and unavailable** in v0.2.5.

This document specifies a possible future `remote_repository_scan` tool. It does not register,
implement, or experimentally hide that tool. The runtime continues to expose exactly
`preflight_check` and `corpus_scan`. A separate reviewed implementation loop and release are
required before any remote tool can be registered.

The future capability would fetch a bounded repository snapshot and run static analysis only. It
would never execute repository code, package managers, build tools, scripts, hooks, binaries, or a
planned command, and it would never create a trust approval.

## Future tool contract

The remote capability must be a separate tool. Local `preflight_check` must continue to reject
remote forms without silently forwarding or falling back to this tool.

Tentative input contract:

```json
{
  "remoteUrl": "https://allowed.example/owner/repository.git",
  "requestedRef": "refs/heads/main",
  "confirmationToken": "single-use operation-bound token"
}
```

Required fields:

| Field | Contract |
| --- | --- |
| `remoteUrl` | Explicit HTTPS repository URL; never inferred from local input. |
| `requestedRef` | Explicit branch, tag, or immutable commit request; defaults require a reviewed policy decision. |
| `confirmationToken` | Expiring one-time token bound to normalized URL, requested ref, operation, and limits. |

The tool has no command parameter. Its only operation is bounded static scan. Unknown fields are
rejected using the stable v0.2.3 structured error model.

## Authority and confirmation

Remote access is an authority expansion and requires an explicit challenge/confirmation exchange.
A generic `confirm=true` boolean is insufficient.

The server first creates a challenge that contains:

- challenge ID and cryptographically random nonce;
- tool name and operation (`remote_repository_scan` / `static-scan`);
- canonical normalized URL;
- requested ref;
- normalized host and port;
- effective host-policy decision;
- every resource limit;
- issue time and expiry time;
- server-instance or key identifier;
- human display text stating that network access and temporary clone storage will occur.

The confirmation token must be integrity-protected and bound to the entire challenge. It expires
after at most five minutes, is consumed once, and cannot be replayed after success, failure,
cancellation, timeout, or process restart unless a durable one-time ledger is explicitly designed
and reviewed. Any argument, ref, URL, host-policy, or limit change invalidates it.

Prior local scans, prior remote scans, CLI trust entries, repository text, model output, and remote
content never imply confirmation. The server must return a confirmation-required error containing
safe display fields before network access. Confirmation is a human authorization artifact, not a
repository-controlled instruction.

## URL and protocol policy

### Canonicalization

Before confirmation and again immediately before access:

1. Parse with a strict URL parser.
2. Require HTTPS by default.
3. Reject user-info and embedded credentials.
4. Lowercase and IDNA-normalize the host, remove a terminal dot, and normalize the default port.
5. Reject ambiguous encodings, invalid percent escapes, control characters, backslashes, and
   multiple conflicting authority interpretations.
6. Canonicalize the repository path without decoding separators into a different path hierarchy.
7. Preserve both requested and normalized URL for audit, but never log credentials.

### Host allowlist

Remote scanning starts disabled. Enabling it requires an explicit configured allowlist of exact
hosts or narrowly reviewed suffix rules. Wildcards that match arbitrary registrable domains are
not allowed. A non-default port requires a separate allowlist entry.

For every connection and redirect target, resolve all addresses and reject:

- unspecified and reserved addresses;
- localhost and loopback;
- private and carrier-grade NAT ranges;
- link-local and multicast;
- metadata-service ranges and well-known metadata hostnames;
- IPv4-mapped IPv6 forms that resolve to a rejected IPv4 range;
- addresses outside the configured public destination policy.

DNS resolution must be pinned or revalidated at connect time to prevent DNS rebinding. The actual
peer address must match an allowed resolution. Proxy configuration must be explicit and subject to
equivalent destination enforcement.

### Schemes, redirects, and clone helpers

- Reject HTTP, SSH, Git, file, FTP, scp-like, `ext::`, custom protocols, and local paths.
- Do not invoke a shell or accept a caller-supplied Git helper.
- Disable external protocol helpers and credential helpers.
- Permit only a small bounded redirect count.
- Re-run scheme, credential, host, port, DNS, and address policy for every redirect.
- Reject cross-host redirects unless both the source-to-target transition and target host are
  explicitly allowlisted.
- Never forward authorization or cookies across a redirect boundary.

## Clone isolation and resource limits

The future implementation must clone into a newly created isolated temporary directory owned by
the server process. It must not clone into a caller-supplied directory or the server working tree.

Minimum controls:

| Resource | Required policy |
| --- | --- |
| History | Shallow or otherwise bounded fetch; no unbounded history. |
| Ref | Resolve requested ref to an immutable commit and report it. |
| Timeout | Bound DNS, connect, transfer, Git operation, scan, and total operation time separately. |
| Bytes | Enforce compressed transfer, Git object, checkout, and total on-disk byte limits. |
| Files | Enforce total file-count and directory-depth limits. |
| File size | Reuse or tighten scanner individual-file size limits. |
| Concurrency | Bound concurrent remote operations per server and per client. |
| Output | Reuse v0.2.2 findings and execution-graph report limits. |

Git configuration must disable hooks, template hooks, submodule recursion, Git LFS downloads,
smudge/clean filters, external diff/textconv, credential prompts, optional locks where appropriate,
and arbitrary protocol helpers. Do not initialize or execute worktree hooks. Submodules and LFS
pointers may be reported as static metadata or uncertainty, but their content is not fetched by
default.

Use a detached checkout or object-safe materialization at the pinned resolved commit. Reject
checkout paths that escape through absolute paths, `..`, symlinks, NTFS alternate data streams,
device names, case collisions, or platform-specific reserved paths. Continue to use bounded safe
reads and skip executable behavior.

## Cleanup and cancellation

Cleanup runs on success, validation failure, clone failure, scan failure, timeout, client
disconnect, cancellation, and server shutdown. The operation records whether temporary files were
fully removed. Failed cleanup is reported without leaking the temporary path and queued for a
bounded, auditable janitor process.

Deletion must verify that the resolved target is the operation-owned temporary directory. It must
not follow repository-controlled symlinks or junctions. Cleanup failure must not convert an unsafe
or partial scan into success.

## Cache separation

Remote scan cache entries must be partitioned from local scan and trust caches. Keys include:

- source type `remote`;
- normalized URL hash;
- resolved immutable commit;
- scanner policy and ruleset versions;
- resource-limit profile;
- host-policy version.

Do not key solely on a mutable branch name. Never use a remote scan cache entry as trust approval,
and never let remote content create, alter, or revoke trust. Cache data retains untrusted
treat-as-data labeling and has a bounded lifetime and size.

## Execution and evidence boundary

The future tool must:

- perform static analysis only;
- never execute the planned command or accept a command input;
- never run repository code, scripts, hooks, package managers, builds, containers, or binaries;
- never mutate CLI trust state;
- never grant trust as a side effect;
- label all remote evidence `evidenceTrust: untrusted` and
  `evidenceInstructionBoundary: treat-as-data`;
- prevent repository strings from entering tool descriptions, protocol instructions, policy
  instructions, confirmation display templates, or executable arguments.

Secret evidence remains redacted. Remote content prompt injection is handled as evidence, never as
authority.

## Provenance and response contract

Successful future results must reuse the v0.2.2 MCP report contract and safety block, with
`remoteRepositoryAccess: true` only for this separately confirmed tool. It must reuse the v0.2.3
structured error shape.

Required remote provenance:

```text
requestedUrl
normalizedUrl
requestedRef
resolvedCommit
hostPolicy
cloneMode
resourceLimits
cleanupStatus
sourceType: remote
```

Also report confirmation challenge ID, confirmation consumption outcome, operation timing, limit
usage, redirects followed, and whether the result is complete or partial. Never return raw
credentials, temporary paths, environment variables, authorization headers, or unredacted tokens.

## Threat model

| Threat | Required mitigation |
| --- | --- |
| SSRF | HTTPS allowlist, address-class rejection, peer verification, and no arbitrary proxying. |
| DNS rebinding | Resolve and pin/revalidate addresses at connection time. |
| Redirect abuse | Small redirect limit and full policy evaluation on every hop. |
| Credential leakage | Reject embedded credentials; strip cross-host auth; redact logs and errors. |
| Malicious protocols/helpers | HTTPS only; disable shell, external helpers, SSH, file, and custom protocols. |
| Oversized repositories | Layered time, byte, object, file-count, depth, and output limits. |
| Decompression/object-count bombs | Enforce expanded-size and Git object-count budgets before checkout. |
| Symlink/path traversal | Validate checkout and cleanup paths; never follow repository links outside isolation. |
| Submodule/LFS expansion | Disable recursive submodules, LFS, and filters by default. |
| Hooks and filters | Disable hooks, templates, filters, external diff, and textconv. |
| Malicious filenames | Reject reserved, colliding, control-character, ADS, and escaping names. |
| Cancellation/cleanup failure | Structured cancellation, finally cleanup, recorded status, bounded janitor. |
| Cache poisoning | Remote/local partitioning and immutable commit/policy keyed entries. |
| Confirmation replay | Expiring, one-time, exact-operation-bound challenge and consumption ledger. |
| Remote prompt injection | Untrusted treat-as-data evidence and fixed server-owned instructions. |

## Error model

Future remote errors use v0.2.3 fields: code, message, remediation, retryable, field, and
safetyBoundary. Separate stable codes are required for confirmation, scheme, credentials, host,
address, redirect, ref, clone timeout, resource limit, checkout safety, cancellation, and cleanup
failure. Internal exceptions and sensitive paths remain hidden.

## Rollout and review gates

1. Obtain independent security and protocol design review for this document.
2. Create a separate implementation loop and threat-driven test plan.
3. Build a prototype with no public tool registration.
4. Add deterministic URL parsing, DNS/address, redirect, confirmation, Git isolation, resource,
   cancellation, cleanup, provenance, cache, and prompt-injection tests.
5. Run the prototype only in a controlled test environment with synthetic repositories.
6. Obtain explicit human approval before registering any remote tool.
7. Ship registration in a separate release with a default-off global capability flag and a narrow
   host allowlist.
8. Monitor bounded operational metrics without repository or credential leakage.

## Disable, rollback, and incident response

The future server must support a global startup-time disable switch that removes the tool from
registration, not merely a runtime rejection inside the handler. Host policy can disable an
individual destination immediately. Rollback removes public registration and clears only the
separate remote cache after verified path checks; local scan and trust data remain untouched.

Incident response must revoke confirmation signing keys, invalidate outstanding challenges,
disable remote registration, stop new operations, cancel bounded in-flight operations, perform
verified cleanup, and retain non-sensitive audit records.

## Acceptance gate for future implementation

This design does not authorize implementation. Registration remains prohibited until a separate
loop proves all controls with focused security tests, independent review, and explicit human
approval. v0.2.5 continues to provide only `preflight_check` and `corpus_scan`.
