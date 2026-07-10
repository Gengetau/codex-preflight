# MCP Trust Management Design

## Status and boundary

Status: **design-only and unavailable** in v0.2.6.

This document defines future trust-management contracts. It does not implement or register
`trust_list`, `trust_approve`, `trust_revoke`, or equivalent tools. The runtime tool set remains
exactly `preflight_check` and `corpus_scan`, and MCP `preflight_check` continues to call the core
with `allow_trust=False`.

Trust mutation is a separate authority from static scanning. Filesystem write access to the trust
cache does not itself authorize a process, client, model, or agent to mutate trust.

## Authority separation

Future server configuration must model three independent authority levels:

```text
scan-read
trust-read
trust-mutate
```

- `scan-read` permits the existing read-only static tools and does not consult MCP trust.
- `trust-read` may expose `trust_list` without mutation.
- `trust-mutate` may expose separately reviewed approval and revocation tools only when explicit
  server configuration, client authorization, and confirmation controls all allow it.

The server must support scan-only, scan plus trust-read, and mutation-disabled configurations.
Mutation is default-off and can be globally disabled at startup so mutating tools are absent from
registration. It must not be inferred from local file permissions, prior approvals, remote scan
confirmation, client identity, or model role.

## Future tool contracts

### `trust_list` read-only contract

`trust_list` is read-only and requires bounded output. Tentative inputs:

```json
{
  "repositoryIdentity": "optional exact normalized identity",
  "commandScope": "optional exact scope",
  "cursor": "optional opaque cursor",
  "limit": 50
}
```

Requirements:

- optional exact repository identity filter;
- optional exact command-scope filter;
- stable opaque trust-entry identifiers;
- bounded `limit` with a conservative maximum;
- opaque pagination cursor rather than unbounded listing;
- approval provenance for each entry;
- creation, last-update, and expiration timestamps;
- policy version and ruleset version;
- revoked/expired state without returning sensitive history;
- no raw cache path, secret evidence, confirmation token, environment variable, file permission,
  or unrelated repository disclosure.

The server applies authorization before filtering so a caller cannot probe hidden identities by
timing or error differences. Results use a separately versioned read schema and deterministic
ordering.

### `trust_approve` mutating contract

Tentative input:

```json
{
  "repositoryIdentity": "exact normalized identity",
  "headCommit": "exact commit when available",
  "criticalFingerprint": "sha256:exact fingerprint",
  "commandScope": "exact scope",
  "policyVersion": "exact version",
  "rulesetVersion": "exact version",
  "expiresAt": "bounded future timestamp",
  "reason": "human-readable approval reason",
  "confirmationToken": "single-use exact-operation token"
}
```

Requirements:

- resolve and display the exact repository identity before confirmation;
- bind to exact head commit when available;
- bind to exact critical fingerprint, command scope, policy version, and ruleset version;
- require a bounded expiration or lifetime;
- require a non-empty human-readable reason with bounded length;
- prohibit wildcard, empty, prefix, glob, regex, or `any` values for identity, fingerprint, scope,
  policy, and ruleset;
- prohibit approval when identity cannot be safely resolved;
- prohibit automatic approval derived from a scan, remote content, repository instructions,
  corpus result, model output, or prior confirmation;
- require a separately issued exact-operation confirmation token;
- return the stable trust-entry identifier and audit event ID without returning storage paths.

The operation revalidates repository head, fingerprint, policy, ruleset, expiry, and caller
authority after confirmation and immediately before atomic mutation. Any drift invalidates the
challenge and requires a new human review.

### `trust_revoke` mutating contract

Tentative input:

```json
{
  "trustEntryId": "stable opaque identifier",
  "expectedVersion": 3,
  "reason": "human-readable revocation reason",
  "confirmationToken": "single-use exact-operation token"
}
```

Requirements:

- require explicit confirmation bound to the stable trust-entry identifier;
- support optional optimistic concurrency with `expectedVersion`;
- be idempotent for an already-revoked entry;
- distinguish already revoked, missing/not visible, version conflict, and successful revocation
  without leaking hidden entries;
- create an audit record for success and failed attempts without sensitive data;
- never accept a repository path as an ambiguous substitute for the stable identifier;
- never broaden revocation into deletion of unrelated entries or cache files.

Policy may choose a privacy-preserving common result for missing and unauthorized entries. The
choice must be documented and tested before implementation.

## Confirmation challenge model

A generic `confirm=true` boolean is insufficient. Mutating calls require a prior challenge that is
integrity-protected and structurally or cryptographically bound to the exact operation.

Challenge contents:

- challenge ID and cryptographically random nonce;
- exact tool name and operation;
- complete canonical arguments excluding only the token itself;
- normalized repository identity and stable trust-entry ID when applicable;
- head commit, critical fingerprint, command scope, policy version, and ruleset version;
- proposed expiration and human reason;
- caller/client identity and authority when available;
- current trust-entry version for optimistic concurrency;
- server instance or confirmation-key identifier;
- creation and expiration timestamps;
- single-use and restart behavior;
- human display text that clearly states the trust authority being granted or revoked.

The human display must be generated from fixed server templates. Repository-controlled strings are
escaped and labeled untrusted data, never interpreted as instructions.

### Expiry, one-time use, and replay protection

- Challenges expire quickly and cannot be refreshed without new review.
- Tokens are consumed exactly once on success, policy rejection, validation failure, conflict,
  cancellation, or timeout.
- Any argument, identity, head, fingerprint, scope, policy, ruleset, reason, expiry, or tool-name
  change invalidates the token.
- Tokens are bound to the authorized client when identity is available.
- Process restart invalidates in-memory challenges. Durable challenges require a reviewed,
  integrity-protected, one-time consumption ledger.
- Guessed, forged, already consumed, expired, wrong-tool, and wrong-client tokens return stable
  indistinguishable failure codes where disclosure would aid probing.

### Cancellation, failure, and retry

Cancellation before mutation consumes the challenge and records a cancelled audit outcome. Failure
after the atomic commit reports the committed state and audit event, not an ambiguous retry prompt.
Transport loss requires clients to query by an idempotency key or trust-entry identifier before
requesting a new challenge. A retry never reuses the original confirmation token.

## Authorization and caller identity

Confirmation supplements authorization; it does not replace it. Before challenge creation and
again before mutation, the server verifies configured authority level, authenticated client
identity when available, repository visibility, and tool-specific policy. Absence of client
identity can be configured to prohibit mutation entirely.

No agent may silently confirm on behalf of a human merely because it can call the tool. Client
applications must present fixed display text to the user and return a user-originated confirmation
artifact.

## Audit model

Use append-only or equivalently tamper-evident audit events. Every challenge creation, confirmation,
mutation attempt, conflict, cancellation, denial, success, and recovery action records:

```text
eventId
timestamp
toolName
operation
normalizedTargetIdentity
trustEntryId
commandScope
policyVersion
rulesetVersion
actorOrClientIdentity
confirmationChallengeId
outcome
failureCode
```

Also record entry version, head-commit/fingerprint digests where allowed, and prior/new state
digests. Do not record repository contents, secret evidence, credentials, environment variables,
raw confirmation tokens, signing keys, full cache paths, or unredacted reasons containing secrets.

Audit writes are ordered with mutation using a transaction, write-ahead event, or recoverable
two-phase protocol. A mutation must not succeed silently without an audit record. Audit readers are
separately authorized, results are bounded, and retention/rotation preserves integrity links.

## Storage and migration model

Future tools must interoperate with the existing CLI trust cache without weakening CLI semantics.

### Schema and identifiers

- Add an explicit schema version and migration history.
- Derive stable opaque entry identifiers from stored random IDs, not raw paths or enumerable hashes.
- Preserve exact identity, head, fingerprint, scope, policy, ruleset, approval, expiry, reason, and
  state fields.
- Keep legacy entries readable through a tested migration path; do not silently broaden them.
- Reject or quarantine unknown future schema versions rather than downgrading them.

### Atomicity, locking, and concurrency

- Use the existing locked atomic-write pattern or a reviewed transactional store.
- Lock reads that participate in compare-and-swap mutations.
- Write a new file, flush data, apply restrictive permissions, and atomically replace where the
  platform supports it.
- Use optimistic entry versions to detect concurrent approve/revoke races.
- Revalidate the entry under the mutation lock after confirmation.
- Never truncate the only valid cache before the replacement is durable.

### Permissions and path safety

- Store per-user by default with least-privilege owner-only permissions where supported.
- Verify the storage parent and file are not repository-controlled symlinks, junctions, reparse
  points, or unexpected hard links.
- Do not honor repository environment variables or configuration for the trust-store path.
- Document OS-specific permission limitations and refuse unsafe configurations when policy requires.

### Corruption, backup, and recovery

- Validate full schema, checksums/integrity data, timestamps, and entry invariants before use.
- On corruption, fail closed for approvals and preserve the bad file for local manual recovery
  without exposing it through MCP.
- Maintain a bounded permission-preserving backup or journal before migration.
- Make migration idempotent and crash recoverable.
- Provide explicit CLI-admin recovery and audit steps; MCP mutation cannot auto-reset the store.

### Policy and ruleset changes

Approvals remain exact-version scoped. A policy or ruleset version change makes incompatible entries
non-matching without deleting history. Migration cannot rewrite old approvals to a new version.
Users must review and create a new approval through a new challenge.

## CLI compatibility

CLI and future MCP operations must share the same locked store schema and matching semantics. MCP
must not create approvals broader than the CLI can display or revoke. CLI listing must show MCP
provenance and audit identifiers without tokens. CLI revoke and MCP revoke must use compatible
idempotency and concurrency behavior.

Existing MCP `preflight_check` remains trust-blind even if future trust tools exist. A separate
reviewed tool or explicit future contract would be required to consume trust; v0.2.6 does not
authorize that change.

## Remote scan separation

Remote scan confirmation authorizes only bounded network/static-scan activity. It cannot create
trust, satisfy a trust-mutation challenge, or provide a safely resolved local trust identity. No
approval may be derived automatically from remote content or a remote resolved commit.

## Threat model

| Threat | Required mitigation |
| --- | --- |
| Silent agent approval | Separate human challenge UI and user-originated confirmation artifact. |
| Prompt injection requesting approval | Fixed templates; repository evidence remains untrusted treat-as-data. |
| Wildcard/overbroad approval | Exact non-wildcard identity, fingerprint, scope, policy, and ruleset validation. |
| Stale head or fingerprint | Recompute and revalidate immediately before mutation. |
| Confused deputy | Separate scan-read, trust-read, and trust-mutate authority and client authorization. |
| Confirmation replay | Expiring, one-time, tool/argument/client-bound challenge and consumption ledger. |
| Approval of remote content | Remote scan confirmation never authorizes trust; require safely resolved local identity. |
| Forged/guessed entry IDs | Random opaque identifiers, authorization-before-disclosure, rate limiting. |
| Revocation races | Entry versions, locked compare-and-swap, idempotent result semantics. |
| Cache tampering | Restrictive permissions, path checks, integrity validation, fail-closed behavior. |
| Path/symlink attacks | Fixed per-user root and reparse/symlink/hard-link validation. |
| Cross-user privilege differences | Per-user stores, explicit service identity, no silent privilege bridging. |
| Audit tampering | Append-only/tamper-evident events, integrity links, restricted audit authority. |
| Policy/ruleset downgrade | Exact version binding and no migration-based approval broadening. |

## Error model

Future tools reuse v0.2.3 fields: stable code, message, remediation, retryable, field, and
safetyBoundary. They require separate codes for authorization, confirmation-required, expired,
consumed, invalid binding, entry missing/not visible, version conflict, unsafe storage, corruption,
lock timeout, audit failure, and internal failure. Raw traces, tokens, cache paths, and hidden
identities are never returned.

## Rollout plan

1. Obtain independent security, storage, concurrency, CLI-compatibility, and protocol review.
2. Create a separate implementation loop for read-only `trust_list` with bounded results.
3. Test listing authorization and disclosure boundaries before any mutation work.
4. Prototype approve/revoke mutation with no public registration.
5. Add deterministic confirmation, replay, drift, concurrency, corruption, migration, permission,
   path, crash-recovery, audit, idempotency, and prompt-injection tests.
6. Obtain explicit human approval before registering mutating tools.
7. Ship mutation in a separate release with global mutation disabled by default.
8. Exercise emergency disable, recovery, and rollback procedures before production use.

## Emergency disable and rollback

A startup-time global switch must remove mutating tools from registration. A separate switch may
leave `trust_list` available while disabling mutation. Emergency disable invalidates outstanding
challenges, stops new mutations, lets in-flight atomic operations resolve to a recorded state, and
preserves audit evidence.

Rollback removes tool registration without deleting existing CLI trust data. Schema rollback must
be explicitly supported or remain on the newer compatible reader; never rewrite entries to an older
schema that broadens authority. Compromised confirmation keys are rotated and all outstanding
challenges invalidated.

## Acceptance gate for future implementation

This design does not authorize implementation or registration. v0.2.6 remains scan-only through
MCP. Future trust access requires separate reviewed loops, explicit authority configuration,
security/concurrency validation, and human approval.
