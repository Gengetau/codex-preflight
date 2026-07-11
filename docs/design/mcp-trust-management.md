# MCP Trust Management Design

## Status and boundary

Status: **bounded trust read implemented and default-off in v0.3.3; trust mutation unavailable**.

Exact startup value `CODEX_PREFLIGHT_ENABLE_TRUST_READ=1` registers `trust_list`. The default MCP
inventory remains exactly `preflight_check` and `corpus_scan`; the remote and trust-read flags are
independent and may add `remote_repository_scan`, `trust_list`, or both. No runtime mode registers
`trust_approve`, `trust_revoke`, or an equivalent mutation tool. MCP `preflight_check` continues to
call the core with `allow_trust=False`, and remote confirmation cannot inspect or satisfy trust.

Trust mutation is a separate authority from static scanning. Filesystem write access to the trust
cache does not itself authorize a process, client, model, or agent to mutate trust.

## Authority separation

Server configuration models three independent authority levels:

```text
scan-read
trust-read
trust-mutate
```

- `scan-read` permits the existing read-only static tools and does not consult MCP trust.
- `trust-read` exposes only the bounded, redacted `trust_list` when the exact startup flag is set.
- `trust-mutate` may expose separately reviewed approval and revocation tools only when explicit
  server configuration, client authorization, and confirmation controls all allow it.

The server must support scan-only, scan plus trust-read, and mutation-disabled configurations.
Mutation is default-off and can be globally disabled at startup so mutating tools are absent from
registration. It must not be inferred from local file permissions, prior approvals, remote scan
confirmation, client identity, or model role.

## Tool contracts

### `trust_list` read-only contract

`trust_list` is read-only, default-off, and requires bounded output. Its exact optional inputs are:

```json
{
  "repoId": "optional exact stored repository identity filter",
  "commandScope": "optional exact supported scope",
  "limit": "optional integer 1-100, default 50",
  "cursor": "optional opaque cursor from a prior page"
}
```

The schema uses `additionalProperties: false`. `repoId` is a non-empty exact equality filter of at
most 4096 UTF-8 bytes with no controls; it is never opened as a path or fetched as a URL.
`commandScope` accepts only `dependency_install`, `script_execution`, `build`, `test`, `docker`,
`network_shell`, `mcp_server_start`, or `unknown_shell`. Unknown fields and invalid scalar types
fail before reading trust data.

Success uses exact schema `trust-list/v1` and deterministic ordering by expiry, process-keyed
repository hash, scope, policy, ruleset, fingerprint, and stored UUIDv4 entry ID. Each live entry
returns stored commit/fingerprint/scope/decision/timestamps/actor/policy/ruleset and exact v2
provenance. Expired entries remain stored but are excluded. Raw `repoId`, local path, remote URL,
approved command, cache/lock/temp paths, environment, credentials, evidence, and tokens are never
returned. Results expose stable opaque trust-entry identifiers from stored random UUIDv4 values;
raw identities are replaced by process-local HMAC-SHA256 hashes.

Pagination cursors are HMAC protected with a separate process-local key, at most 512 bytes, valid
for 300 seconds, reusable within that window, and bound to tool, schema, repository filter hash,
scope filter, limit, snapshot digest, offset, issue/expiry time, and nonce. Restart, expiry,
tampering, filter/limit mismatch, or any filtered trust-snapshot change fails with
`MCP_TRUST_LIST_CURSOR_INVALID` and no partial results.

Runtime identity is intentionally fixed to stdio with `identityStatus: unavailable` and null client
and session IDs. The current callback does not claim authenticated caller identity.

The tool cannot approve, revoke, extend, refresh, consume, satisfy, or create trust. The only
trust-file write it may trigger is the exact metadata-only migration described below. Dedicated
audit uses `<codex-preflight-home>/trust-read/audit.jsonl`, 4096-byte records, a 1 MiB active
segment, and three rotated segments. Lock, append, fsync, rotation, or directory failure closes the
read and returns no metadata.

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

v0.3.3 trust reads interoperate with the existing CLI trust cache without weakening CLI semantics.
Mutation-tool requirements below remain future design.

### Schema and identifiers

- v0.3.3 adds `entryVersion: 1`, schema `trust-cache-array-v2`, and migration provenance.
- Stable opaque entry identifiers are stored UUIDv4 values, not raw paths or enumerable hashes.
- Preserve exact identity, head, fingerprint, scope, policy, ruleset, approval, expiry, reason, and
  state fields.
- Keep legacy entries readable through a tested migration path; do not silently broaden them.
- Reject or quarantine unknown future schema versions rather than downgrading them.

The reader parses at most 1 MiB and validates every entry before migration or listing. Valid legacy
arrays are migrated under the shared CLI trust lock by adding only `entryId`, `entryVersion`, and
provenance. Before atomic replacement it creates a permission-preserving backup named
`trust.json.v0.3.3-migration.<timestamp>.<nonce>.bak` and retains at most three. All approval values,
approval count, expiry, and matching semantics remain unchanged. Missing/empty stores succeed
empty; corruption, unsupported schema, invalid fields, lock timeout, backup failure, size overflow,
atomic replacement failure, and audit failure fail closed.

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
reviewed tool or explicit future contract would be required to consume trust; v0.3.3 does not
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

1. Completed in v0.3.3: independent security, storage, concurrency, CLI-compatibility, and protocol review.
2. Completed in v0.3.3: separate implementation loop for bounded read-only `trust_list`.
3. Completed in v0.3.3: listing authorization, migration, cursor, audit, and disclosure tests.
4. Prototype approve/revoke mutation with no public registration.
5. Add deterministic confirmation, replay, drift, concurrency, corruption, migration, permission,
   path, crash-recovery, audit, idempotency, and prompt-injection tests.
6. Obtain explicit human approval before registering mutating tools.
7. Ship mutation in a separate release with global mutation disabled by default.
8. Exercise emergency disable, recovery, and rollback procedures before production use.

## Emergency disable and rollback

A startup-time global switch must remove mutating tools from registration. The implemented
trust-read switch independently removes `trust_list` when disabled. Emergency disable invalidates outstanding
challenges, stops new mutations, lets in-flight atomic operations resolve to a recorded state, and
preserves audit evidence.

Rollback removes tool registration without deleting existing CLI trust data. Removing
`CODEX_PREFLIGHT_ENABLE_TRUST_READ` and restarting invalidates process-local cursors while preserving
the trust file, migration backups, and audit. Schema rollback must remain on the newer compatible reader; never rewrite entries to an older
schema that broadens authority. Compromised confirmation keys are rotated and all outstanding
challenges invalidated.

## Acceptance gate

v0.3.3 authorizes only default-off `trust_list` and its exact metadata-only migration. Trust
approval, revocation, extension, consumption, matching changes, authenticated identity claims, or
other mutation still require separate reviewed loops, explicit authority configuration,
security/concurrency validation, exact-head acceptance, and release approval.
