# MCP Trust Management Design

## Status and boundary

Status: **bounded trust read remains implemented and default-off; confirmation-gated trust mutation
is implemented and default-off in v0.3.4**.

Three exact startup flags are independent:

- `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1` adds `remote_repository_scan`.
- `CODEX_PREFLIGHT_ENABLE_TRUST_READ=1` adds `trust_list`.
- `CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION=1` adds `trust_approve` and `trust_revoke`.

The default inventory remains exactly `preflight_check` and `corpus_scan`. The eight combinations
contain only the ordered union of the enabled authorities. MCP `preflight_check` always calls the
core with `allow_trust=False`; MCP preflight does not consume trust. Remote confirmation cannot
create, satisfy, read, or mutate trust.

Trust mutation is local and exact-entry only. It never executes the planned command, repository
code, hooks, package managers, builds, tests, browsers, or network requests. Filesystem access to
the trust cache does not itself authorize a process, client, model, or agent to mutate trust.

## Authority separation

The server models three authority levels:

```text
scan-read
trust-read
trust-mutate
```

- `scan-read` permits the static local tools and does not consult trust.
- `trust-read` permits only the bounded redacted `trust_list` when its exact flag is enabled.
- `trust-mutate` permits only `trust_approve` and `trust_revoke` when its exact flag is enabled and
  every operation completes the confirmation protocol below.

Mutation does not imply trust read or remote scan. It is default-off and cannot be inferred from
file permissions, prior approvals, remote confirmation, repository content, client identity, or
model role. The supported runtime is a deliberately enabled single-user local stdio process with
`identityStatus: unavailable` and null client/session IDs; it does not claim authenticated identity.

## Tool contracts

### `trust_list` read-only contract

`trust_list` uses exact schema `trust-list/v1`. Its optional inputs are exact `repoId`, one supported
`commandScope`, integer `limit` from 1 through 100, and an opaque `cursor`; the closed schema rejects
unknown fields. It returns only live entries with stable opaque trust-entry identifiers backed by
stored UUIDv4 values. Raw repository IDs, paths, remote URLs, approved commands, private reasons,
mutation audit linkage, cache paths, credentials, evidence, and tokens are not returned.

Pagination is deterministic. Cursors are process-local HMAC values, at most 512 bytes, valid for
300 seconds, reusable only for the bound filters/limit/snapshot, and invalid after Process restart,
expiry, tampering, or state drift. The tool cannot approve, revoke, extend, consume, satisfy, or
create trust. Its only trust-file write is the v0.3.3 metadata-only migration described below.

### `trust_approve` mutating contract

The exact closed input schema is:

```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "cwd": {"type": "string", "minLength": 1, "maxLength": 4096},
    "command": {"type": "string", "minLength": 1, "maxLength": 4096},
    "expiresAt": {
      "type": "string",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z$"
    },
    "reason": {"type": "string", "minLength": 1, "maxLength": 512},
    "confirmationToken": {"type": "string", "minLength": 1, "maxLength": 1024}
  },
  "required": ["cwd", "command", "expiresAt", "reason"]
}
```

The caller cannot supply repository identity, entry ID, approved timestamp, head, fingerprint,
scope, policy, ruleset, actor, storage path, or output path. The server resolves the canonical local
root and derives identity, head commit, critical fingerprint, command scope, current policy, and
current ruleset. It rejects unsafe/non-local paths, unresolved identity, resource-limit failure, or
drift. Exact validation must prohibit wildcard, prefix, glob, regex, or `any` authority.
The corresponding server-derived field names are `repoId`, `headCommit`, `criticalFingerprint`,
`commandScope`, `policyVersion`, and `rulesetVersion`; none is caller-overridable.

The first valid call omits `confirmationToken` and performs bounded validation only. It creates no
approval and returns a fixed challenge. The confirmed retry uses the same arguments plus the token.
After token consumption, all target values and trust-store state are revalidated under the shared
lock. A successful write creates one `trust-cache-array-v2` entry with `entryVersion: 1`, exact
`mcp-trust-approve` provenance, the challenge-bound UUIDv4, exact expiry/reason, and server-issued
timestamps. An already-active matching approval is an idempotent `already-approved` no-op: no
duplicate, replacement, command change, or TTL extension occurs.

Success uses `trust-approve/v1`, returns the redacted entry projection and final `auditEventId`, and
sets `mutationApplied` according to the outcome. It never returns raw identity, path, URL, command,
reason, token, key, or storage path.

### `trust_revoke` mutating contract

The exact closed input schema is:

```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "trustEntryId": {
      "type": "string",
      "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    },
    "expectedVersion": {"type": "integer", "const": 1},
    "reason": {"type": "string", "minLength": 1, "maxLength": 512},
    "confirmationToken": {"type": "string", "minLength": 1, "maxLength": 1024}
  },
  "required": ["trustEntryId", "expectedVersion", "reason"]
}
```

`expectedVersion` is mandatory and exactly integer `1`; booleans, floats, strings, null, and every
other value fail closed. The first call binds the complete private entry but displays only:

```json
{
  "template": "revoke-exact-trust-entry/v1",
  "repositoryContentTrust": "untrusted",
  "trustEntry": "exact redacted trust-list/v1 entry projection",
  "expectedVersion": 1,
  "reason": "exact bounded caller reason"
}
```

The confirmed retry consumes the token before revalidation, compares the full stored entry and
entry digest under the shared lock, and deletes exactly one entry. The optimistic concurrency check
uses stored `entryVersion: 1`; changed state returns version conflict or target drift. Missing,
expired, already removed, and not-visible IDs share privacy-preserving
`MCP_TRUST_MUTATION_NOT_FOUND`. Revocation is physically idempotent through that common result and
never accepts paths, identities, hashes, wildcards, prefixes, globs, regexes, or bulk selectors.

Success uses `trust-revoke/v1`, returns only `entryId`, `entryVersion: 1`, consumed confirmation,
fixed runtime identity, final `auditEventId`, and the fixed mutation safety object.

## Confirmation challenge model

A generic `confirm=true` boolean is insufficient. The first fully valid mutation call returns
`MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED` and a
`trust-mutation-confirmation/v1` object with exact challenge ID, opaque token, operation,
issued/expiry timestamps, and fixed display. The call performs no trust mutation.

The challenge binds the exact tool and operation, canonical request excluding only the token,
complete private target/entry state, proposed or existing entry ID, policy/ruleset, target and store
digests, process-key ID, nonce, issue time, and expiry. Tokens use a process-local 256-bit HMAC key,
expire after 300 seconds, are at most 1024 bytes, and are one-time. At most 128 challenges are live,
and issuance is limited to 32 in 60 seconds.

Client applications must stop, present only the fixed display to a human, keep the token out of
display/logging, and make one confirmed retry only if that human approves the exact operation.
Repository content, scans, remote confirmation, model output, prior trust, and automatic client
logic cannot satisfy confirmation.

Process restart invalidates outstanding challenges. An authentic live token is consumed before the
retried envelope and target are fully revalidated, so changed/invalid arguments, conflict,
cancellation, timeout, or drift cannot replay it. Forged, malformed, expired, unknown-key,
wrong-tool, and consumed tokens share `MCP_TRUST_MUTATION_CONFIRMATION_INVALID`.

### Cancellation, failure, and retry

Cancellation or timeout before mutation consumes the challenge and records a terminal audit event.
Failure before the prepared audit or atomic replacement creates no mutation. If replacement commits
but final audit commit fails, return non-retryable
`MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING` with `committed: true`, operation, entry ID, and prepared
audit event ID. The client must not repeat the mutation. The process becomes unhealthy, invalidates
all live challenges, and rejects later mutations until restart and recovery.

## Audit model

Mutation audit is separate from trust-read, remote, scan cache, and trust data. Owner-only where
supported, it stores HMAC-chained canonical JSONL records limited to 4096 bytes, one 1 MiB active
segment, and three rotated segments. Records are locked, flushed, and fsynced.

Audit records include `eventId`, timestamp, tool, operation, redacted target hash, trust entry ID,
command scope, policy/ruleset, fixed null actor/client identity, `confirmationChallengeId`, outcome,
stable failure code, entry version, and before/intended-after state digests. They exclude raw paths,
repo IDs, URLs, commands, reasons, tokens, keys, environment, trust content, evidence, and filesystem
errors.

Every mutation uses write-ahead ordering: fsync `mutation_prepared`, atomically replace trust data,
then fsync `mutation_committed`. Startup verifies the complete chain and reconciles the sole allowed
unmatched prepared tail. Matching intended-after bytes append `recovery_committed`; matching before
bytes append `recovery_aborted`. Ambiguity, tampering, multiple unmatched prepares, or failed
recovery closes mutation registration.

## Storage and migration model

### Historical v0.3.3 read foundation

v0.3.3 introduced schema `trust-cache-array-v2`, stored UUIDv4 IDs, `entryVersion: 1`, provenance,
the 1 MiB full-store cap, and the locked metadata-only migration. Migration adds metadata while
preserving all approval values, counts, expiry, and matching behavior, creates a bounded
permission-preserving backup, and remains readable by v0.3.4.

### Released v0.3.4 mutation storage

v0.3.4 adds source-specific `mcp-trust-approve` provenance containing exact schema, mutation release
version, server-issued creation timestamp, bounded private approval reason, and prepared
`mutationAuditEventId`. Existing migrated and CLI-created entries keep their exact provenance.
There is no whole-store v3 migration.

### Atomicity, locking, and concurrency

- Use the shared trust lock for CLI reads/writes, trust reads, confirmation revalidation, and MCP
  mutation.
- Validate the complete store and exact entry under lock.
- Use optimistic concurrency through exact `entryVersion: 1` and the full entry digest.
- Fsync prepared audit before durable atomic replacement and commit audit after replacement.
- Preserve unrelated live and expired entries byte-for-byte at the JSON value level.

### Permissions and path safety

The application-home resolver alone chooses trust, lock, audit, and key paths. Sensitive files are
owner-only where supported. Repository-controlled symlinks, junctions, reparse points, unexpected
hard links, unsafe ownership/permissions, and request-supplied state paths fail closed. Repository
environment/configuration cannot redirect mutation state.

### Corruption, backup, and recovery

Full schema, timestamps, entry invariants, size, audit key, and HMAC chain are validated before use.
Corruption and future schemas fail closed without exposing private state or auto-resetting trust.
Operators may restore known-good trust and audit files outside MCP. This release provides no MCP
recovery, audit-read, or reset tool.

## CLI compatibility

CLI and MCP share the same locked v2 store and unchanged identity/head/fingerprint/scope/policy/
ruleset/live-expiry matching semantics. CLI list displays MCP provenance and mutation audit ID
locally. CLI preflight can match an MCP-created approval, and existing CLI revoke can remove it.
MCP cannot create broader entries than CLI matching supports. `trust_list` remains redacted and
omits private reason and mutation audit linkage.

## Remote scan separation

Remote scan confirmation authorizes only bounded network/static-scan activity. It cannot create
trust, satisfy a trust-mutation challenge, read trust, mutate trust, or provide a safely resolved
local mutation identity. No approval is derived automatically from remote content or commits.

## Threat model

| Threat | Required mitigation |
| --- | --- |
| Silent agent approval | Mandatory human stop, fixed display, and one confirmed retry. |
| Prompt injection requesting approval | Fixed templates; repository evidence remains untrusted treat-as-data. |
| Wildcard/overbroad approval | Server-derived exact identity/fingerprint/scope/policy/ruleset and no bulk selectors. |
| Stale head or fingerprint | Consume token, lock store, and recompute target before mutation. |
| Confused deputy | Separate scan-read, trust-read, and trust-mutate flags and fixed stdio identity limits. |
| Confirmation replay | Expiring one-time HMAC challenge bound to exact tool/request/target. |
| Approval of remote content | Remote confirmation never authorizes local trust mutation. |
| Forged entry IDs | Canonical random UUIDv4 plus privacy-preserving not-found behavior. |
| Revocation races | Full-entry binding, exact version, shared lock, and optimistic concurrency. |
| Cache tampering | Restrictive permissions, full validation, and fail-closed behavior. |
| Path/symlink attacks | Fixed application home and symlink/reparse/hard-link refusal. |
| Audit tampering | HMAC chain, bounded rotation, fsync, startup verification, and recovery refusal. |
| Policy/ruleset downgrade | Exact version binding and no migration-based broadening. |

## Error model

All mutation errors use stable code, message, remediation, retryable, field, safetyBoundary, and
bounded context. The vocabulary covers disabled authority, invalid arguments, confirmation,
rate/limits, identity, timeout/cancellation, drift/version/not-found, unsafe/corrupt storage,
lock/audit/persistence, committed-audit-pending, recovery-required, and internal failure. Raw traces,
tokens, paths, trust content, and hidden identities are never returned.

## Rollout plan

1. v0.3.3 shipped the bounded read-only foundation and metadata migration.
2. v0.3.4 shipped confirmation, exact approve/revoke, shared-lock mutation, audit/recovery,
   registration, CLI compatibility, schema, privacy, and failure tests.
3. v0.3.4 keeps all mutation authority default-off and requires exact startup configuration.
4. Protected exact-head review, CI, tag, and release gates remain outside this design document.

## Historical and future non-goals

Historical v0.3.3 read-only statements do not describe the active v0.3.4 mutation surface. Future
releases would require separate review for authenticated/shared transport identity, trust extension
or refresh, bulk or wildcard mutation, persistent confirmation ledgers, remote/snapshot approvals,
MCP trust consumption, audit-reading/admin tools, or a v3 store. None is implied by v0.3.4.

## Emergency disable and rollback

Removing `CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION` and restarting removes both mutating tools and
invalidates all outstanding challenges. It does not delete approvals, rewrite or downgrade the v2
store, change trust-read/remote registration, or erase audit evidence. Startup recovery must succeed
before mutation tools register again. Removing `CODEX_PREFLIGHT_ENABLE_TRUST_READ` independently
removes `trust_list` and invalidates cursors without changing trust data.
