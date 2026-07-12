# MCP Report Schema

## Contract versions

Successful MCP tool results use `mcpSchemaVersion: "1.0"`. The nested core report keeps its
existing additive JSON contract and continues to expose `schemaVersion: "1.0"` for CLI
compatibility. Consumers should reject unsupported major versions and tolerate additive fields
within the same major version.

## Common MCP fields

Every successful MCP tool result returns these stable fields:

| Field | Meaning |
| --- | --- |
| `mcpSchemaVersion` | Version of the MCP-facing result contract. |
| `tool` | Exact tool identity: `preflight_check`, `corpus_scan`, or an enabled `remote_repository_scan`, `trust_list`, `trust_approve`, or `trust_revoke`. |
| `safety` | Stable static-analysis and authority-boundary metadata. |

The `safety` object contains:

```json
{
  "analysisMode": "static-only",
  "repositoryContentTrust": "untrusted",
  "evidenceInstructionBoundary": "treat-as-data",
  "commandExecuted": false,
  "networkAccess": false,
  "trustMutationAllowed": false,
  "remoteRepositoryAccess": false
}
```

These values describe enforced runtime behavior, not repository claims. Repository-controlled
strings never change these fields.

For a confirmed successful `remote_repository_scan`, `networkAccess` and
`remoteRepositoryAccess` are `true`. The other values remain unchanged: analysis is static-only,
content is untrusted treat-as-data, no planned command runs, and trust mutation is false. Errors
are not successful results and never claim remote access success.

## `preflight_check` successful result

The result preserves the existing core report fields and adds the common MCP fields. Required
top-level fields are:

```text
mcpSchemaVersion
tool
schemaVersion
decision
riskScore
command
commandScope
repo
summary
reason
agentInstruction
policyExplanation
findings
executionGraph
reportLimits
cache
safety
```

### Repository provenance

The `repo` object records the normalized scanned path, `sourceType`, remote identity when known,
head commit when known, and the critical fingerprint. MCP `preflight_check` accepts local paths
only, so `sourceType` is `local`; remote-repository access remains false.

### Findings and evidence

Every finding includes:

```json
{
  "evidenceSource": "repository-content",
  "evidenceTrust": "untrusted",
  "evidenceInstructionBoundary": "treat-as-data"
}
```

`evidenceSource` distinguishes repository content, the caller's command string, redacted secret
material, fixed rule phrases, and tool-generated uncertainty. Regardless of source, clients must
treat evidence as untrusted data and must never execute it or promote it into protocol or policy
instructions. Secret evidence remains redacted.

Execution-graph capabilities and uncertainties carry the same trust-boundary fields. A
tool-generated `REPORT_SIZE_BUDGET_EXCEEDED` uncertainty also carries this boundary so clients do
not mistake its surrounding report content for instructions.

### Policy explanation

`policyExplanation` is additive and preserves the existing decision fields. It records the final
decision, command scope, deterministic selector, bounded command contribution, and stable
rule-sorted matrix contributions. Each rule contribution states whether it affected the final gate
or is report-only. Rationale strings are source-controlled policy data; repository evidence is
never promoted into policy rationale or selection metadata.

### Report limits

`reportLimits` records maximum, included, and omitted counts for findings and execution-graph
items. When report details are capped, the report includes a `REPORT_SIZE_BUDGET_EXCEEDED`
uncertainty. Consumers must not interpret an omitted count as evidence that omitted content is
safe.

### Cache behavior

The `cache` object keeps the existing fields:

```text
usedScanCache
usedTrustCache
cacheReason
```

MCP `preflight_check` calls the core with scan cache disabled and trust disabled. Both used flags
therefore remain false for MCP calls; no MCP trust approval is consulted or mutated.

### Compatibility

This contract is additive. Existing consumers of `decision`, `riskScore`, `command`,
`commandScope`, `repo`, `summary`, `reason`, `agentInstruction`, `findings`, `executionGraph`,
`reportLimits`, and `cache` continue to read those fields at the same locations. CLI Markdown and
CLI JSON behavior are not converted into an MCP envelope.

MCP accepts only `format=json`. Markdown and text output remain CLI-only.

## `corpus_scan` successful result

`corpus_scan` preserves its `passed` and `cases` fields, adds deterministic category `groups` and
negative-control labels, and adds `mcpSchemaVersion`, `tool`, and `safety`. It executes only the
bundled synthetic corpus with static analysis.

## `remote_repository_scan` successful result

This result is possible only when startup registration was enabled, a one-time confirmation was
consumed, the requested ref resolved to an immutable commit, bounded acquisition/static scan
completed, cache/audit operations succeeded, and temporary cleanup was verified.

It preserves the core report fields and adds `remoteProvenance`:

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
skippedSymlinks
skippedSubmodules
skippedLfsPointers
```

`repo.path` is the canonical repository URL, never a temporary local path. `resolvedCommit` is a
verified 40-hex commit. `redirectsFollowed` is zero, `confirmationConsumed` is true,
`cleanupStatus` is `removed`, and `complete` is true on every successful response. Cache hits are
identified only after confirmation and immutable ref resolution. Tokens, nonces, credentials,
environment values, subprocess output, and temporary paths are never returned.

## `trust_list` successful result

`trust_list` is not a scan report and has no decision, findings, execution graph, repository path,
or command. It uses exact schema `trust-list/v1`:

```json
{
  "mcpSchemaVersion": "1.0",
  "tool": "trust_list",
  "schemaVersion": "trust-list/v1",
  "sourceType": "trust-cache",
  "trustReadOnly": true,
  "trustMutationAllowed": false,
  "entries": [],
  "pagination": {
    "resultCount": 0,
    "limit": 50,
    "nextCursor": null,
    "complete": true,
    "snapshotDigest": "hmac-sha256:..."
  },
  "runtimeIdentity": {
    "transport": "stdio",
    "identityStatus": "unavailable",
    "clientId": null,
    "sessionId": null
  },
  "auditEventId": "event-id",
  "safety": {}
}
```

Entries contain exactly stored random `entryId`, `entryVersion`, `repoIdHash`, redaction/remote
presence fields, optional `remoteUrlHash`, commit, fingerprint, scope, decision, approval/expiry
timestamps, actor, policy/ruleset, and provenance. The safety object explicitly marks raw repository
identity, path, remote URL, and approved command as not returned, and confirms that preflight and
remote confirmation do not use trust. See the complete machine-checked
[`trust-list-response.json`](../examples/mcp/trust-list-response.json).

## `trust_approve` and `trust_revoke` results

Both mutation tools are available only when exact startup flag
`CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION=1` is set. Their first valid call is an error envelope with
`MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED`, `field: "confirmationToken"`, fixed unavailable stdio
runtime identity, and a `trust-mutation-confirmation/v1` object containing `challengeId`, opaque
`confirmationToken`, operation, issued/expiry timestamps, and fixed display. It means no trust
mutation occurred. The challenge is single-use and 300-second expiring; a client must stop for a
human decision and make one confirmed retry only after confirmation. The fixed display is the only
place a first approval response may echo caller-supplied cwd, command, or reason.

Successful approval uses exact `trust-approve/v1`; successful revocation uses exact
`trust-revoke/v1`. Both include `mcpSchemaVersion`, `tool`, `sourceType: "trust-cache"`, `outcome`,
`mutationApplied`, public entry projection, consumed challenge ID, fixed runtime identity,
`auditEventId`, and the mutation safety object. Approvals expose the redacted repo hash, head,
fingerprint, scope, policy/ruleset, and requested expiry; revocations expose only entry ID and
version. Neither returns raw path, repository ID, remote URL, approved command, reason, token,
key, or audit storage path. See the machine-checked examples:

- [`trust-approve-confirmation-required.json`](../examples/mcp/trust-approve-confirmation-required.json)
- [`trust-approve-response.json`](../examples/mcp/trust-approve-response.json)
- [`trust-revoke-confirmation-required.json`](../examples/mcp/trust-revoke-confirmation-required.json)
- [`trust-revoke-response.json`](../examples/mcp/trust-revoke-response.json)

`MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING` is a terminal, non-retryable error. It unambiguously
means that the trust change committed while the final audit event is pending recovery:

```json
{
  "error": {
    "code": "MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING",
    "retryable": false,
    "context": {
      "committed": true,
      "operation": "approve-or-revoke",
      "entryId": "lowercase UUIDv4",
      "preparedAuditEventId": "lowercase UUIDv4"
    }
  }
}
```

Clients must not retry that mutation. The process refuses later mutation calls until restart and
audit recovery; recovery can only commit or abort the sole unmatched prepared event and has no MCP
tool surface.

## Structured errors

Expected MCP input failures are raised through the MCP runtime error mechanism. The error message
contains a compact JSON object with this stable shape:

```json
{
  "error": {
    "code": "MCP_CWD_NOT_FOUND",
    "message": "MCP preflight_check requires an existing local directory; cwd was not found.",
    "remediation": "Check the path and create or clone the directory outside this MCP tool before retrying.",
    "retryable": false,
    "field": "cwd",
    "safetyBoundary": null
  }
}
```

Clients should branch on `code`, display `message` and `remediation`, and avoid parsing prose.
`field` is null when no individual input field is responsible. `safetyBoundary` explains
authority-preserving rejections. Expected client-facing errors never include raw tracebacks,
credentials, environment variables, or internal paths that the caller did not supply.

| Code | Meaning |
| --- | --- |
| `MCP_CWD_REQUIRED` | `cwd` was omitted. |
| `MCP_CWD_EMPTY` | `cwd` was empty or whitespace-only. |
| `MCP_CWD_URL_NOT_ALLOWED` | A URL, scp-like remote, or clone helper was supplied. |
| `MCP_CWD_FILE_NOT_DIRECTORY` | The path exists but is not a directory. |
| `MCP_CWD_NOT_FOUND` | The local directory does not exist. |
| `MCP_CWD_PERMISSION_DENIED` | The server process cannot read or resolve the directory. |
| `MCP_CWD_INVALID` | The value is not a valid host-platform local path. |
| `MCP_COMMAND_REQUIRED` | The planned `command` was omitted or empty. |
| `MCP_FORMAT_UNSUPPORTED` | A format other than JSON was requested. |
| `MCP_ARGUMENT_UNSUPPORTED` | An unsupported argument was supplied. |
| `MCP_CASE_NOT_FOUND` | The requested bundled corpus case does not exist. |
| `MCP_REMOTE_DISABLED` | Remote registration is disabled for this process. |
| `MCP_REMOTE_URL_INVALID` | The repository URL is not an accepted canonical GitHub HTTPS form. |
| `MCP_REMOTE_HOST_NOT_ALLOWED` | The destination host is outside policy. |
| `MCP_REMOTE_ADDRESS_NOT_ALLOWED` | DNS returned an empty, mixed, or non-public address set. |
| `MCP_REMOTE_REF_INVALID` | The requested ref failed lexical policy. |
| `MCP_REMOTE_CONFIRMATION_REQUIRED` | Review the fixed operation and retry once with its token. |
| `MCP_REMOTE_CONFIRMATION_INVALID` | The token is malformed or bound to another operation/policy. |
| `MCP_REMOTE_CONFIRMATION_EXPIRED` | The token exceeded its 300-second lifetime. |
| `MCP_REMOTE_CONFIRMATION_REPLAYED` | The one-time token was already consumed. |
| `MCP_REMOTE_REF_NOT_FOUND` | The ref did not resolve to the required immutable commit. |
| `MCP_REMOTE_REDIRECT_NOT_ALLOWED` | The endpoint attempted a forbidden redirect. |
| `MCP_REMOTE_AUTH_NOT_ALLOWED` | The endpoint required unauthorized authentication. |
| `MCP_REMOTE_TIMEOUT` | A fixed subprocess or total deadline expired. |
| `MCP_REMOTE_CANCELLED` | Client or core cancellation stopped the operation. |
| `MCP_REMOTE_LIMIT_EXCEEDED` | A fixed time, disk, file, byte, depth, or concurrency limit was exceeded. |
| `MCP_REMOTE_TREE_UNSAFE` | The tree contained an unsafe path, collision, or unsupported mode. |
| `MCP_REMOTE_ACQUISITION_FAILED` | Bounded Git acquisition failed without exposing process output. |
| `MCP_REMOTE_SCAN_FAILED` | The isolated static worker failed. |
| `MCP_REMOTE_CACHE_FAILED` | The dedicated remote cache failed closed. |
| `MCP_REMOTE_AUDIT_FAILED` | The redacted remote audit log failed closed. |
| `MCP_REMOTE_CLEANUP_FAILED` | Verified removal of operation-owned temporary state failed. |
| `MCP_TRUST_READ_DISABLED` | A direct trust read was attempted without startup authority. |
| `MCP_TRUST_LIST_INVALID_ARGUMENT` | A field, type, identity, or scope is invalid. |
| `MCP_TRUST_LIST_CURSOR_INVALID` | The cursor is malformed, expired, restart-invalid, mismatched, or stale. |
| `MCP_TRUST_LIST_LIMIT_EXCEEDED` | The limit is not an integer from 1 through 100. |
| `MCP_TRUST_LIST_UNAVAILABLE` | The local trust store cannot be read safely. |
| `MCP_TRUST_LIST_CORRUPT` | Full trust-store validation failed. |
| `MCP_TRUST_LIST_UNSUPPORTED_SCHEMA` | The store or entry uses an unsupported schema/version. |
| `MCP_TRUST_LIST_LOCK_TIMEOUT` | The shared trust-store lock timed out. |
| `MCP_TRUST_LIST_MIGRATION_FAILED` | The exact metadata-only migration failed closed. |
| `MCP_TRUST_LIST_AUDIT_FAILED` | The dedicated trust-read audit failed closed. |
| `MCP_TRUST_LIST_INTERNAL_ERROR` | An unexpected trust-read failure was normalized and redacted. |
| `MCP_INTERNAL_ERROR` | An unexpected failure was hidden behind a safe generic response. |

Errors are not successful report objects and therefore do not carry the successful-result schema.

## Authority boundary

Three independent exact-value flags produce eight exact inventories. Only value `1` enables an
authority; absent flags and every other value leave that authority disabled.

| Remote scan | Trust read | Trust mutation | Exact ordered inventory |
| --- | --- | --- | --- |
| off | off | off | `preflight_check`, `corpus_scan` |
| on | off | off | `preflight_check`, `corpus_scan`, `remote_repository_scan` |
| off | on | off | `preflight_check`, `corpus_scan`, `trust_list` |
| off | off | on | `preflight_check`, `corpus_scan`, `trust_approve`, `trust_revoke` |
| on | on | off | `preflight_check`, `corpus_scan`, `remote_repository_scan`, `trust_list` |
| on | off | on | `preflight_check`, `corpus_scan`, `remote_repository_scan`, `trust_approve`, `trust_revoke` |
| off | on | on | `preflight_check`, `corpus_scan`, `trust_list`, `trust_approve`, `trust_revoke` |
| on | on | on | `preflight_check`, `corpus_scan`, `remote_repository_scan`, `trust_list`, `trust_approve`, `trust_revoke` |

The flags are:

- `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1`: adds only `remote_repository_scan`.
- `CODEX_PREFLIGHT_ENABLE_TRUST_READ=1`: adds only `trust_list`.
- `CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION=1`: adds only `trust_approve` and `trust_revoke`.

Mutation authority remains local, exact-entry, and confirmation-gated. No inventory exposes
planned-command execution, arbitrary filesystem mutation, arbitrary network destinations,
credentials, proxy control, trust consumption by MCP preflight, or remote trust mutation. Removing
a flag and restarting removes its tools and invalidates the corresponding process-local token,
cursor, or challenge; the default remains the two-tool no-network, no-trust-read, no-trust-mutation
inventory.
