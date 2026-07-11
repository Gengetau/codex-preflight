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
| `tool` | Exact tool identity: `preflight_check`, `corpus_scan`, or opt-in `remote_repository_scan`. |
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
| `MCP_INTERNAL_ERROR` | An unexpected failure was hidden behind a safe generic response. |

Errors are not successful report objects and therefore do not carry the successful-result schema.

## Authority boundary

The default runtime registers exactly two tools:

```text
preflight_check
corpus_scan
```

With exact startup flag `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1`, registration adds only:

```text
remote_repository_scan
```

No mode exposes command execution, trust listing, trust approval, trust revocation, arbitrary
filesystem mutation, arbitrary network destinations, credentials, or proxy control. Removing the
flag and restarting restores the default two-tool, no-network inventory.
