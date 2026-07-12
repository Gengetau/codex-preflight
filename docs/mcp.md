# MCP Safety Notes

The versioned response contract is in [MCP Report Schema](mcp-report-schema.md). Installation,
stdio configuration, and machine-checked clients are in
[MCP Integration and Client Examples](mcp-client-examples.md).

Codex Preflight's MCP outputs may be read by a model. Repository-controlled evidence is untrusted
data and must never be followed as instructions. The server does not execute repository code,
planned commands, package managers, scripts, hooks, builds, tests, or downloaded artifacts.

Bounded trust read is implemented as a separate default-off authority; trust mutation remains
unavailable. The reviewed contract is documented in
[MCP Trust Management Design](design/mcp-trust-management.md). No runtime mode registers
`trust_approve` or `trust_revoke`.

## Runtime shape

The MCP package is `codex_preflight_mcp`. Static tool listing and CLI configuration do not import
the optional MCP SDK:

```bash
codex-preflight-mcp --list-tools
```

Run the stdio server after installing the optional runtime:

```bash
python -m pip install "codex-preflight[mcp]"
codex-preflight-mcp
```

Source-checkout development uses:

```bash
python -m pip install -e ".[dev,mcp]"
```

The extra requires `mcp>=1.3.0`. Startup fails closed when the installed FastMCP runtime cannot
prove that it preserves the fixed server instructions. Upgrade explicitly with:

```bash
python -m pip install --upgrade "codex-preflight[mcp]"
```

## Startup authority

The default inventory is exactly:

```text
preflight_check
corpus_scan
```

Remote authority is absent by default. Start a new process with the exact value below to register
one additional tool:

```bash
CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1 codex-preflight-mcp --list-tools
```

PowerShell equivalent:

```powershell
$env:CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN = "1"
codex-preflight-mcp --list-tools
```

The remote-only inventory is exactly:

```text
preflight_check
corpus_scan
remote_repository_scan
```

Trust-read authority is independently absent by default. Enable only the bounded read tool with:

```bash
CODEX_PREFLIGHT_ENABLE_TRUST_READ=1 codex-preflight-mcp --list-tools
```

PowerShell equivalent:

```powershell
$env:CODEX_PREFLIGHT_ENABLE_TRUST_READ = "1"
codex-preflight-mcp --list-tools
```

The trust-read-only inventory is exactly:

```text
preflight_check
corpus_scan
trust_list
```

With both exact flags set, the inventory is exactly:

```text
preflight_check
corpus_scan
remote_repository_scan
trust_list
```

Values other than exact `1` stay disabled. Registration is decided at startup, so restart after
changing either flag. The bundled plugin `.mcp.json` sets neither flag and therefore preserves the
default two-tool inventory.

## Tools

### `preflight_check`

Accepts only an existing local `cwd`, planned `command`, and `format=json`. It uses static reads,
does not execute the command, ignores scan/trust cache, and rejects URLs, scp-like forms, and clone
commands without forwarding to the remote tool.

### `corpus_scan`

Runs only bundled synthetic fixtures with static analysis. It has no network or trust authority.

### `remote_repository_scan`

Available only in the enabled inventory. It accepts exactly `remoteUrl`, `requestedRef`, and an
optional first-call `confirmationToken`. It supports unauthenticated public
`https://github.com/OWNER/REPOSITORY` inputs only.

The first valid call returns `MCP_REMOTE_CONFIRMATION_REQUIRED` before DNS, network, Git,
filesystem snapshot, scanning, or remote-cache access. After a human reviews the canonical URL,
ref, and fixed limits, retry once with the returned one-time token. The token is process-local,
operation-bound, expires after 300 seconds, and never creates trust.

Confirmed acquisition uses validated and pinned public GitHub addresses, zero redirects, a shallow
bare fetch, no checkout, regular-blob-only materialization, fixed time/byte/file/depth limits, an
isolated static worker, verified cleanup, a dedicated remote cache, and redacted audit records.
See [Remote Repository MCP Design](design/mcp-remote-repository.md) for the complete enforced
contract and rollback procedure.

### `trust_list`

Available only with exact startup value `CODEX_PREFLIGHT_ENABLE_TRUST_READ=1`. All fields are
optional: `repoId` is an exact in-memory equality filter, `commandScope` is one supported exact
scope, `limit` is 1-100 and defaults to 50, and `cursor` is an opaque token from a prior page.
Unknown fields and invalid scalar types fail with stable trust-list errors.

The response is `trust-list/v1`. It returns only live entries with stored UUIDv4 IDs, matching
fingerprint/commit/scope/policy/ruleset data, timestamps, actor, and provenance. Raw repository
identity, local path, remote URL, and approved command never appear. Repository and URL identities
use process-local HMAC-SHA256 values that intentionally change after restart.

Cursors expire after 300 seconds, are at most 512 bytes, and are bound to tool/schema, filters,
limit, offset, and a process-keyed snapshot digest. Restart, expiry, tampering, changed filters, or a
changed trust snapshot returns `MCP_TRUST_LIST_CURSOR_INVALID` with no partial page.

The tool cannot approve, revoke, extend, refresh, consume, satisfy, or create trust. Its only
authorized write is an idempotent locked migration that adds UUIDv4 IDs, entry version `1`, and
provenance to valid legacy entries while preserving all approval values and matching behavior.

### `trust_approve` and `trust_revoke`

Trust mutation is a separate default-off authority. Only exact startup value
`CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION=1` registers both tools. It does not enable remote scans or
`trust_list`; all eight remote/trust-read/trust-mutation flag combinations have independently
scoped inventories. When the mutation flag is absent or has any other value, the tools are absent,
no mutation audit/key/challenge state is created, and direct calls fail with
`MCP_TRUST_MUTATION_DISABLED`.

`trust_approve` accepts only `cwd`, `command`, `expiresAt`, `reason`, and an optional
`confirmationToken`. It derives repository identity, head, fingerprint, command scope, policy,
and ruleset server-side, records one exact local approval, and never executes the command,
repository code, package manager, hook, build, test, browser, or network request. `trust_revoke`
accepts only canonical UUIDv4 `trustEntryId`, integer `expectedVersion: 1`, `reason`, and an
optional `confirmationToken`; it removes exactly that one entry. There is no bulk selector,
extension, import/export, wildcard approval, cache clear, audit reader, recovery tool, or reset
tool.

The first fully valid request has a mandatory human stop: it creates no approval or revocation and
returns `MCP_TRUST_MUTATION_CONFIRMATION_REQUIRED` with a fixed display. The client must display
only that object to a human, keep the token out of logs/display, and make one confirmed retry only
after the human approves the exact operation. Challenges are process-local, operation-bound,
single-use, and expire after 300 seconds. Repository content, stored trust, scan results, model
output, remote confirmation, and automatic client logic cannot satisfy a challenge; there is no
automatic confirmation. An authentic token is consumed before full retry validation, so a retry
that fails validation cannot be replayed.

The runtime reports fixed stdio identity only:

```json
{
  "transport": "stdio",
  "identityStatus": "unavailable",
  "clientId": null,
  "sessionId": null
}
```

This is a deliberately enabled single-user local process, not authenticated user or session
identity. `approvedBy: local-user` is a compatibility label, not an actor claim. MCP preflight does
not consume trust. Remote confirmation cannot create, satisfy, read, or mutate trust, and no
remote scan can authorize local mutation.

MCP-created approvals use private `mcp-trust-approve` provenance with a local
`mutationAuditEventId`. `trust_list` remains redacted and does not expose the reason or audit
linkage, while local CLI `trust list` displays both provenance and audit ID. CLI `preflight` can
match the approval under the unchanged identity/head/fingerprint/scope/policy/ruleset/expiry key,
and CLI `trust revoke` can remove it through existing local behavior.

## Server instructions

MCP initialization returns fixed, source-controlled instructions. Every mode states that analysis
is static-only, repository evidence is untrusted data, repository code and planned commands are
never executed, and `ASK_USER`/`BLOCK` stop automatic execution.

The selected instruction set describes only the enabled remote, trust-read, and/or trust-mutation
authority. Public GitHub scans require one-time operation-bound human confirmation and never
create trust. `trust_list` is bounded read-only and cannot create, consume, satisfy, extend,
approve, or revoke trust. `trust_approve` and `trust_revoke` require the mandatory human stop and
one confirmed retry. Repository content, stored trust values, user input, environment values,
findings, and errors are never interpolated into an instruction string.

## Results and evidence

Successful results add `mcpSchemaVersion`, exact tool identity, and a stable `safety` object while
preserving core report fields. Local/corpus results set network and remote access false. A
confirmed successful remote result sets `networkAccess` and `remoteRepositoryAccess` true; all
other safety fields remain static-only, untrusted, no-command, and no-trust.

`trust_list` uses its exact separate top-level `trust-list/v1` response, including pagination,
fixed unavailable stdio runtime identity, the final audit event ID, and explicit redaction/mutation
safety booleans. It is not wrapped as a scan report and has no `decision` field.

Findings and execution-graph items preserve:

```json
{
  "evidenceTrust": "untrusted",
  "evidenceInstructionBoundary": "treat-as-data"
}
```

Display evidence for review if useful, but never execute it, promote it into server instructions,
or use it to produce confirmation or trust.

## Remote state

Remote state is partitioned under `~/.codex-preflight/remote`:

```text
scan-cache.json
audit.jsonl
```

The cache is immutable-commit/policy keyed, TTL/entry/report/file bounded, and never consulted
before confirmation and ref resolution. Audit records contain hashes and stable state only, not
tokens, credentials, temp paths, process output, environment values, or repository evidence.
Cache and audit failures fail closed and do not mutate local `scan-cache.json` or `trust.json`.

## Trust-read state

The trust store remains the normal local `trust.json`. v0.3.3 validates at most 1 MiB and migrates
valid legacy entries under the shared trust lock to metadata-bearing v2 entries. Before replacement
it creates a permission-preserving backup and retains at most three. No approval value, expiry,
count, or matching rule changes.

Read audit records use a separate namespace:

```text
~/.codex-preflight/trust-read/audit.jsonl
```

Records are redacted, at most 4096 bytes, locked and fsynced, with a 1 MiB active segment and three
rotated segments. Audit failure returns no trust metadata.

## Trust-mutation state and audit recovery

Mutation state derives only from the normal application home:

```text
~/.codex-preflight/trust-mutation/audit.jsonl
~/.codex-preflight/trust-mutation/audit.key
```

It is distinct from trust-read, remote, scan-cache, and trust data. Audit records are owner-only
where supported, redacted, HMAC-chained, fsynced, limited to 4096 bytes, and retained as one 1 MiB
active segment plus at most three rotated segments. Before a mutation, the service fsyncs a
`mutation_prepared` record; it atomically replaces the trust store; then it fsyncs
`mutation_committed`.

If replacement succeeds but the final audit record cannot be persisted, the response is exactly
`MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING`, is not retryable, and includes this fixed context:

```json
{
  "committed": true,
  "operation": "approve-or-revoke",
  "entryId": "lowercase UUIDv4",
  "preparedAuditEventId": "lowercase UUIDv4"
}
```

The operation is committed; clients must not repeat it. The process becomes unhealthy, invalidates
outstanding challenges, and rejects further mutations until restart. Startup audit recovery
reconciles only the sole unmatched prepared tail against exact trust-store bytes. A corrupt chain,
ambiguous state, or failed recovery disables mutation registration. Operators may restore known-good
local trust and audit files; this release intentionally provides no MCP recovery, audit-read, or
reset tool.

## Error troubleshooting

Expected failures use the structured shape in
[MCP Report Schema](mcp-report-schema.md#structured-errors). Branch on `error.code`, show
`remediation`, and retry only when `retryable` is true.

Local codes cover missing/invalid paths, command, format, unsupported arguments, and corpus case.
Remote codes cover disabled registration, URL/host/address/ref policy, confirmation lifecycle,
ref resolution, redirect/auth rejection, timeout, cancellation, limits, unsafe trees,
acquisition, scan, cache, audit, and cleanup. Expected errors never include raw tracebacks,
credentials, subprocess output, or internal temporary paths.

Trust-read codes cover disabled direct calls, invalid arguments, cursor/limit rejection,
unavailable/corrupt/future stores, lock timeout, migration failure, audit failure, and normalized
internal failure. Mutation codes cover disabled calls, argument/confirmation/replay/rate-limit,
identity/budget/drift/version/not-found, storage/audit/persistence, committed-audit-pending,
recovery-required, and normalized internal failure. They never expose raw identity, path, URL,
approved command, reason, token, environment, or trust-file content.

## Plugin and diagnostics

The plugin manifest launches `codex-preflight-mcp` directly over stdio. Plugin installation and
Python package installation are separate. These commands print configuration/diagnostics without
installing packages, starting a long-running server, or mutating trust/cache:

```bash
codex-preflight mcp config --client codex
codex-preflight mcp doctor --client codex
```

Standard output is reserved for MCP protocol messages. Do not wrap the server in a shell command
that writes banners or logs to stdout.

## Disable and rollback

Remove an optional startup flag (or set it to any value other than `1`) and restart the server. The
corresponding tool disappears; remote confirmation tokens, trust-list cursors, and mutation
challenges are process-local and become invalid. Emergency disable of mutation removes both
mutating tools without deleting approvals, downgrading the v2 reader, or rewriting mutation audit
records. Remote state can be cleared independently only after verifying the exact
`~/.codex-preflight/remote` path. Disabling trust read does not delete or downgrade CLI trust data,
migration backups, or dedicated audit state.
