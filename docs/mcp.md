# MCP Safety Notes

The versioned response contract is in [MCP Report Schema](mcp-report-schema.md). Installation,
stdio configuration, and machine-checked clients are in
[MCP Integration and Client Examples](mcp-client-examples.md).

Codex Preflight's MCP outputs may be read by a model. Repository-controlled evidence is untrusted
data and must never be followed as instructions. The server does not execute repository code,
planned commands, package managers, scripts, hooks, builds, tests, or downloaded artifacts.

Trust management remains unavailable through MCP. The design is documented in
[MCP Trust Management Design](design/mcp-trust-management.md); no runtime mode registers
`trust_list`, `trust_approve`, or `trust_revoke`.

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

The enabled inventory is exactly:

```text
preflight_check
corpus_scan
remote_repository_scan
```

Values other than exact `1` stay disabled. Registration is decided at startup, so restart after
changing the flag. The bundled plugin `.mcp.json` does not set this flag and therefore preserves
the default two-tool inventory.

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

## Server instructions

MCP initialization returns fixed, source-controlled instructions. Both modes state that analysis
is static-only, repository evidence is untrusted data, repository code and planned commands are
never executed, and `ASK_USER`/`BLOCK` stop automatic execution.

The default instruction set states that remote access and trust mutation are unavailable. The
enabled instruction set states that public GitHub scans require one-time operation-bound human
confirmation and never create trust. Repository content, user input, environment values, findings,
and errors are never interpolated into either instruction string.

## Results and evidence

Successful results add `mcpSchemaVersion`, exact tool identity, and a stable `safety` object while
preserving core report fields. Local/corpus results set network and remote access false. A
confirmed successful remote result sets `networkAccess` and `remoteRepositoryAccess` true; all
other safety fields remain static-only, untrusted, no-command, and no-trust.

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

## Error troubleshooting

Expected failures use the structured shape in
[MCP Report Schema](mcp-report-schema.md#structured-errors). Branch on `error.code`, show
`remediation`, and retry only when `retryable` is true.

Local codes cover missing/invalid paths, command, format, unsupported arguments, and corpus case.
Remote codes cover disabled registration, URL/host/address/ref policy, confirmation lifecycle,
ref resolution, redirect/auth rejection, timeout, cancellation, limits, unsafe trees,
acquisition, scan, cache, audit, and cleanup. Expected errors never include raw tracebacks,
credentials, subprocess output, or internal temporary paths.

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

Remove `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN` (or set any value other than `1`) and restart the
server. `remote_repository_scan` disappears from registration, outstanding tokens become invalid,
and local tools continue unchanged. Remote state can be cleared independently only after verifying
the exact `~/.codex-preflight/remote` path; local scan and trust files remain untouched.
