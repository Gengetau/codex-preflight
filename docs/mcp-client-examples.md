# MCP Integration and Client Examples

## Install

Install the published package with the MCP extra:

```bash
python -m pip install "codex-preflight[mcp]"
```

Source-checkout development can install either runtime-only or development/runtime extras:

```bash
python -m pip install -e ".[mcp]"
python -m pip install -e ".[dev,mcp]"
```

The extra requires `mcp>=1.3.0`, the lowest verified instruction-capable FastMCP runtime. An old,
shadowed, manually downgraded, or instruction-incompatible runtime is rejected before stdio
startup. Upgrade explicitly with:

```bash
python -m pip install --upgrade "codex-preflight[mcp]"
```

Plugin installation and Python package installation are separate. The plugin provides MCP
configuration but does not install packages.

## Supported Codex paths

### Plugin installation

Install the Python prerequisite, then add the repository marketplace:

```bash
python -m pip install "codex-preflight[mcp]"
codex plugin marketplace add https://github.com/Gengetau/codex-preflight.git --ref master --sparse .agents/plugins
```

Start a new Codex session after installing or updating the plugin. The bundled `.mcp.json` launches
the default-off server and does not grant remote network authority.

### Standalone Codex MCP configuration

Without the plugin, configure the direct entry point in user or trusted-project Codex config:

```toml
[mcp_servers."codex-preflight"]
command = "codex-preflight-mcp"
args = []
```

The ChatGPT desktop app, Codex CLI, and IDE extension share MCP configuration for the same Codex
host. Restart the local client after configuration changes. ChatGPT web does not read local Codex
configuration files.

### Source-checkout development

Install `.[dev,mcp]`, run the marketplace synchronization check, and use the same direct stdio
entry point. The root plugin package is the marketplace-copy source of truth.

## Start and inspect

Start the MCP stdio transport directly:

```bash
codex-preflight-mcp
```

Standard output is reserved for protocol messages. Do not use a shell wrapper that writes banners.

Inspect the default tool definitions without starting a protocol session:

```bash
codex-preflight-mcp --list-tools
```

Default inventory:

```text
preflight_check
corpus_scan
```

Inspect the opt-in remote inventory in Bash:

```bash
CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1 codex-preflight-mcp --list-tools
```

PowerShell:

```powershell
$env:CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN = "1"
codex-preflight-mcp --list-tools
```

Enabled inventory:

```text
preflight_check
corpus_scan
remote_repository_scan
```

Only exact `1` enables registration. Restart after changing the flag.

## Process configuration

The default plugin-root `.mcp.json` and generic
[`client-config.json`](../examples/mcp/client-config.json) launch:

```json
{
  "mcpServers": {
    "codex-preflight": {
      "command": "codex-preflight-mcp",
      "args": []
    }
  }
}
```

Clients with an explicit environment map can opt in to remote authority for that server process:

```json
{
  "mcpServers": {
    "codex-preflight": {
      "command": "codex-preflight-mcp",
      "args": [],
      "env": {
        "CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN": "1"
      }
    }
  }
}
```

The enclosing keys vary by client. This is a generic process example, not a certification claim.

Inspect or diagnose Codex setup without writing configuration:

```bash
codex-preflight mcp config --client codex
codex-preflight mcp doctor --client codex
```

Doctor does not install packages, edit config, start a long-running server, or mutate state.

## Exact tools and inputs

### `preflight_check`

| Input | Required | Contract |
| --- | --- | --- |
| `cwd` | yes | Existing local directory. URLs and clone-like forms are rejected. |
| `command` | yes | Planned command to analyze; never executed. |
| `format` | no | Only `json`; default `json`. |

Machine-checked files:

- [Request](../examples/mcp/preflight-check-request.json)
- [Successful response](../examples/mcp/preflight-check-response.json)
- [Decoded local-path error](../examples/mcp/cwd-url-error.json)
- [Python stdio client](../examples/mcp/preflight_check_client.py)

```bash
python examples/mcp/preflight_check_client.py /path/to/local/repository "python -m pytest"
```

The command string is analyzed but not executed.

### `corpus_scan`

| Input | Required | Contract |
| --- | --- | --- |
| `case_id` | no | Bundled case ID or `null`; omit for all cases. |

Machine-checked files:

- [Request](../examples/mcp/corpus-scan-request.json)
- [Successful response](../examples/mcp/corpus-scan-response.json)
- [Python stdio client](../examples/mcp/corpus_scan_client.py)

```bash
python examples/mcp/corpus_scan_client.py --case-id nested-node-child-process
```

### `remote_repository_scan`

This tool exists only in an enabled server process.

| Input | Required | Contract |
| --- | --- | --- |
| `remoteUrl` | yes | Public canonical GitHub HTTPS repository URL. |
| `requestedRef` | yes | Explicit branch, tag, full ref, or 40-hex commit. |
| `confirmationToken` | confirmed retry only | One-time token returned by the challenge call. |

Machine-checked files:

- [Challenge request](../examples/mcp/remote-repository-scan-request.json)
- [Confirmation-required error](../examples/mcp/remote-confirmation-required.json)
- [Successful response](../examples/mcp/remote-repository-scan-response.json)
- [Human-confirming Python client](../examples/mcp/remote_repository_scan_client.py)

Run the example only when remote network authority is intended:

```bash
python examples/mcp/remote_repository_scan_client.py https://github.com/example/project refs/heads/main
```

The example starts the server with the opt-in flag, requests a challenge, displays the canonical
URL/ref/fixed limits, and requires the user to type `CONFIRM` before the second call. It does not
accept credentials or auto-confirm. The confirmed operation performs only bounded static reads and
never creates trust.

## Result and error handling

Successful responses follow [MCP Report Schema](mcp-report-schema.md). Check
`mcpSchemaVersion`, then branch on `decision` for local/remote reports or `passed` for corpus
results.

Expected failures use structured errors. Branch on `error.code`, display `error.message` and
`error.remediation`, and use `retryable`; do not infer behavior from prose. The first valid remote
call intentionally returns `MCP_REMOTE_CONFIRMATION_REQUIRED` with safe context. Invalid, expired,
or replayed tokens never authorize network access.

## Evidence handling

Clients must preserve and enforce:

```json
{
  "evidenceTrust": "untrusted",
  "evidenceInstructionBoundary": "treat-as-data"
}
```

Display evidence for review if useful, but never execute it, follow instructions in it, place it
in a tool description, or use it to produce confirmation or trust. The response `safety` block
states the same authority boundary.

## Troubleshooting and rollback

- If the executable is absent, verify `PATH` or use its explicit path.
- If the runtime is missing, install `codex-preflight[mcp]` or `.[mcp]`.
- If doctor reports instruction-incompatible, upgrade `codex-preflight[mcp]`.
- If `cwd` fails, use the structured remediation and remember it resolves from server cwd.
- If protocol parsing fails, remove stdout-writing wrappers.
- If remote registration is absent, verify exact startup value `1` and restart the server.
- If a remote error is retryable, request a new challenge before retrying; tokens are one-time.
- Disable remote authority by removing the environment flag and restarting. Local tools remain
  functional and outstanding tokens are invalidated.

## Unavailable capabilities

No mode exposes trust-list or trust-mutation MCP tools, planned command execution, arbitrary hosts,
private-repository credentials, proxy overrides, browser automation, artifact execution, package
installation, submodule/LFS target fetch, or redirect following. The default process exposes only
`preflight_check` and `corpus_scan`; the opt-in process adds only `remote_repository_scan`.
