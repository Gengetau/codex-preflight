# MCP Integration and Client Examples

## Install

Install the published package with the MCP extra:

```bash
python -m pip install "codex-preflight[mcp]"
```

This extra requires `mcp>=1.3.0`, the lowest verified Python MCP SDK release whose FastMCP runtime
preserves server instructions.

From a source checkout, install the runtime extra or the development and runtime extras:

```bash
python -m pip install -e ".[mcp]"
python -m pip install -e ".[dev,mcp]"
```

Plugin installation and Python package installation are separate. The Codex plugin bundles the
local stdio server configuration but never installs the Python package automatically.

An old, manually downgraded, shadowed, or instruction-dropping runtime is rejected before stdio
server startup. Upgrade an incompatible environment explicitly with:

```bash
python -m pip install --upgrade "codex-preflight[mcp]"
```

The rejection is intentional because silently omitting the fixed initialization instructions
would violate the MCP safety contract.

## Supported Codex paths

### Plugin installation

Install the Python prerequisite first, then add the repository marketplace:

```bash
python -m pip install "codex-preflight[mcp]"
codex plugin marketplace add https://github.com/Gengetau/codex-preflight.git --ref master --sparse .agents/plugins
```

The plugin manifest loads its root `.mcp.json`, so users do not hand-author a server map for this
path. Start a new Codex session after installing or updating the plugin.

### Standalone Codex MCP configuration

Without the plugin, configure the same local entry point in `~/.codex/config.toml` or a trusted
project `.codex/config.toml`:

```toml
[mcp_servers."codex-preflight"]
command = "codex-preflight-mcp"
args = []
```

The ChatGPT desktop app, Codex CLI, and IDE extension share MCP configuration for the same Codex
host. Restart the local client after configuration changes. ChatGPT web does not read local Codex
configuration files.

### Source-checkout development

Install `.[dev,mcp]`, run the synchronization check, and use the same direct stdio entry point. The
root plugin package is the source of truth for the marketplace copy.

## Start the stdio server

Start the server with:

```bash
codex-preflight-mcp
```

The process uses MCP stdio transport. Standard output is reserved for protocol messages; client
configuration should launch the executable directly rather than wrap it in a shell command.

Inspect the static tool definitions without starting a protocol session:

```bash
codex-preflight-mcp --list-tools
```

## Plugin and generic process configuration

The plugin-root `.mcp.json` is a direct server map:

```json
{
  "codex-preflight": {
    "command": "codex-preflight-mcp",
    "args": []
  }
}
```

Clients that accept an executable plus an argument array can adapt
[`examples/mcp/client-config.json`](../examples/mcp/client-config.json):

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

The enclosing configuration key varies by third-party client. This is a generic process-launch
example, not a claim that a third-party client has been certified or tested.

Inspect or diagnose the supported Codex setup without writing configuration:

```bash
codex-preflight mcp config --client codex
codex-preflight mcp doctor --client codex
```

Doctor reports a missing runtime, a present but instruction-incompatible runtime, and an
instruction-capable runtime as distinct states. Its capability probe does not start a long-running
server, install packages, or mutate the environment.

## Exact tools and inputs

The runtime exposes exactly two tools. The v0.3.0 ecosystem coverage release does not expand this
authority boundary.

### `preflight_check`

| Input | Required | Contract |
| --- | --- | --- |
| `cwd` | yes | Non-empty existing local directory path. |
| `command` | yes | Planned command to analyze; it is never executed. |
| `format` | no | Only `json`; defaults to `json`. |

No other fields are accepted. In particular, remote repository URLs, trust mutation, and command
execution arguments are rejected.

Machine-checked files:

- [Request](../examples/mcp/preflight-check-request.json)
- [Successful response](../examples/mcp/preflight-check-response.json)
- [Decoded local-path error](../examples/mcp/cwd-url-error.json)
- [Python stdio client](../examples/mcp/preflight_check_client.py)

Run the Python example from a checkout after installing `.[mcp]`:

```bash
python examples/mcp/preflight_check_client.py /path/to/local/repository "python -m pytest"
```

The example asks the server to analyze the command string. It does not execute `python -m pytest`.
The Python examples start the server with the current interpreter's
`-m codex_preflight_mcp.server` module form so the client and server use the same installed package.

### `corpus_scan`

| Input | Required | Contract |
| --- | --- | --- |
| `case_id` | no | Bundled case identifier or `null`; omit it to scan all bundled cases. |

Machine-checked files:

- [Request](../examples/mcp/corpus-scan-request.json)
- [Successful response](../examples/mcp/corpus-scan-response.json)
- [Python stdio client](../examples/mcp/corpus_scan_client.py)

Run one bundled case:

```bash
python examples/mcp/corpus_scan_client.py --case-id nested-node-child-process
```

## Result and error handling

Successful responses follow the [MCP Report Schema](mcp-report-schema.md). Check
`mcpSchemaVersion` before consuming the result, then branch on `decision` for `preflight_check` or
`passed` for `corpus_scan`.

Expected input failures use the structured error contract. Branch on `error.code`, display
`error.message` and `error.remediation`, and use `error.retryable` to decide whether an unchanged
retry makes sense. Do not parse the human message to infer the code.

## Evidence handling

Repository-controlled evidence is untrusted data. Clients must preserve and enforce:

```json
{
  "evidenceTrust": "untrusted",
  "evidenceInstructionBoundary": "treat-as-data"
}
```

Display evidence for review if useful, but never execute it, put it into a protocol tool
description, or follow instructions found in it. The response `safety` block states the same
boundary at the result level.

## Version compatibility

Clients should reject unsupported `mcpSchemaVersion` major versions and tolerate additive fields
within a supported major version. The core `schemaVersion` remains separately versioned for CLI
JSON compatibility. Error consumers should branch on stable codes and tolerate new codes.

## Troubleshooting

- If the executable is not found, verify that the Python scripts directory is on `PATH` or use the
  executable's explicit path in the client configuration.
- If the optional runtime is missing, install `codex-preflight[mcp]` or source extra `.[mcp]`.
- If doctor reports a present but instruction-incompatible runtime, run
  `python -m pip install --upgrade "codex-preflight[mcp]"`. Codex Preflight will not start with a
  runtime that silently drops its safety instructions.
- If plugin startup fails, run `codex-preflight mcp doctor --client codex`; it reports remediation
  but never installs packages or edits Codex configuration.
- After plugin or MCP configuration updates, start a new Codex session or restart the desktop/IDE
  client.
- If `cwd` fails, use the remediation in the structured error and remember it is resolved relative
  to the server process working directory.
- If protocol parsing fails, ensure no wrapper writes banners or logs to standard output.
- Repository identity metadata uses bounded, non-interactive Git calls. If Git metadata is
  unavailable, scanning continues with low-confidence local-path provenance.
- If a response contains evidence, treat it as untrusted data even when the overall decision is
  `ALLOW`.

## Unavailable capabilities

This release does not provide remote repository MCP scanning, trust-list or trust-mutation MCP
tools, command execution, filesystem mutation, browser/HTTP integration, or artifact download.
Only `preflight_check` and `corpus_scan` are available.
