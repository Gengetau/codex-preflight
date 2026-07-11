# Codex Preflight

![CI](https://img.shields.io/badge/CI-passing-brightgreen)
![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![Static analysis](https://img.shields.io/badge/static-analysis-informational)
![Local first](https://img.shields.io/badge/local--first-yes-success)
![No code execution](https://img.shields.io/badge/no%20code%20execution-enforced-success)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

Local-first, command-aware, pre-execution, execution-chain preflight for Codex-style AI coding
agents.

Codex Preflight statically scans a repository before risky commands run, analyzes the planned
command itself, builds a best-effort execution graph of reachable local scripts/files, detects
dangerous capabilities and uncertainty, and returns `ALLOW`, `WARN`, `ASK_USER`, or `BLOCK`
decisions with JSON/Markdown reports.

Codex Preflight is open-source software licensed under the Apache License 2.0.

## Why This Exists

AI coding agents often need to run commands such as dependency installation, shell scripts, Docker
commands, test/build commands, or MCP startup commands. Those commands can be risky when the
repository is unfamiliar or untrusted: package lifecycle scripts can run automatically, Docker can
mount host resources, shell scripts can download and execute remote content, and agent instruction
files can try to steer the agent toward unsafe behavior.

Codex Preflight sits before command execution and answers:

> Should this command run in this repository right now?

## What It Solves

Codex Preflight gives an agent a local, explainable safety gate before it runs a command. It does
not try to prove a repository is safe. Instead, it catches high-signal static risks, traces obvious
local indirection, surfaces uncertainty, and gives the user a decision with evidence.

## Key Features

- Local repository preflight.
- External GitHub repository scan via `--repo`.
- Composite command classification.
- Planned-command risk findings for remote shell pipelines, encoded PowerShell, dangerous Docker
  flags and mounts, and inline interpreter execution.
- Static README link-poisoning detection for fake release links, non-release installer/download
  hosts, raw source archive downloads, and security-warning bypass wording.
- Static Rust and Go ecosystem coverage for Cargo build scripts, Cargo source replacement,
  Cargo aliases, git-sourced Cargo lock entries, Go generator directives, TestMain hooks, cgo
  indicators, and Go module replacements.
- Reachability parsing for common wrappers such as shell `-c`, interpreter flags, `env`,
  package-manager wrappers, PowerShell, `cmd /c`, and Windows-style paths.
- Cross-file Node.js module reachability for local `require()` and `import` chains.
- Evidence trust-boundary labels for repository-controlled snippets.
- Nested monorepo critical file collection.
- Package lifecycle detection.
- Shell, Docker, GitHub Actions, MCP, agent instruction, Rust, Go, and secret checks.
- Execution graph for reachable local scripts/files.
- Capability detection for Node.js, Python, shell, and Docker.
- Uncertainty policy: unknown is not safe.
- Trust and cache management.
- Synthetic historical attack-pattern corpus.
- JSON and Markdown reports.
- `exec` wrapper for command gating.

## How It Works

```text
planned command
  -> command classifier
  -> command self-risk analysis
  -> critical file collection
  -> static scanner rules
  -> reachability execution graph
  -> capability / uncertainty findings
  -> policy decision
  -> JSON / Markdown report
```

Codex Preflight uses bounded safe reads and never executes repository code. Reachability follows
only statically visible local paths inside the repository and reports missing, dynamic,
outside-repo, symlink, oversized, binary, or incomplete paths as uncertainty. README
link-poisoning detection is static-only: it parses local repository documentation and does not fetch
linked pages, download artifacts, recursively scan linked repositories, use browser automation, or
call GitHub metadata APIs.

## Safety Model

Codex Preflight is local-first: repository files are read on the local machine, and reports are
generated locally. The scanner does not run package install scripts, shell payloads, Docker, MCP
servers, test commands from fixtures, or repository code. The CLI is intentionally scanner-first:
it does not include a web dashboard, SaaS backend, cloud upload, database server, browser
extension, or IDE extension.

Policy decisions:

- `ALLOW`: no relevant static risk findings were detected.
- `WARN`: low or contextual risk; proceed only after summarizing the warning.
- `ASK_USER`: do not execute automatically; summarize and ask the user.
- `BLOCK`: do not execute; explain the blocking finding.

## Quick Start

Install locally:

```bash
pip install -e ".[dev]"
codex-preflight --help
```

Run a scan before a command:

```bash
codex-preflight preflight --cwd . --command "pytest" --format json
```

Wrap command execution:

```bash
codex-preflight exec --cwd . --format markdown -- pytest
```

The exec wrapper runs the command only when preflight returns `ALLOW` or `WARN`. It prints a
readable report and exits without running the command for `ASK_USER` or `BLOCK`.

## Codex Plugin Usage

Codex Preflight remains a Python CLI project and is also packaged as a Codex plugin that bundles
the operational skill and the existing local stdio MCP server configuration.

The plugin package contains:

- `.codex-plugin/plugin.json`: Codex plugin manifest.
- `.mcp.json`: direct local stdio server map for `codex-preflight-mcp`.
- `skills/codex-preflight/SKILL.md`: English skill instructions for when and how Codex should call
  `codex-preflight`.
- `.agents/plugins/marketplace.json`: Codex marketplace root manifest for the Codex UI
  "Add marketplace" flow.
- `.agents/plugins/plugins/codex-preflight/`: marketplace-packaged copy of the plugin referenced by
  the marketplace root.

The manifest declares `mcpServers: "./.mcp.json"`. It does not declare an App, remote MCP URL,
credentials, shell wrapper, or repository-controlled startup arguments.

When Codex is about to run a risky command in a local or unfamiliar repository, it should run:

```bash
codex-preflight preflight --cwd . --command "<planned command>" --format markdown
```

Codex must respect the resulting decision:

- `ALLOW`: the command may proceed.
- `WARN`: summarize the warning before proceeding.
- `ASK_USER`: stop and ask the user.
- `BLOCK`: do not run the command.

Install the Python MCP prerequisite first. Plugin installation does not install packages or modify
the Python environment:

```bash
python -m pip install "codex-preflight[mcp]"
```

The MCP extra requires `mcp>=1.3.0`, the lowest verified Python MCP SDK release whose
FastMCP runtime preserves server instructions. An old, manually downgraded, shadowed, or
instruction-dropping runtime is rejected before stdio server startup. Upgrade an incompatible
environment explicitly with:

```bash
python -m pip install --upgrade "codex-preflight[mcp]"
```

This fail-closed behavior is intentional: silently omitting the fixed server instructions would
violate the MCP safety contract. `mcp doctor` reports a missing runtime, a present but
instruction-incompatible runtime, and an instruction-capable runtime as distinct states; it does
not install or upgrade packages.

Then add this repository through the Codex UI "Add marketplace" flow with:

- Source: `https://github.com/Gengetau/codex-preflight.git`
- Git ref: `master`
- Sparse path: `.agents/plugins`

The equivalent CLI marketplace command is:

```bash
codex plugin marketplace add https://github.com/Gengetau/codex-preflight.git --ref master --sparse .agents/plugins
```

Use the marketplace sparse path, not `.codex-plugin`. `.codex-plugin/plugin.json` is the plugin
manifest, while `.agents/plugins/marketplace.json` is the marketplace root manifest that the UI
expects.

Do not use `git@github.com:Gengetau/codex-preflight.git` unless SSH host keys and credentials are
configured in the Codex runtime. If SSH fails with "Host key verification failed", use the HTTPS
source URL above.

After marketplace, plugin, or MCP configuration changes, reinstall or refresh according to the
official Plugin Creator workflow and start a new Codex session so the updated skill and server are
loaded.

Inspect the supported configuration or diagnose prerequisites without changing files:

```bash
codex-preflight mcp config --client codex
codex-preflight mcp doctor --client codex
```

The ChatGPT desktop app, Codex CLI, and IDE extension share MCP configuration for the same Codex
host. Standalone configuration remains available when the plugin is not used; see
[MCP Integration and Client Examples](docs/mcp-client-examples.md).

More details are in [docs/plugin.md](docs/plugin.md).

## MCP

The MCP-facing package is read-only and local-path-only. It exposes static preflight checks
and bundled corpus scans, but does not expose remote repository clone, command execution, trust
approval, trust revoke, or cache mutation tools. Evidence snippets from repositories are marked as
untrusted data. Server initialization also supplies fixed safety instructions that require
`ASK_USER` and `BLOCK` decisions to stop automatic execution.

The runtime authority remains exactly two tools: `preflight_check` and `corpus_scan`. The v0.3.1
reporting release adds policy explanation and local report comparison only; it does not add MCP
capabilities.

See [docs/mcp.md](docs/mcp.md) for MCP safety notes and
[docs/mcp-client-examples.md](docs/mcp-client-examples.md) for machine-checked integration examples.

## Demo Examples

Safe dependency install:

```bash
codex-preflight preflight --cwd demo_repos/safe_node_app --command "pnpm install" --format markdown
```

Expected decision: `ALLOW`.

Direct lifecycle remote shell pattern:

```bash
codex-preflight preflight --cwd demo_repos/malicious_postinstall --command "pnpm install" --format markdown
```

Expected decision: `BLOCK`.

Indirect execution chain:

```bash
codex-preflight preflight --cwd case_corpus/nested-node-child-process --command "pnpm install" --format markdown
```

Expected decision: `ASK_USER`, because package install reaches a local Node.js file with child
process execution.

Docker compose to Dockerfile:

```bash
codex-preflight preflight --cwd case_corpus/docker-compose-to-dockerfile-run --command "docker compose up" --format markdown
```

Expected decision: `BLOCK`, because compose reaches a Dockerfile remote shell pattern.

Generated demo reports live in [docs/examples](docs/examples/README.md).

## Reports

JSON reports include `executionGraph` with reachable nodes, edges, capabilities, and uncertainty.
Markdown reports include `Execution Chain` and `Uncertainty` sections for human review.
Large reports are capped to keep agent output bounded; when detail is omitted, the report includes
an explicit `REPORT_SIZE_BUDGET_EXCEEDED` uncertainty summary.

JSON reports also include additive `policyExplanation` data showing the final gate, command scope,
risk-score contribution, matched matrix entries, and whether each rule affected the gate or was
report-only. Markdown reports render the same information in `Policy Explanation`.

Compare two existing local JSON reports without scanning or executing report content:

```bash
codex-preflight report compare baseline.json candidate.json --format markdown
```

Comparison covers decisions, command classifications, findings, policy contributions, execution
capabilities, and uncertainties. Inputs are bounded local files and all report text remains
untrusted data.

README link-poisoning findings use `README_` rule IDs:

- `README_FAKE_RELEASE_LINK`: release/download wording points away from the expected GitHub
  Releases page.
- `README_INSTALLER_FROM_NON_RELEASE_HOST`: installer/setup/download wording points to a target
  that is not shaped like a GitHub Releases asset.
- `README_RAW_SOURCE_ARCHIVE_DOWNLOAD`: download/install/release wording points to raw source URLs
  such as raw GitHub file paths.
- `README_DEFEAT_SECURITY_WARNING`: repository documentation encourages bypassing operating
  system, browser, antivirus, Defender, or SmartScreen warnings.

For safe read-only commands these findings warn; for install, build, and script-execution scopes
they require user review. Evidence snippets remain labeled as repository-controlled untrusted data.

Rust and Go ecosystem findings use warning-oriented rule IDs:

- `RUST_BUILD_SCRIPT`: a `build.rs` file or Cargo package build script is present.
- `RUST_CARGO_SOURCE_REPLACEMENT`: Cargo source replacement or custom registry configuration is
  present.
- `RUST_CARGO_ALIAS`: Cargo aliases can hide additional subcommands behind familiar names.
- `RUST_CARGO_GIT_SOURCE`: `Cargo.lock` references a git-sourced dependency.
- `GO_GENERATE_DIRECTIVE`: repository source declares a `//go:generate` command.
- `GO_TESTMAIN`: Go tests define a `TestMain` hook.
- `GO_CGO_USAGE`: Go source imports cgo through `import "C"`.
- `GO_MODULE_REPLACE` and `GO_LOCAL_MODULE_REPLACE`: `go.mod` changes module resolution.

These findings are local static signals. Codex Preflight does not run Cargo, Go, build scripts,
tests, generators, compilers, package managers, or repository code while detecting them.

## External Repository Scan

Scan a public repository without running its code:

```bash
codex-preflight preflight --repo https://github.com/octocat/Hello-World.git --ref master --command "cat README" --format json
```

Clone protocol restrictions reject unsafe local, file, ssh, git, and `ext::` clone URLs by default.

## Corpus

Run the safe synthetic historical-pattern corpus:

```bash
codex-preflight corpus scan
```

The corpus contains static fixtures only. The scanner reads files and compares actual decisions and
rule IDs with expected outcomes. JSON and Markdown output group cases by category, display expected
and actual rules, and label negative controls.

## Trust And Cache

`ALLOW` and `WARN` scan reports can be cached by repository identity, head commit, critical-file
fingerprint, command scope, policy version, and ruleset version. Local trust approvals use the same
scope, so approval is invalidated by policy or ruleset changes, relevant file changes, or a
different command scope.

Use:

```bash
codex-preflight trust approve --cwd . --command "pnpm install" --ttl 7d
codex-preflight trust list
codex-preflight trust revoke --cwd .
codex-preflight cache clear
```

## Dogfooding Workflow

When working on this project, run preflight before tests, lint, package installation, Docker, shell
scripts, MCP startup, or commands in unfamiliar repositories:

```bash
codex-preflight preflight --cwd . --command "pytest" --format json --no-cache
pytest

codex-preflight preflight --cwd . --command "ruff check ." --format json --no-cache
ruff check .
```

If the decision is `ASK_USER` or `BLOCK`, stop and inspect the report before continuing.

## Development

Run tests:

```bash
pytest
```

Run lint:

```bash
ruff check .
```

## Release History

See [docs/release-history.md](docs/release-history.md).

## License

Copyright 2026 Gengetau and contributors.

Codex Preflight is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for the complete
license terms and [NOTICE](NOTICE) for attribution information.

## Limitations

Codex Preflight is static, heuristic, and best-effort. It does not prove a repository is safe, does
not execute code, and does not replace SAST, dependency audit tools, malware sandboxes, or CVE
scanners. Dynamic runtime behavior may still evade static analysis. Unknown, dynamic, missing,
outside-repository, symlink, oversized, binary, or incompletely scanned high-risk paths are
escalated conservatively. Very large graphs or finding sets may be summarized with explicit
report-budget uncertainty instead of unbounded detail.
