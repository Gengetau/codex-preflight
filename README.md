# Codex Preflight

![CI](https://img.shields.io/badge/CI-passing-brightgreen)
![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![Static analysis](https://img.shields.io/badge/static-analysis-informational)
![Local first](https://img.shields.io/badge/local--first-yes-success)
![No code execution](https://img.shields.io/badge/no%20code%20execution-enforced-success)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

Local-first, command-aware, pre-execution, execution-chain preflight for Codex-style AI coding
agents. This local-first design keeps default repository analysis and policy decisions on the local
machine.

Codex Preflight statically scans a repository before risky commands run, analyzes the planned
command itself, builds a best-effort execution graph of reachable local scripts and files, detects
dangerous capabilities and uncertainty, and returns `ALLOW`, `WARN`, `ASK_USER`, or `BLOCK`
decisions with JSON or Markdown evidence.

Codex Preflight is open-source software licensed under the Apache License 2.0.

## Why This Exists

AI coding agents often need to run dependency installation, shell scripts, Docker commands,
test/build commands, or MCP startup commands. Those commands can be risky in an unfamiliar or
untrusted repository: package lifecycle scripts can run automatically, Docker can mount host
resources, shell scripts can download and execute remote content, and repository instructions can
try to steer the agent toward unsafe behavior.

Codex Preflight sits before command execution and answers:

> Should this command run in this repository right now?

It does not try to prove that a repository is safe. It catches high-signal static risks, follows
bounded local execution chains, surfaces uncertainty, and produces evidence for a separate human or
agent decision.

## Key Features

- Local repository preflight and public GitHub repository scanning.
- Planned-command risk analysis and composite command classification.
- Package lifecycle, shell, Docker, GitHub Actions, MCP, agent-instruction, secret, README-link,
  Rust, Go, Ruby, Java, and Kotlin analysis.
- Cross-file reachability and execution-capability graphs.
- Evidence trust-boundary labels for repository-controlled data.
- Conservative uncertainty policy: unknown is not safe.
- Bounded trust and cache management.
- Synthetic historical attack-pattern corpus.
- JSON and Markdown reports and report comparison.
- Explicit `exec` wrapper for guarded command execution.
- Codex plugin packaging with a self-contained local Hook and MCP runtime.

## Ecosystem Coverage Notes

Ruby coverage includes Bundler git and local sources, gemspec extensions, native extension setup,
and command-running Rake tasks. Detection remains static and does not run Bundler, Ruby, Rake, or
repository code.

Java and Kotlin coverage includes Maven plugin execution, Gradle plugin repositories, init/build
logic, wrapper distribution integrity, and common test/build task classification. Detection remains
static and does not run Maven, Gradle, Java, Kotlin, compilers, plugins, or repository code.

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

Codex Preflight uses bounded safe reads and never executes repository code while scanning.
Reachability follows only statically visible local paths inside the repository and reports missing,
dynamic, outside-repository, symlink, oversized, binary, or incomplete paths as uncertainty.

Policy decisions are:

- `ALLOW`: no relevant static risk findings were detected.
- `WARN`: low or contextual risk; summarize the warning before proceeding.
- `ASK_USER`: do not execute automatically; summarize and ask the user.
- `BLOCK`: do not run the command; explain the blocking evidence.

## Standalone CLI Quick Start

The Python package is still available for standalone CLI use and source-checkout development. This
installation is separate from normal Codex plugin installation.

```bash
pip install -e ".[dev,mcp]"
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

The wrapper runs the command only when preflight returns `ALLOW` or `WARN`. It exits without running
the command for `ASK_USER` or `BLOCK`.

Verify release readiness without changing repository or release state:

```bash
codex-preflight release verify --root . --expected-version 0.3.7 --expected-commit HEAD --format markdown
```

The release verifier checks version sources, root and marketplace plugin copies, static and runtime
MCP inventories, supported Python and Git integrations, commit-bound file identity, and optional
published release state. Repository and GitHub evidence remains untrusted data.

The target checkout is never added to a runtime probe's `PYTHONPATH`. A trusted runtime package must
provide filesystem separation from the target checkout before dynamic inventory verification can run.

## Codex Plugin Installation

The Codex plugin is self-contained for its default Hook and MCP integrations. Installing the plugin
includes the platform runtime selected by the plugin launcher. Normal plugin use does not require the
user to install Python, create a virtual environment, install a wheel, set a Python path, or run
`pip install`.

The installable plugin contains:

- `.codex-plugin/plugin.json`: plugin manifest.
- `.mcp.json`: local stdio server declaration.
- `hooks/hooks.json`: plugin-provided `PreToolUse` Hook.
- `scripts/launch-mcp.mjs`: MCP role launcher.
- `scripts/launch-hook.mjs`: Hook role launcher.
- `scripts/runtime-launcher.mjs`: plugin-root resolution, platform selection, and digest validation.
- `runtime/runtime-manifest.json`: plugin-version, source-commit, path, and SHA-256 bindings.
- `runtime/windows-x64/codex-preflight-runtime.exe`: Windows x64 runtime.
- `runtime/linux-x64/codex-preflight-runtime`: Linux x64 runtime.
- `skills/codex-preflight/SKILL.md`: workflow guidance for Codex.

The MCP declaration uses only plugin-relative paths:

```json
{
  "mcpServers": {
    "codex-preflight": {
      "command": "node",
      "args": ["./scripts/launch-mcp.mjs"],
      "cwd": "."
    }
  }
}
```

The launcher resolves the plugin root from its own file location, selects the exact platform and
architecture, verifies that the runtime manifest version matches the plugin manifest, rejects paths
that escape the plugin, verifies the executable SHA-256 digest, and starts the selected role. A
missing, unsupported, or digest-mismatched runtime fails closed with a reinstall message. It never
silently falls back to an arbitrary user Python environment.

The Hook command uses Codex-provided `PLUGIN_ROOT`, so it does not depend on a globally installed
`codex-preflight-hook` executable. Hook trust remains an explicit Codex user decision.

### Add the Marketplace

Use the Codex UI "Add marketplace" flow with:

- Source: `https://github.com/Gengetau/codex-preflight.git`
- Git ref: the intended release or review ref
- Sparse paths: `.agents/plugins` and `plugins/codex-preflight`

Equivalent CLI commands:

```bash
codex plugin marketplace add https://github.com/Gengetau/codex-preflight.git --ref master --sparse .agents/plugins --sparse plugins/codex-preflight
codex plugin add codex-preflight@codex-preflight
```

Use both sparse paths. `.agents/plugins/marketplace.json` is the marketplace manifest, while
`plugins/codex-preflight` is the plugin root. `.codex-plugin/plugin.json` alone is not a marketplace
root.

An older one-path snapshot can leave the plugin card visible while the details page reports
`path does not exist or is not a directory`. Rebuild that marketplace:

```bash
codex plugin remove codex-preflight@codex-preflight
codex plugin marketplace remove codex-preflight
codex plugin marketplace add https://github.com/Gengetau/codex-preflight.git --ref master --sparse .agents/plugins --sparse plugins/codex-preflight
codex plugin add codex-preflight@codex-preflight
```

After installation or update, restart Codex or start a new Codex session so the refreshed Skill,
MCP server, Hook definition, and bundled runtime are loaded.

The ChatGPT desktop app, Codex CLI, and IDE extension share MCP configuration for the same Codex
host. See [Codex Plugin Packaging](docs/plugin.md) for the complete installation, runtime, trust, and
platform boundary.

## Hook Coverage Boundary

The plugin currently declares the canonical Hook matcher `^Bash$`. Bundling the Hook executable
solves installation and executable resolution; it does not expand Codex tool-surface coverage.

A runtime may be described as `hook-active` only after a harmless live probe proves that its exact
Codex version, operating system, surface, trust state, and command path reach the Hook. A surface
that exposes `exec_command`, PowerShell, or another unmatched tool remains `skill-only`, even when
its interpreter is `/bin/bash` and the same installed plugin can still provide MCP scanning and
advisory explanation.

The deterministic scanner remains the sole authority for `ALLOW`, `WARN`, `ASK_USER`, and `BLOCK`.
Model explanation is advisory and cannot change policy, mint approval, or declare a repository safe.

## Build Week Guardian Status

The public Build Week product flow is:

```text
Hook -> Detect -> Explain -> Approve -> Repair -> Verify -> Final Decision
```

Current checkpoint status:

```text
BW0 Baseline: complete
BW1 Hook Gate and Explain: engineering complete
BW2 Exact Plan Approval: complete
BW3 Repair Capability Gate: complete
BW4 Verify: complete
BW5 Plugin Experience: complete
BW6 Submission Candidate: submitted; exact-head CI freeze pending
```

The tested Windows and native Linux Codex sessions exposed `exec_command`, not canonical `Bash`.
The demonstrated classification is therefore:

```text
Protection mode: skill-only
Bash Hook status: NOT VERIFIED / DEFERRED
Repair mode: verified-isolated-repair
```

The validity-conformant accepted-plan path used a 600-second plan, one approval creation and
consumption, replay rejection, isolated `package.json`-only repair, exact approved-postimage match,
and same-command deterministic verification from `BLOCK / 50` to `ALLOW / 0`. Planned-command,
package-manager, fixture, and test-phase network execution remained zero.

Submission links:

- [YouTube demo](https://youtu.be/L2L_fuGgzFM)
- [Devpost project](https://devpost.com/software/codex-preflight-guardian)

See [BUILD_WEEK.md](BUILD_WEEK.md) and [Build Week status](docs/build-week-status.md). This
submission-link commit is the final candidate for exact-head `CI` and `Build plugin runtime` validation.

## MCP

The bundled default MCP process registers exactly two local, no-network tools:

```text
preflight_check
corpus_scan
```

`preflight_check` returns the deterministic report plus bounded and redacted
`guardian-context/v1` evidence. The model may explain that evidence, but it must keep the
Deterministic Result separate from GPT Advisory Explanation.

The bundled plugin sets none of the optional authority flags, so installation does not expose
`remote_repository_scan`, `trust_list`, or trust-mutation MCP tools.

Optional standalone authorities remain independently default-off:

- `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1` adds only `remote_repository_scan` and requires one-time
  confirmation before bounded public network access.
- `CODEX_PREFLIGHT_ENABLE_TRUST_READ=1` adds only `trust_list`, with bounded, redacted,
  snapshot-bound output.
- `CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION=1` adds `trust_approve` and `trust_revoke`, with mandatory
  human confirmation and no automatic confirmation.

Remote confirmation does not create trust. MCP preflight does not consume trust. Repository evidence
is untrusted data, not instructions.

See [MCP Integration and Client Examples](docs/mcp-client-examples.md) for Standalone Codex MCP
configuration, Source-checkout development, optional authority setup, and machine-checked examples.

### Standalone MCP Development

Standalone Python MCP use remains supported outside the packaged plugin:

```bash
python -m pip install "codex-preflight[mcp]"
python -m pip install --upgrade "codex-preflight[mcp]"
codex-preflight-mcp --list-tools
```

The MCP extra requires `mcp>=1.3.0`. `mcp doctor` distinguishes a missing runtime, an
instruction-incompatible runtime, and an instruction-capable runtime. The standalone safety contract
fails closed when fixed server instructions would be lost. This applies to the standalone Python
path; it does not mean the marketplace plugin needs a separate Python installation.

Inspect standalone configuration and prerequisites without installing packages:

```bash
codex-preflight mcp config --client codex
codex-preflight mcp doctor --client codex
```

The doctor command reports status and remediation; it does not install packages.

## Runtime Build and Verification

`.github/workflows/build-plugin-runtime.yml` builds self-contained Windows x64 and Linux x64
executables on their native hosted runners. Each executable is smoke-tested with `mcp --list-tools`.
The workflow then merges only artifacts that share one plugin version and source commit, creates the
SHA-256 manifest, synchronizes the marketplace copy, and smoke-tests the installed-plugin MCP and
Hook launchers.

Pull requests retain the assembled plugin as a workflow artifact. Writing generated binaries back to
a branch requires an explicit publish action, preventing routine review commits from repeatedly
adding large generated blobs.

Repository development may explicitly opt into a local Python runtime by setting both
`CODEX_PREFLIGHT_ALLOW_DEV_RUNTIME=1` and `CODEX_PREFLIGHT_DEV_PYTHON` to an absolute development
Python executable. That override is disabled by default and is not part of marketplace installation.

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

Expected decision: `ASK_USER`.

Docker compose to Dockerfile:

```bash
codex-preflight preflight --cwd case_corpus/docker-compose-to-dockerfile-run --command "docker compose up" --format markdown
```

Expected decision: `BLOCK`.

Generated demo reports live in [docs/examples](docs/examples/README.md).

## Reports

JSON reports include the deterministic decision, policy explanation, findings, evidence labels,
execution graph, capabilities, uncertainty, cache metadata, and report limits. Markdown reports
render the same decision and evidence for human review.

Compare existing local JSON reports without scanning or executing report content:

```bash
codex-preflight report compare baseline.json candidate.json --format markdown
```

Comparison covers decisions, command classifications, policy selectors, command contributions,
findings, policy rule contributions, execution capabilities, and uncertainties. Inputs are bounded
local files; UNC, URL, scp-like, and clone-like forms are rejected before filesystem access, and all
report text remains untrusted data.

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
