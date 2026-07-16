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
- Default-off, confirmation-gated MCP static scan for public GitHub HTTPS repositories.
- Default-off, bounded and redacted MCP listing of existing local trust approvals.
- Composite command classification.
- Planned-command risk findings for remote shell pipelines, encoded PowerShell, dangerous Docker
  flags and mounts, and inline interpreter execution.
- Static README link-poisoning detection for fake release links, non-release installer/download
  hosts, raw source archive downloads, and security-warning bypass wording.
- Static Rust and Go ecosystem coverage for Cargo build scripts, Cargo source replacement,
  Cargo aliases, git-sourced Cargo lock entries, Go generator directives, TestMain hooks, cgo
  indicators, and Go module replacements.
- Static Ruby ecosystem coverage for Bundler git/local sources, gemspec extensions and lifecycle
  hooks, native `extconf.rb` configuration, and command-running Rake tasks.
- Static Java and Kotlin ecosystem coverage for Maven plugin executions, Gradle plugin
  repositories, init/build logic, and wrapper distribution integrity indicators.
- Reachability parsing for common wrappers such as shell `-c`, interpreter flags, `env`,
  package-manager wrappers, PowerShell, `cmd /c`, and Windows-style paths.
- Cross-file Node.js module reachability for local `require()` and `import` chains.
- Evidence trust-boundary labels for repository-controlled snippets.
- Nested monorepo critical file collection.
- Package lifecycle detection.
- Shell, Docker, GitHub Actions, MCP, agent instruction, Rust, Go, Ruby, Java/Kotlin, and secret checks.
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
generated locally. Remote MCP access exists only behind an explicit startup flag and one-time
confirmation, and materializes a bounded static snapshot locally. The scanner does not run package
install scripts, shell payloads, Docker, MCP servers, test commands from fixtures, or repository code. The CLI is intentionally scanner-first:
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

Verify local release readiness without changing repository or release state:

```bash
codex-preflight release verify --root . --expected-version 0.3.7 --expected-commit HEAD --format markdown
```

The command checks all five version sources, the three root/marketplace plugin-copy files, the
exact eight-way static MCP inventories, and supported Python, Git, and optional MCP integrations.
When the optional MCP runtime is installed, it also checks all eight runtime inventories. When it
is missing, both the integration and `mcp.inventory.runtime` checks return `SKIP`, the runtime probe
is not invoked, and the exact install command is reported without installing anything. Add `--tag`,
`--github-repo OWNER/NAME`, and `--merged-branch` only when
you explicitly want bounded, read-only tag, published Release, and branch-cleanup verification.
JSON output uses the stable `release-readiness/v1` schema. Repository and GitHub evidence remains
untrusted data.

The target checkout is never added to a runtime probe's `PYTHONPATH`. Runtime probes are allowed only
when the active Codex Preflight package root resolves outside the target checkout; filesystem overlap
fails readiness before a probe starts. This proves filesystem separation only: it does not determine
editable-install metadata or prove independent build provenance. Invoke the command from a separately
trusted installation when an independent code-provenance boundary is required. Each probe replaces
only the side-effectful trust-service factories with inert in-memory services and then calls the same
default `create_mcp_server()` path as normal startup. Normal startup and verification therefore use
one pure shared registration function and the same registration inputs; the probe reads the resulting
actual FastMCP Tool Manager without opening trust stores or writing registration audit state.
Every required target file is opened through no-follow handles; symbolic links, reparse points,
unsafe hard links, and repository escapes fail readiness. `HEAD` must equal the requested canonical
commit, and every file actually consumed by diagnostics must content-match its tracked commit blob.
The commit tree entry must be a regular `100644` or `100755` blob; symlink and submodule modes fail
even when a checkout materializes them as ordinary files. One immutable no-follow byte snapshot is
verified and then reused by all version, plugin, and inventory parsers. Only the safe built-in
CRLF-to-LF checkout conversion is accepted; repository filters are never run. Dynamic namespace
writes such as `globals()` and `exec` fail the strict static version/inventory contract.
Index hints such as `assume-unchanged` and `skip-worktree` cannot hide drift. Git environment
overrides are discarded, and the verifier does not call `git status` or repository fsmonitor hooks.
The discovered Git executable is resolved once to a canonical absolute path outside the target and
that exact path is used for every Git subprocess.
Tag checks require annotated tags; lightweight tags fail. External checks reject redirects, cap response bytes,
validate repository and branch names, and positively identify the public repository before a branch
`404` can mean deletion. Markdown output encodes every interpolated value as data.

## Codex Plugin Usage

Codex Preflight remains a Python CLI project and is also packaged as a Codex plugin that bundles
the operational skill and the existing local stdio MCP server configuration.

The plugin package contains:

- `.codex-plugin/plugin.json`: Codex plugin manifest.
- `.mcp.json`: local stdio server map for the bundled cross-platform MCP launcher.
- `scripts/launch-mcp.mjs`: shell-free launcher that selects an installed Python environment and
  starts `python -m codex_preflight_mcp.server`.
- `skills/codex-preflight/SKILL.md`: English skill instructions for when and how Codex should call
  `codex-preflight`.
- `.agents/plugins/marketplace.json`: Codex marketplace root manifest for the Codex UI
  "Add marketplace" flow.
- `plugins/codex-preflight/`: marketplace-packaged copy of the plugin referenced relative to the
  repository marketplace root.

The manifest declares `mcpServers: "./.mcp.json"`. It does not declare an App, remote MCP URL,
credentials, shell command, automatic installer, or repository-controlled startup arguments.

When Codex is about to run a risky command in a local or unfamiliar repository, it should run:

```bash
codex-preflight preflight --cwd . --command "<planned command>" --format markdown
```

Codex must respect the resulting decision:

- `ALLOW`: the command may proceed.
- `WARN`: summarize the warning before proceeding.
- `ASK_USER`: stop and ask the user.
- `BLOCK`: do not run the command.

### BW1 Guardian self-verification

Run the deterministic Hook Gate and Explain harness from a clean checkout:

```bash
codex-preflight guardian verify-bw1
```

The command prints only `PASS`, `FAIL`, or `UNSUPPORTED`, writes sanitized evidence beneath
`artifacts/bw1-self-verification/<utc-timestamp>/`, returns exit code `1` for `FAIL`, and returns the
distinct exit code `3` when a required local Codex runtime capability is unavailable. The synthetic
corpus command is analyzed as data and is never executed.

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

The plugin MCP launcher does not depend on the Python console-script directory being present on
`PATH`. It probes Python without a shell and starts the module directly. If several Python
environments are installed, set `CODEX_PREFLIGHT_PYTHON` to the executable where
`codex-preflight[mcp]` is installed. The selected Python package version must match the plugin
manifest version; a Codex local cachebuster suffix is ignored for this comparison.

Then add this repository through the Codex UI "Add marketplace" flow with:

- Source: `https://github.com/Gengetau/codex-preflight.git`
- Git ref: `master`
- Sparse paths: `.agents/plugins` and `plugins/codex-preflight`

The equivalent CLI marketplace command is:

```bash
codex plugin marketplace add https://github.com/Gengetau/codex-preflight.git --ref master --sparse .agents/plugins --sparse plugins/codex-preflight
```

Use both sparse paths. `.agents/plugins/marketplace.json` is the marketplace manifest, while
`plugins/codex-preflight` is the plugin root resolved by its `./plugins/codex-preflight` source
path. `.codex-plugin/plugin.json` alone is not a marketplace root.

An older marketplace configured with only `.agents/plugins` can still show the plugin card or
retain an installed cache while the details page fails with `path does not exist or is not a
directory`. Rebuild that marketplace with both sparse paths by following the recovery procedure in
[`docs/plugin.md`](docs/plugin.md#repair-an-existing-one-path-marketplace-snapshot).

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

The MCP-facing package never executes repository code or planned commands. Evidence and stored
trust values are marked or described as untrusted data. Server initialization supplies fixed safety
instructions requiring `ASK_USER` and `BLOCK` decisions to stop automatic execution.

The default runtime authority remains exactly two tools:

```text
preflight_check
corpus_scan
```

v0.3.2 adds a separately gated public GitHub scanner. It is absent unless the server starts with
the exact environment value `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1`; enabled registration adds only
`remote_repository_scan`. The first valid call performs lexical validation and returns a one-time
confirmation challenge before DNS or network access. A confirmed call uses public-address
validation and pinning, zero redirects, bounded shallow bare Git acquisition, regular-file-only
materialization, an isolated static worker, dedicated remote cache/audit state, and verified
cleanup. Confirmation never creates trust.

v0.3.3 adds a separate default-off trust-read capability. Exact startup value
`CODEX_PREFLIGHT_ENABLE_TRUST_READ=1` registers only `trust_list`; with both startup flags, the
inventory is `preflight_check`, `corpus_scan`, `remote_repository_scan`, and `trust_list`.
`trust_list` reads only the normal local trust cache, returns at most 100 deterministically sorted
entries per page, redacts raw repository identities, paths, URLs, and approved commands, and uses
process-local HMAC hashes and 300-second snapshot-bound cursors. It cannot approve, revoke, extend,
consume, satisfy, or create trust.

The first v0.3.3 read may perform only the reviewed metadata migration that adds stored UUIDv4
entry IDs, entry version `1`, and provenance while preserving every approval field and matching
semantic. Migration is locked, permission-preserving, backed up, capped at 1 MiB, and fail-closed.
Trust-read audit records use the separate `trust-read/audit.jsonl` namespace and never contain raw
identities or trust content.

v0.3.4 adds two independently default-off local tools. Only the exact startup value
`CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION=1` registers `trust_approve` and `trust_revoke`; it does not
imply remote scanning or trust reads. The bundled plugin configures none of the remote, trust-read,
or trust-mutation flags. The first fully valid mutation request returns a single-use, 300-second
challenge and makes no approval or revocation. A mandatory human stop must present the fixed
display and make the decision; the client may make one confirmed retry only after that human
approves the exact request. There is no automatic confirmation.

MCP preflight does not consume trust. Remote confirmation cannot create, satisfy, read, or mutate
trust. A confirmed approval writes one exact local v2 entry and a confirmed revoke deletes one
exact UUIDv4 entry at `expectedVersion: 1`; neither operation executes a caller command,
repository code, or network request. The stdio runtime reports `identityStatus: unavailable`, so
the process flag and confirmation integrity are not authenticated client identity.

Mutation audit records are redacted and recoverable under `trust-mutation/`. If a trust-file write
commits but the audit commit cannot be persisted, the server returns
`MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING` with `committed: true`; do not retry the mutation.
Restart performs audit recovery or leaves mutation registration disabled. Emergency disable removes
`CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION` and restarts the process; it removes the two tools and
invalidates outstanding challenges without deleting existing approvals or audit state. Local CLI
`trust list` displays MCP provenance and `mutationAuditEventId`, and existing CLI matching and
revoke behavior remains compatible with MCP-created approvals.

Disable any optional authority by removing its flag and restarting the MCP process. The bundled
plugin configuration sets none of the flags, so its default remains the two local/no-network tools.

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

Comparison covers decisions, command classifications, policy selectors, command contributions,
findings, policy rule contributions, execution capabilities, and uncertainties. Inputs are bounded
local files; UNC, URL, scp-like, and clone-like forms are rejected before filesystem access, and
all report text remains untrusted data.

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
