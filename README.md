# Codex Preflight

![CI](https://img.shields.io/badge/CI-passing-brightgreen)
![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![Static analysis](https://img.shields.io/badge/static-analysis-informational)
![Local first](https://img.shields.io/badge/local--first-yes-success)
![No code execution](https://img.shields.io/badge/no%20code%20execution-enforced-success)

Local-first, command-aware, pre-execution, execution-chain preflight for Codex-style AI coding
agents.

Codex Preflight statically scans a repository before risky commands run, classifies the planned
command, builds a best-effort execution graph of reachable local scripts/files, detects dangerous
capabilities and uncertainty, and returns `ALLOW`, `WARN`, `ASK_USER`, or `BLOCK` decisions with
JSON/Markdown reports.

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
- Nested monorepo critical file collection.
- Package lifecycle detection.
- Shell, Docker, GitHub Actions, MCP, agent instruction, and secret checks.
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
  -> critical file collection
  -> static scanner rules
  -> reachability execution graph
  -> capability / uncertainty findings
  -> policy decision
  -> JSON / Markdown report
```

V1.3.1 uses bounded safe reads and never executes repository code. Reachability follows only
statically visible local paths inside the repository and reports missing, dynamic, outside-repo,
symlink, oversized, binary, or incomplete paths as uncertainty.

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

Codex Preflight remains a Python CLI project. v1.4.0 adds Codex plugin packaging around the
existing CLI so Codex can discover the guidance as a skill.

The plugin is skill-based:

- `.codex-plugin/plugin.json`: Codex plugin manifest.
- `skills/codex-preflight/SKILL.md`: English skill instructions for when and how Codex should call
  `codex-preflight`.

The plugin does not currently provide MCP or App integration, and the manifest intentionally does
not declare `mcpServers` or `apps`.

When Codex is about to run a risky command in a local or unfamiliar repository, it should run:

```bash
codex-preflight preflight --cwd . --command "<planned command>" --format markdown
```

Codex must respect the resulting decision:

- `ALLOW`: the command may proceed.
- `WARN`: summarize the warning before proceeding.
- `ASK_USER`: stop and ask the user.
- `BLOCK`: do not run the command.

Local marketplace registration depends on the user's Codex plugin setup. The official plugin
creator workflow uses `.codex-plugin/plugin.json`, optional local marketplace entries, cachebuster
updates for local plugin iteration, and a new Codex thread after reinstall so updated skills are
picked up.

More details are in [docs/plugin.md](docs/plugin.md).

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
rule IDs with expected outcomes.

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

## Limitations

Codex Preflight is static, heuristic, and best-effort. It does not prove a repository is safe, does
not execute code, and does not replace SAST, dependency audit tools, malware sandboxes, or CVE
scanners. Dynamic runtime behavior may still evade static analysis. Unknown, dynamic, missing,
outside-repository, symlink, oversized, binary, or incompletely scanned high-risk paths are
escalated conservatively.
