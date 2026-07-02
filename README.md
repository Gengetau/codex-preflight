# Codex Preflight

Codex Preflight is a local-first pre-execution safety hook for Codex-style AI coding agents.

It scans a repository before risky commands such as dependency installation, shell scripts,
Docker startup, build commands, or MCP server startup. The scanner is designed to read files
statically and return a command-aware `ALLOW`, `WARN`, `ASK_USER`, or `BLOCK` decision.

V1 is a CLI-first tool. It does not include a web dashboard, FastAPI backend, database server,
SaaS login, cloud upload, browser extension, or IDE extension.

## Status

This repository contains a working V1 CLI:

```bash
codex-preflight --help
codex-preflight preflight --cwd . --command "pnpm install" --format json
codex-preflight preflight --repo https://github.com/octocat/Hello-World.git --ref master --command "cat README" --format json
codex-preflight corpus scan
codex-preflight batch scan examples/public-repos.yml --format markdown
codex-preflight rules list
codex-preflight trust list
codex-preflight cache clear
```

The scanner reads repository files statically, classifies the planned command, evaluates rule
findings through a policy engine, and returns a structured decision.

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

## Dogfooding Workflow

When working on this project, run preflight before tests, lint, package installation, Docker,
shell scripts, MCP startup, or commands in unfamiliar repositories:

```bash
codex-preflight preflight --cwd . --command "pytest -q" --format json --no-cache
pytest -q

codex-preflight preflight --cwd . --command "ruff check . --no-cache" --format json --no-cache
ruff check . --no-cache
```

If the decision is `ASK_USER` or `BLOCK`, stop and inspect the report before continuing.

## Examples

```bash
codex-preflight preflight --cwd demo_repos/malicious_postinstall --command "pnpm install" --format json
```

Expected result: `BLOCK`, because package installation would execute a remote shell pipeline
through a lifecycle script.

```bash
codex-preflight preflight --cwd demo_repos/safe_node_app --command "pnpm install" --format json
```

Expected result: `ALLOW`.

```bash
codex-preflight exec --cwd demo_repos/malicious_postinstall --format markdown -- pnpm install
```

Expected result: exit code `30` with a Markdown report; `pnpm install` is not executed.

Scan a public repository without running its code:

```bash
codex-preflight preflight --repo https://github.com/octocat/Hello-World.git --ref master --command "cat README" --format json
```

Expected result: a JSON report with `repo.sourceType` set to `github` and clone metadata such as
`cloneUrl`, `requestedRef`, and `resolvedCommit`.

Run the safe synthetic historical-pattern corpus:

```bash
codex-preflight corpus scan
```

Expected result: all case expectations pass.

Run an optional public repository batch scan:

```bash
codex-preflight batch scan examples/public-repos.yml --format markdown
```

Batch scans are for manual checks and are not part of CI by default.

## Trust And Cache

`ALLOW` scan reports can be cached by repository identity, head commit, critical-file
fingerprint, command scope, policy version, and ruleset version. Local trust approvals use the
same scope, so approval is invalidated by policy or ruleset changes, relevant file changes, or a
different command scope.

Use:

```bash
codex-preflight trust approve --cwd . --command "pnpm install" --ttl 7d
codex-preflight trust list
codex-preflight trust revoke --cwd .
codex-preflight cache clear
```

## Development

Run tests:

```bash
pytest
```

Run lint:

```bash
ruff check .
```

## Limitations

Codex Preflight is a local static heuristic scanner. It does not execute MCP servers, run package
install scripts, provide a cloud service, replace a full SAST or dependency-audit product, or
prove that a repository is safe. It is not a CVE scanner or malware dynamic analyzer. It is meant
to catch common high-signal hazards before an agent runs commands.
