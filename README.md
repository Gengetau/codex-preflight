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
codex-preflight rules list
codex-preflight trust list
codex-preflight cache clear
```

The scanner reads repository files statically, classifies the planned command, evaluates rule
findings through a policy engine, and returns a structured decision.

## Example

```bash
codex-preflight preflight --cwd demo_repos/malicious_postinstall --command "pnpm install" --format json
```

Expected result: `BLOCK`, because package installation would execute a remote shell pipeline
through a lifecycle script.

## Development

Install locally:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```
