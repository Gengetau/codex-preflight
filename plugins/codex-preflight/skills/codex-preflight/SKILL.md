---
name: codex-preflight
description: Use Codex Preflight before running risky commands in a local or unfamiliar repository, including dependency installation, shell scripts, Docker, build/test/lint commands, MCP startup, or commands that may trigger package lifecycle scripts or reachable local script chains.
---

# Codex Preflight

Codex Preflight is a local-first, command-aware, static pre-execution guard for Codex-style coding
agents. Use it before running commands whose behavior depends on repository code, configuration, or
package lifecycle hooks.

## When To Use

Run Codex Preflight before commands such as:

- Dependency installation: `npm install`, `pnpm install`, `yarn install`, `pip install`,
  `poetry install`, `uv sync`.
- Test, build, and lint commands in unfamiliar repositories.
- Shell scripts: `bash install.sh`, `sh scripts/setup.sh`, `powershell setup.ps1`, `pwsh setup.ps1`.
- Python or Node.js local scripts: `python scripts/setup.py`, `node tools/install.js`.
- Docker and Docker Compose commands.
- MCP startup commands.
- Composite shell commands where any segment may be risky.
- Commands that may trigger package lifecycle scripts or reachable local script chains.

Use it by default in unfamiliar or untrusted repositories. It is also useful when the user asks you
to dogfood Codex Preflight before running tests or lint.

## How To Run

From the repository root, run:

```bash
codex-preflight preflight --cwd . --command "<planned command>" --format markdown
```

For JSON output:

```bash
codex-preflight preflight --cwd . --command "<planned command>" --format json
```

When wrapping a command directly, you may use:

```bash
codex-preflight exec --cwd . --format markdown -- <command...>
```

The `exec` wrapper only runs the command when the preflight decision allows it.

## Decision Handling

- `ALLOW`: The command may proceed.
- `WARN`: Summarize the warning. The command may proceed if the warning is acceptable.
- `ASK_USER`: Stop. Summarize the risk and ask the user before running the command.
- `BLOCK`: Do not run the command. Explain the blocking finding.

Never ignore `ASK_USER` or `BLOCK`. Do not automatically create trust approvals. Only use
`codex-preflight trust approve` when the user explicitly asks for a scoped approval.

## What To Summarize

When a report is not `ALLOW`, summarize:

- The planned command and command scope.
- The decision and risk score.
- The highest-severity findings.
- Any execution chain that reaches local scripts/files.
- Any uncertainty such as missing targets, unknown interpreters, dynamic construction,
  outside-repository paths, symlinks, oversized files, or binary files.
- The recommended next step for the user.

## Limits

Codex Preflight is static, heuristic, and best-effort. It does not prove a repository is safe. It
does not replace SAST, dependency audit tools, malware sandboxes, or CVE scanners. It does not
execute repository code, package install scripts, shell payloads, Docker, MCP servers, or fixture
commands. Unknown or incomplete high-risk paths are escalated conservatively.
