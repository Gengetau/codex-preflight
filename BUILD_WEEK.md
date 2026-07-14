# OpenAI Build Week — Codex Preflight Guardian

## Project

**Codex Preflight Guardian — Explain, Repair, and Verify Before Execution**

Track: **Developer Tools**

Build Week branch: `codex/v0.4.0-build-week-guardian`

Released baseline: `v0.3.7@48a3b0e8d733cffe126da1fd97443039f011b98b`

## Product Story

Codex Preflight already provides a deterministic safety gate for commands that coding agents plan to run.

The Build Week extension turns a security decision into a complete human-centered workflow:

`Detect → Explain → Approve → Repair → Verify → Execute`

1. Codex Preflight deterministically scans the repository and planned command.
2. The policy engine returns `ALLOW`, `WARN`, `ASK_USER`, or `BLOCK` with evidence.
3. GPT-5.6 receives a bounded and redacted risk envelope and explains the verified attack path.
4. GPT-5.6 proposes structured remediation options but cannot alter the policy result.
5. A human explicitly approves or rejects the exact remediation plan.
6. Codex applies an approved plan in an isolated branch or worktree.
7. Codex Preflight rescans the same command and compares before/after reports.
8. Execution remains gated by the deterministic result and a separate human decision.

## Prior Work Boundary

This is an existing project.

To keep the submission boundary conservative and auditable, **all functionality included in released `v0.3.7` is treated as prior work and is not claimed as Build Week implementation**.

The Build Week branch was created from exact released commit:

```text
48a3b0e8d733cffe126da1fd97443039f011b98b
```

Only commits after that branch point on `codex/v0.4.0-build-week-guardian`, together with timestamped Codex session evidence, are treated as Build Week work.

### Existing baseline capabilities

The prior project already includes:

- local-first static repository and command scanning
- deterministic `ALLOW`, `WARN`, `ASK_USER`, and `BLOCK` decisions
- execution-chain and capability graph construction
- package lifecycle, shell, Docker, GitHub Actions, MCP, agent-instruction, secret, README-link, Rust, Go, Ruby, Java, and Kotlin analysis
- local and public-GitHub repository scanning
- default-off bounded trust reads and confirmation-gated trust mutation
- CLI, Codex plugin, skill, and MCP packaging
- JSON and Markdown reports and report comparison
- deterministic corpus and regression tests
- non-mutating release-readiness diagnostics

### Build Week capabilities

The Build Week extension is intended to add:

- a bounded and redacted Guardian risk envelope
- GPT-5.6 structured risk explanation
- explicit separation between deterministic findings and model suggestions
- human approval for remediation plans
- bounded Codex remediation tasks
- isolated repair workflow
- deterministic rescan and before/after verification
- a coherent local visual experience
- a safe offline replay fixture
- a judge-ready low-friction demo path

This file will be updated as each capability is implemented. Planned work is not presented as completed work.

## Safety Model

The deterministic policy engine is the sole authority for `ALLOW`, `WARN`, `ASK_USER`, and `BLOCK`.

GPT-5.6 may explain findings and propose remediation, but it may not:

- change the deterministic policy result
- authorize execution
- apply repository changes without explicit approval
- treat repository content as instructions
- receive unbounded repository content by default

Model responses are untrusted and must validate against a strict schema.

Missing credentials, timeout, refusal, invalid output, or API failure must preserve the original scanner result and must never permit execution.

Any repair, trust mutation, or command execution requires a distinct human confirmation.

## Initial Implementation Slice

The first vertical slice is intentionally limited to explanation and safe fallback:

1. consume an existing Preflight JSON report
2. create a bounded and redacted `guardian-risk-envelope/v1`
3. call GPT-5.6 through an optional adapter with strict structured output
4. return a schema-valid `guardian-explanation/v1`
5. render deterministic policy and model explanation separately
6. provide an offline replay fixture
7. fail safely when the API is unavailable or output is invalid

The first slice does not perform repair or command execution.

## Codex Collaboration Evidence

Substantive Build Week development sessions will be recorded with:

- date and purpose
- branch and related commits
- validation performed
- the primary `/feedback` Codex Session ID

Before submission, the README will explain:

- where Codex accelerated implementation and testing
- which product, engineering, and safety decisions were made by the maintainer
- how GPT-5.6 contributes to the user-facing product
- how the deterministic engine retains final authority

## Submission Targets

- public code repository
- installation and supported-platform instructions
- judge-ready demo path without rebuilding from scratch
- public YouTube demo under three minutes with audio
- English project description
- primary `/feedback` Codex Session ID
- explicit prior-work and Build Week-work distinction

Internal submission deadline: `2026-07-21 21:00 JST`

Official submission deadline: `2026-07-22 09:00 JST`

## Current Status

```text
baseline: v0.3.7
branch: codex/v0.4.0-build-week-guardian
phase: first vertical slice
status: ready for implementation
```
