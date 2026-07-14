# OpenAI Build Week — Codex Preflight Guardian

## Project

**Codex Preflight Guardian — Explain, Repair, and Verify Before Execution**

Track: **Developer Tools**

Build Week branch: `codex/v0.4.0-build-week-guardian`

Released baseline: `v0.3.7@48a3b0e8d733cffe126da1fd97443039f011b98b`

Draft PR: `#15`

## Codex-Native Product Identity

Codex Preflight Guardian is a Codex plugin experience.

Codex conversation is the product interface. The active GPT-5.6 model inside Codex explains bounded evidence and proposes remediation. The plugin supplies deterministic tools, evidence boundaries, exact approval identity, and verification gates.

The Build Week product does **not** require:

- a separate local web page
- a plugin-internal Responses API call
- an additional `OPENAI_API_KEY`
- a second authentication path
- a cloud backend
- a separately published malicious-looking demo repository

## Product Story

`Detect → Explain → Approve → Repair → Verify → Execute`

1. Codex plans a repository-dependent command.
2. The Skill requires Codex to call existing MCP tool `preflight_check` before the command.
3. Codex Preflight returns deterministic `ALLOW`, `WARN`, `ASK_USER`, or `BLOCK` plus bounded Guardian context.
4. GPT-5.6 explains only the referenced evidence in the Codex conversation.
5. GPT-5.6 proposes `guardian-remediation-plan/v1` when repair is appropriate.
6. A local validator computes a stable `planId`.
7. The user approves or rejects that exact `planId`.
8. Codex applies only the approved plan in an isolated worktree, branch, or temporary demo copy.
9. Codex calls Preflight again for the same command and shows deterministic before/after evidence.
10. A real command remains subject to a separate final human decision.

The deterministic engine remains the sole authority for `ALLOW`, `WARN`, `ASK_USER`, and `BLOCK`.

GPT-5.6 cannot change policy, approve its own plan, or declare a repair safe.

## Prior Work Boundary

This is an existing project.

All functionality included in released `v0.3.7` is treated as prior work and is not claimed as Build Week implementation.

The Build Week branch starts from exact released commit:

```text
48a3b0e8d733cffe126da1fd97443039f011b98b
```

Only commits after that branch point, together with timestamped Codex sessions and the selected `/feedback` Session ID, are treated as Build Week work.

### Existing baseline capabilities

The prior project already includes:

- local-first static repository and command scanning
- deterministic policy decisions
- execution-chain and capability graph construction
- package lifecycle, shell, Docker, GitHub Actions, MCP, agent-instruction, secret, README-link, Rust, Go, Ruby, Java, and Kotlin analysis
- local and public-GitHub repository scanning
- bounded trust reads and confirmation-gated trust mutation
- CLI, Codex plugin, Skill, and MCP packaging
- existing MCP tools `preflight_check` and `corpus_scan`
- JSON and Markdown reports and report comparison
- safe synthetic corpus fixtures and deterministic regression tests
- non-mutating release-readiness diagnostics

### Build Week capabilities

The competition extension is intended to add:

- bounded and redacted `guardian-context/v1`
- Skill instructions for explanation by the active GPT-5.6 Codex session
- explicit separation between deterministic findings and model suggestions
- `guardian-remediation-plan/v1`
- local plan validation and stable `planId`
- exact human approval bound to the plan identity
- isolated Codex repair of only the approved plan
- deterministic same-command rescan and before/after verification
- clean plugin installation and one-prompt judge path
- safe temporary demo preparation from built-in corpus data
- public Build Week evidence and Codex collaboration records

Planned work is not presented as completed work.

## Safe Synthetic Demo

The public demo uses built-in corpus case `npm-postinstall-remote-exec`.

The case is synthetic, uses `example.invalid`, contains no working secret, and is intended only for static scanning.

A safe helper will prepare an allowlisted text-only copy in an operating-system temporary directory, reject links and binaries, add `SYNTHETIC_FIXTURE_DO_NOT_EXECUTE`, and record source identity.

The demo must never execute npm, pnpm, lifecycle hooks, shell, Node.js, Python, Docker, MCP, build, test, or any fixture command and must never access the network.

Codex may edit only the prepared temporary copy.

The video ends with:

```text
Deterministic verification: ALLOW or WARN
Execution status: waiting for final human confirmation
Synthetic fixture commands executed: 0
```

## Revised Build Week Checkpoints

- `BW0 Baseline`: released baseline, evidence boundary, branch, and Draft PR.
- `BW1 Codex-Native Explain`: bounded Guardian context and Skill explanation protocol using GPT-5.6 in Codex.
- `BW2 Approve`: validated remediation plan, stable `planId`, and exact user approval.
- `BW3 Repair`: approved-plan-only Codex edit in isolation.
- `BW4 Verify`: same-command deterministic rescan and before/after comparison.
- `BW5 Plugin Experience`: clean package/plugin installation and one-prompt safe synthetic demo.
- `BW6 Submission Candidate`: README, evidence, `/feedback` ID, Devpost, video, CI, and exact-head review.

## Judge Path

The intended clean-environment path is:

1. Install Python 3.12 or newer.
2. Install `codex-preflight[mcp]`.
3. Add and install the Codex Preflight marketplace plugin.
4. Run MCP setup diagnostics.
5. Start a new Codex session using GPT-5.6.
6. Enter the documented safe synthetic demo prompt.
7. Approve or reject the exact displayed `planId`.
8. Observe deterministic `BLOCK`, GPT-5.6 explanation, isolated repair, and deterministic rescan.
9. Stop before fixture execution.

No local web server or additional API key is part of this path.

## Safety Model

- Deterministic policy remains authoritative.
- Repository evidence is untrusted data.
- GPT-5.6 explanation is advisory.
- No plan is actionable before local validation and exact user approval.
- Codex edits only an isolated target.
- No automatic execution follows model output.
- No synthetic fixture command is executed.
- No new MCP or trust authority is introduced without separate review.

## Current State

`BW0 Baseline` and the revised architecture documentation are complete.

Guardian implementation is not yet complete. The current implementation target is `BW1 Codex-Native Explain`.
