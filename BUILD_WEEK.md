# OpenAI Build Week — Codex Preflight Guardian

## Project

**Codex Preflight Guardian — Hook, Explain, Approve, Repair, and Verify Before Execution**

Track: **Developer Tools**

Build Week branch: `codex/v0.4.0-build-week-guardian`

Released baseline: `v0.3.7@48a3b0e8d733cffe126da1fd97443039f011b98b`

Draft PR: `#15`

## Hook-Backed Codex-Native Product Identity

Codex Preflight Guardian remains a Codex plugin experience.

The Codex conversation is the product interface. The plugin combines:

- plugin-bundled `PreToolUse` hooks for deterministic guardrails on supported Codex tool paths
- the existing local stdio MCP server and deterministic scanner
- the existing Skill for explanation, approval, repair, and verification workflow guidance
- the active GPT-5.6 model inside Codex for advisory explanation and remediation planning

The Skill is not treated as a code-level enforcement boundary. The hook supplies the supported-tool guardrail; the Skill supplies the user-facing protocol.

The Build Week product does **not** require:

- a separate local web page
- a plugin-internal Responses API call
- an additional `OPENAI_API_KEY`
- a second authentication path
- a cloud backend
- a separately published malicious-looking demo repository

## Honest Hook Boundary

Codex currently supports plugin-bundled lifecycle hooks, including `PreToolUse` for `Bash`, `apply_patch`, and MCP tool calls.

The product will use the documented `permissionDecision: "deny"` response for blocking supported tool calls. It will not use unsupported `permissionDecision: "ask"` behavior.

The hook is a guardrail, not an operating-system or universal Codex enforcement boundary:

- plugin hooks do not run until the user reviews and trusts the current definition
- users can disable non-managed hooks
- interception of newer `unified_exec` shell behavior is incomplete
- Codex may have equivalent tool paths outside the intercepted set

Accordingly, the product claim is:

> When the plugin hook is trusted and active, Codex Preflight provides deterministic pre-tool guardrails for the supported Codex tool paths it intercepts.

The product does not claim to intercept every possible process or file mutation on the host.

## Product Story

`Hook → Detect → Explain → Approve → Repair → Verify → Final Decision`

1. Codex prepares a repository-dependent `Bash` command.
2. The trusted plugin `PreToolUse` hook reads the Codex hook envelope and runs the deterministic Preflight core before the supported tool call.
3. `ALLOW` may proceed; `ASK_USER`, `BLOCK`, scanner failure, and synthetic-demo execution are denied with a bounded reason and report identity. `WARN` handling remains explicit and tested rather than relying on unsupported hook-level ask behavior.
4. The deterministic result contains bounded `guardian-context/v1` evidence.
5. GPT-5.6 explains only that referenced evidence in the Codex conversation.
6. GPT-5.6 proposes `guardian-remediation-plan/v1` when repair is appropriate.
7. A local validator canonicalizes the complete closed-schema plan and computes a stable `planId`.
8. The user approves or rejects that exact `planId`.
9. A later `apply_patch` hook denies edits unless the exact approved plan, target identity, paths, operations, and preimage digests still match.
10. Codex applies only the approved plan in an isolated worktree, branch, or temporary demo copy.
11. The same planned command is rescanned and deterministic before/after evidence is shown.
12. A real command remains subject to a separate final human decision.

The deterministic engine remains the sole authority for `ALLOW`, `WARN`, `ASK_USER`, and `BLOCK`.

GPT-5.6 cannot change policy, mint approval, or declare a repair safe.

## Exact Plan Identity

`planId` is not a loose correlation identifier and is not approval by itself.

The intended form is:

```text
planId = guardian-plan-v1:sha256:<digest-of-complete-canonical-plan>
```

The digest must bind the complete validated plan, excluding only the `planId` field itself, including:

- schema version
- source report and command digests
- original deterministic decision
- isolated target identity
- exact ordered target paths and edit operations
- target-file preimage digests
- prohibited operations
- verification conditions
- expected deterministic improvement
- evidence references
- session or expiry binding where used

Unknown fields are rejected. Any field, nested value, operation order, path, preimage, or verification change produces a different `planId` or target-drift failure.

Before an edit, local code revalidates the complete plan, recomputes the ID, verifies the approval record, rechecks target state, and consumes the approval as single-use.

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

- plugin-bundled trusted `PreToolUse` guardrails for supported `Bash` and later `apply_patch` paths
- hook status, trust, and compatibility diagnostics for the judge path
- bounded and redacted `guardian-context/v1`
- Skill instructions for explanation by the active GPT-5.6 Codex session
- explicit separation between deterministic findings and model suggestions
- `guardian-remediation-plan/v1`
- complete deterministic canonicalization and stable `planId`
- exact human approval bound to the plan identity
- apply-time target and preimage revalidation
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

Before any attempted demonstration tool call, the judge path must visibly verify that the plugin hook is installed, trusted, enabled, and active. If that check fails, the demo stops and uses the read-only scanner path; it does not attempt the fixture command.

When the trusted hook is active, the synthetic marker is an unconditional deny rule even after the repaired static result becomes `ALLOW` or `WARN`.

The demo must never execute npm, pnpm, lifecycle hooks, shell payloads, Node.js, Python, Docker, build, test, or any fixture command and must never access the network.

Codex may edit only the prepared temporary copy after exact plan approval.

The video ends with:

```text
Deterministic verification: ALLOW or WARN
Hook guardrail: trusted and active
Execution status: denied by synthetic-demo policy
Synthetic fixture commands executed: 0
```

## Revised Build Week Checkpoints

- `BW0 Baseline`: released baseline, evidence boundary, branch, and Draft PR.
- `BW1 Hook Gate and Explain`: plugin hook feasibility, trust workflow, supported-tool deny semantics, bounded Guardian context, and GPT-5.6 explanation protocol.
- `BW2 Exact Plan Approval`: closed plan schema, complete canonical digest, stable `planId`, separate single-use approval, and drift tests.
- `BW3 Guarded Repair`: `apply_patch` guardrail and approved-plan-only Codex edit in isolation.
- `BW4 Verify`: same-command deterministic rescan and before/after comparison.
- `BW5 Plugin Experience`: clean package/plugin installation, hook trust verification, and one-prompt safe synthetic demo.
- `BW6 Submission Candidate`: README, evidence, `/feedback` ID, Devpost, video, CI, and exact-head review.

## Judge Path

The intended clean-environment path is:

1. Install Python 3.12 or newer.
2. Install `codex-preflight[mcp]`.
3. Add and install the Codex Preflight marketplace plugin.
4. Review and trust the bundled hook definition.
5. Verify hook status through the Codex hook UI and run plugin/MCP diagnostics.
6. Start a new Codex session using GPT-5.6.
7. Enter the documented safe synthetic demo prompt.
8. Approve or reject the exact displayed `planId`.
9. Observe hook-backed deterministic `BLOCK`, GPT-5.6 explanation, guarded isolated repair, and deterministic rescan.
10. Stop with synthetic execution denied and execution count `0`.

No local web server or additional API key is part of this path.

## Safety Model

- Deterministic policy remains authoritative.
- Repository evidence is untrusted data.
- GPT-5.6 explanation is advisory.
- Skill instructions are workflow guidance, not enforcement.
- Hook protection is reported only when trusted and active.
- No plan is actionable before complete canonical validation and exact approval.
- Codex edits only an isolated target.
- No automatic execution follows model output.
- No synthetic fixture command is executed.
- No new MCP or trust authority is introduced without separate review.

## Current State

`BW0 Baseline` and the revised hook-backed architecture documentation are complete.

Guardian hook and workflow implementation are not yet complete. The current implementation target is `BW1 Hook Gate and Explain`.