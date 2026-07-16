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

- a plugin-bundled `PreToolUse` hook for deterministic guardrails on verified supported Codex tool paths
- the existing local stdio MCP server and deterministic scanner
- the existing Skill for explanation, approval, repair, and verification workflow guidance
- the active GPT-5.6 model inside Codex for advisory explanation and remediation planning

The Skill is not a code-level enforcement boundary. Hook coverage is claimed only after an exact-version, exact-surface runtime probe succeeds.

The Build Week product does **not** require:

- a separate local web page
- a plugin-internal Responses API call
- an additional `OPENAI_API_KEY`
- a second authentication path
- a cloud backend
- a separately published malicious-looking demo repository

## Honest Hook Boundary

Current Codex documentation and source describe plugin-bundled lifecycle hooks and `PreToolUse` support beyond simple Bash paths, but Hook behavior remains version-, operating-system-, and surface-dependent.

The implemented Build Week Hook currently targets `Bash` and uses the documented deny response. It does not use unsupported `permissionDecision: "ask"` behavior.

The product does not infer protection from configuration files or installed plugin files alone. A protection claim requires a live probe on the exact Codex build and surface used by the tester.

Known boundaries:

- plugin hooks do not run until the user reviews and trusts the current definition
- users can disable non-managed hooks
- Hook feature state must be checked on the exact build; current Codex source uses canonical feature key `hooks` and enables it by default, but older or managed builds may differ
- Windows support is not assumed from `commandWindows`; it remains unverified until a real Windows Hook probe passes
- interception of `unified_exec` and equivalent alternate paths may be incomplete
- `apply_patch` enforcement is conditional on a separate BW3 capability probe
- MCP, file-write, and other paths are not claimed merely because a current document or source tree mentions them
- process launch failure, timeout, disabled hooks, and unsupported paths are not host-level fail-closed conditions

Accordingly, the product claim is:

> When the exact Codex build and surface pass the Hook capability probe and the plugin Hook is trusted and active, Codex Preflight provides deterministic pre-tool guardrails for the verified tool paths it intercepts.

If any required probe fails, the product reports advisory or fallback mode and does not claim Hook enforcement.

## Protection Modes

The product reports one of these modes:

- `hook-active`: the exact build, surface, platform, Hook trust state, and tested tool path have passed a live probe
- `skill-only`: Skill and MCP are available, but no enforcement claim is made
- `explicit-wrapper`: the user deliberately uses a guarded CLI path such as `codex-preflight exec`
- `verified-isolated-repair`: pre-edit `apply_patch` enforcement is unavailable or unverified, so repair relies on isolation, complete patch review, deterministic rescan, and a separate final execution decision

Only `hook-active` may be described as supported-tool Hook coverage.

## Product Story

`Hook → Detect → Explain → Approve → Repair → Verify → Final Decision`

1. Codex prepares a repository-dependent command.
2. On a verified supported Bash path, the trusted `PreToolUse` Hook runs the deterministic Preflight core before the tool call.
3. `ALLOW` may proceed; `WARN`, `ASK_USER`, `BLOCK`, malformed input, scanner failure, and synthetic-demo execution follow the tested conservative policy.
4. The deterministic result supplies bounded `guardian-context/v1` evidence.
5. GPT-5.6 explains only that referenced evidence in the Codex conversation.
6. GPT-5.6 proposes `guardian-remediation-plan/v1` when repair is appropriate.
7. A local validator canonicalizes the complete closed-schema plan and computes a stable `planId`.
8. The user approves or rejects that exact `planId`.
9. BW3 first probes whether the exact Codex build exposes a usable `apply_patch` `PreToolUse` path and whether deny prevents the write.
10. If the probe passes, the Hook can enforce approved-plan and preimage checks before the verified edit path.
11. If the probe fails, Codex repairs only an isolated worktree or temporary copy, the complete resulting patch is checked against the approved plan, and any unexpected edit fails the repair gate.
12. The same planned command is rescanned and deterministic before/after evidence is shown.
13. A real command remains subject to a separate final human decision.

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

Before an edit, local code revalidates the complete plan, recomputes the ID, verifies the approval record, and rechecks target state.

When pre-edit Hook enforcement is unavailable, `planId` still defines the approved intent. The isolated repair is accepted only if the complete resulting patch matches the approved paths and operations and the deterministic rescan satisfies the verification gate.

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

- a verified Bash `PreToolUse` guardrail with honest platform and surface status
- Hook status, trust, feature-state, platform, and compatibility diagnostics for the judge path
- bounded and redacted `guardian-context/v1`
- Skill instructions for explanation by the active GPT-5.6 Codex session
- explicit separation between deterministic findings and model suggestions
- `guardian-remediation-plan/v1`
- complete deterministic canonicalization and stable `planId`
- exact human approval bound to the plan identity
- isolated Codex repair tied to the approved plan
- conditional pre-edit `apply_patch` enforcement only when the exact-version capability probe passes
- a documented `verified-isolated-repair` fallback when that probe does not pass
- deterministic same-command rescan and before/after verification
- clean plugin installation and one-prompt judge path
- safe temporary demo preparation from built-in corpus data
- public Build Week evidence and Codex collaboration records

Planned work is not presented as completed work.

## Safe Synthetic Demo

The public demo uses built-in corpus case `npm-postinstall-remote-exec`.

The case is synthetic, uses `example.invalid`, contains no working secret, and is intended only for static scanning.

A safe helper will prepare an allowlisted text-only copy in an operating-system temporary directory, reject links and binaries, add `SYNTHETIC_FIXTURE_DO_NOT_EXECUTE`, and record source identity.

Before any attempted demonstration tool call, the judge path must visibly verify the exact Codex build, platform, effective Hook feature state, plugin trust, Hook activation, and tested Bash interception path.

If that check fails on Windows or any other platform, the demo uses the read-only scanner path and does not attempt the fixture command.

When the trusted Bash Hook is verified active, the synthetic marker is an unconditional deny rule even after the repaired static result becomes `ALLOW` or `WARN`.

The demo must never execute npm, pnpm, lifecycle hooks, shell payloads, Node.js, Python, Docker, build, test, or any fixture command and must never access the network.

Codex may edit only the prepared temporary copy after exact plan approval.

The video must label which repair mode was used:

```text
Repair mode: guarded-repair
```

or:

```text
Repair mode: verified-isolated-repair
```

The video ends with:

```text
Deterministic verification: ALLOW or WARN
Bash Hook status: verified active, or read-only fallback
Execution status: denied by synthetic-demo policy or not attempted
Synthetic fixture commands executed: 0
```

## Revised Build Week Checkpoints

- `BW0 Baseline`: released baseline, evidence boundary, branch, and Draft PR.
- `BW1 Hook Gate and Explain`: Bash Hook feasibility, trust workflow, exact-version status path, bounded Guardian context, and GPT-5.6 explanation protocol.
- `BW2 Exact Plan Approval`: closed plan schema, complete canonical digest, stable `planId`, separate approval, and drift tests.
- `BW3 Repair Capability Gate`: probe `apply_patch` on the exact target build; use guarded repair when verified, otherwise use verified isolated repair without claiming pre-edit enforcement.
- `BW4 Verify`: same-command deterministic rescan and before/after comparison.
- `BW5 Plugin Experience`: clean installation, platform and Hook status verification, one-prompt safe synthetic demo, and explicit fallback behavior.
- `BW6 Submission Candidate`: README, evidence, `/feedback` ID, Devpost, video, CI, and exact-head review.

## Judge Path

The intended clean-environment path is:

1. Install Python 3.12 or newer.
2. Install `codex-preflight[mcp]`.
3. Add and install the Codex Preflight marketplace plugin.
4. Record the exact Codex version, surface, and operating system.
5. Check the effective Hook feature state. Current builds use canonical key `hooks`; do not require or document deprecated aliases as a universal step.
6. Review and trust the exact bundled Hook definition.
7. Run a harmless live Bash allow/deny probe and verify the Hook is actually active on that surface.
8. If the probe fails, select read-only fallback and do not attempt the synthetic command.
9. Start a new Codex session using GPT-5.6.
10. Enter the documented safe synthetic demo prompt.
11. Approve or reject the exact displayed `planId`.
12. Use `guarded-repair` only after an exact-build `apply_patch` capability probe passes; otherwise use `verified-isolated-repair`.
13. Observe deterministic rescan and before/after evidence.
14. Stop with fixture execution count `0`.

No local web server or additional API key is part of this path.

## Safety Model

- Deterministic policy remains authoritative.
- Repository evidence is untrusted data.
- GPT-5.6 explanation is advisory.
- Skill instructions are workflow guidance, not enforcement.
- Hook protection is reported only after an exact runtime probe.
- Windows Hook protection is never inferred from packaging or `commandWindows` alone.
- `apply_patch` enforcement is never inferred from documentation alone.
- No plan is actionable before complete canonical validation and exact approval.
- Every repair occurs only in an isolated target.
- The complete resulting patch must be reviewed against the approved plan.
- Deterministic same-command rescan is required.
- No automatic execution follows model output.
- No synthetic fixture command is executed.
- No new MCP or trust authority is introduced without separate review.

## Current State

`BW0 Baseline` and the hook-backed architecture planning are complete.

The bounded Bash Hook feasibility implementation exists on the Build Week branch. BW1 now includes
the deterministic `codex-preflight guardian verify-bw1` self-verification harness, additive
`guardian-context/v1` output on `preflight_check`, and independently validated
`guardian-explanation/v1` advisory output.

The verifier writes a sanitized evidence bundle under
`artifacts/bw1-self-verification/<utc-timestamp>/`. It returns `0` for `PASS`, `1` for `FAIL`, and
the distinct documented exit code `3` for `UNSUPPORTED`. `PASS` requires every phase and
`fixtureCommandsExecuted: 0`. An unavailable supported Codex shell, model, authentication, or MCP
surface is `UNSUPPORTED`; Hook failure, timeout, exit code 1, missing command attempt, fail-open,
ambiguous evidence, invalid explanation references, or unexpected command execution is `FAIL`.

The command does not modify Hook definitions, repositories under test, trust, policy, or execution
authority. It creates only isolated temporary Git repositories and the required sanitized evidence
bundle. BW2 approval, repair modes, and later Build Week checkpoints remain out of scope.
