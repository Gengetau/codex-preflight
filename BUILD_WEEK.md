# OpenAI Build Week — Codex Preflight Guardian

## Project

**Codex Preflight Guardian — Explain, Approve, Repair, and Verify Before Execution**

Track: **Developer Tools**

- Build Week branch: `codex/v0.4.0-build-week-guardian`
- Released baseline: `v0.3.7@48a3b0e8d733cffe126da1fd97443039f011b98b`
- Draft PR: `#15`

Only work after the released baseline is claimed as Build Week implementation.

## Product Identity

Codex Preflight Guardian is a Codex plugin experience:

```text
Hook -> Detect -> Explain -> Approve -> Repair -> Verify -> Final Decision
```

The product combines:

- a local deterministic scanner and policy engine;
- the existing local stdio MCP tools `preflight_check` and `corpus_scan`;
- a plugin-bundled `PreToolUse` Hook for exact tool surfaces that pass a live capability probe;
- Skill guidance for the explanation, approval, repair, and verification workflow;
- GPT-5.6 inside Codex for advisory explanation and remediation-plan proposal;
- local closed-schema validation, canonical plan identity, exact approval, single-use consumption, isolated repair, and deterministic same-command verification.

The deterministic engine remains the sole authority for `ALLOW`, `WARN`, `ASK_USER`, and `BLOCK`. GPT-5.6 cannot change policy, choose `planId`, create or consume approval, declare a repository safe, or authorize command execution.

Normal plugin use does not require:

- a separate web application;
- a plugin-internal model API call;
- an additional `OPENAI_API_KEY`;
- a second authentication path;
- a cloud backend;
- a separately published malicious-looking demo repository;
- a user-managed Python environment.

## Prior Work Boundary

The released `v0.3.7` baseline already provided:

- local-first static repository and planned-command scanning;
- deterministic policy decisions and execution-chain evidence;
- package lifecycle, shell, Docker, GitHub Actions, MCP, secret, instruction, README-link, Rust, Go, Ruby, Java, and Kotlin analysis;
- CLI, MCP, Skill, and plugin packaging;
- JSON/Markdown reports, comparison, trust/cache controls, corpus fixtures, and release diagnostics.

Build Week added the Guardian workflow around that deterministic core:

- bounded `guardian-context/v1` evidence;
- explicit separation of deterministic findings from GPT advisory explanation;
- closed `guardian-remediation-plan/v1` with complete intended postimages;
- stable content-derived `planId`;
- separate `guardian-plan-approval/v1` authority with expiry and single-use enforcement;
- capability-gated repair-mode selection;
- `verified-isolated-repair` for tool surfaces without verified pre-edit enforcement;
- approval replay rejection and target-drift checks;
- same-command deterministic before/after verification;
- self-contained Windows x64 and Linux x64 plugin runtimes;
- clean plugin installation and a no-execution judge/demo path.

## Exact Plan and Approval Boundary

`planId` identifies the complete validated plan; it is not approval.

```text
planId = guardian-plan-v1:sha256:<digest-of-complete-canonical-plan>
```

The identity binds the source report and command, original deterministic decision, isolated target, session, ordered operations, preimages, complete UTF-8 postimages, prohibited operations, verification requirements, evidence references, and validity interval. Unknown fields or any bound-value change fail validation or produce a different ID.

Approval is a separate record bound to the exact plan, target, session, nonce, approval time, expiry, and single-use state. Target and preimage state are revalidated immediately before consumption.

## Protection and Repair Modes

The product reports its actual mode rather than inferring protection from installation files:

- `hook-active`: the exact Codex version, platform, surface, trust state, and tested tool path passed a harmless live Hook probe;
- `skill-only`: Skill and MCP are available, but no Hook-enforcement claim is made;
- `explicit-wrapper`: the user deliberately selects the guarded CLI execution path;
- `guarded-repair`: an exact-build edit-path probe proved deny-before-write behavior;
- `verified-isolated-repair`: pre-edit enforcement was unavailable or unverified, so repair is bounded by isolation, exact approved postimages, complete patch comparison, replay protection, deterministic rescan, and a separate final execution decision.

Only `hook-active` may be described as verified Hook coverage.

## Tested Capability Boundary

### Windows Codex Desktop

The clean-install product path passed on Windows 11 x64 with Codex Desktop `26.715.21425`, app-server API `v2`, plugin `0.3.7`, and the digest-bound bundled Windows runtime.

Observed classification:

```text
Protection mode: skill-only
Bash Hook status: NOT VERIFIED
apply_patch Hook coverage: unsupported on the tested surface
Repair mode: verified-isolated-repair
```

The surface exposed PowerShell-backed `exec_command` and structured `apply_patch`, not a canonical `Bash` tool event matched by `^Bash$`.

### Native Linux Codex

A native Ubuntu 22.04 x64 Codex session was launched on a cloud server after installing Codex CLI `0.144.6`. Candidate identity and the bundled Linux runtime digest matched.

Observed classification:

```text
remoteCodexNativeExecution: true
shellToolObserved: exec_command
shell interpreter: /bin/bash
Hook matcher: ^Bash$
PreToolUse event observed: false
Hook launcher observed: false
Linux/Bash Hook-active certification: NOT VERIFIED / DEFERRED
Protection mode: skill-only
```

Using `/bin/bash` as the interpreter does not change the model-visible tool identity from `exec_command` to `Bash`. No Linux or Windows Bash Hook-enforcement claim is made.

## Completed Guardian Path

The final accepted-plan conformance run used a fresh isolated target and a `600`-second plan, below the `900`-second contract maximum.

```text
Initial deterministic result: BLOCK / 50
Blocking rule: NODE_LIFECYCLE_REMOTE_EXEC
Approval records created: 1
Approval consumption count: 1
Approval replay: REJECTED
Approved paths: package.json
Actual changed paths: package.json
Approved postimage matched: yes
Target drift: false
Final deterministic result: ALLOW / 0
Command digest unchanged: yes
```

The repair changed only `package.json` inside the isolated target. The same planned command string was rescanned after repair.

Safety result:

```text
planned command executions: 0
package-manager executions: 0
npm install executions: 0
fixture command executions: 0
fixture-content executions: 0
test-phase network access: 0
product-source modifications: 0
plugin-source modifications: 0
unexpected changes: 0
outside-target changes: 0
```

## Build Week Checkpoints

- `BW0 Baseline`: **complete** — released baseline, branch, prior-work boundary, and Draft PR established.
- `BW1 Hook Gate and Explain`: **engineering complete** — bounded Hook implementation, Guardian context, advisory explanation protocol, and honest exact-runtime capability reporting delivered. Bash Hook-active certification remains deferred.
- `BW2 Exact Plan Approval`: **complete** — closed plan and approval contracts, canonical plan identity, expiry, rejection, drift checks, and single-use authority delivered and exercised.
- `BW3 Repair Capability Gate`: **complete** — exact-surface capability probe selected `verified-isolated-repair`; package.json-only bounded repair, postimage matching, and replay rejection passed.
- `BW4 Verify`: **complete** — unchanged-command deterministic rescan and before/after evidence passed without executing the command.
- `BW5 Plugin Experience`: **complete** — clean installation, capability classification, valid 600-second accepted plan, one approval/consumption, isolated repair, replay rejection, and `BLOCK / 50 -> ALLOW / 0` verification passed.
- `BW6 Submission Candidate`: **submitted / validation pending** — YouTube and Devpost are published; this submission-link commit must pass final exact-head review.

## Validation Coverage

The latest fully validated evidence candidate passed:

- Windows and Ubuntu test suites;
- lint and release-readiness diagnostics;
- marketplace-copy synchronization checks;
- Windows and Ubuntu MCP runtime smoke tests;
- Windows x64 and Linux x64 standalone runtime builds and platform smoke tests;
- assembled installed-plugin launcher smoke tests.

Documentation-only submission commits create newer heads, so the final frozen submission commit must pass the same exact-head workflows again.

## Public Judge Path

1. Add the repository as a Codex marketplace and install the plugin.
2. Start a new Codex session so the current Skill, MCP definition, Hook definition, and bundled runtime are loaded.
3. Record the exact Codex version, surface, operating system, feature state, and observed tool names.
4. Report `hook-active` only after a harmless live allow/deny probe succeeds on the exact tool path.
5. Otherwise report `skill-only` and use the read-only scanner/advisory path.
6. Prepare a fresh isolated copy of the built-in synthetic lifecycle fixture.
7. Treat `npm install` only as planned-command data; never execute it.
8. Show deterministic `BLOCK / 50 / NODE_LIFECYCLE_REMOTE_EXEC` and bounded evidence.
9. Show GPT-5.6 advisory explanation separately.
10. Display the complete closed remediation plan and exact content-derived `planId`.
11. Create one separate, time-bounded, single-use approval.
12. Use `verified-isolated-repair` unless the exact edit path has separately proved deny-before-write behavior.
13. Verify the complete resulting content against the approved postimage.
14. Reject approval replay.
15. Rescan the same command identity and show `ALLOW / 0`.
16. Stop with all planned-command, package-manager, fixture, and test-network execution counters at zero.

## Submission Status

Published owner-account links:

```text
YouTube demo URL: https://youtu.be/L2L_fuGgzFM
Devpost project/submission URL: https://devpost.com/software/codex-preflight-guardian
```

Devpost submission `1110678` is `Submitted` in the `Developer Tools` category.

This submission-link commit is the final candidate and must pass exact-head `CI` and `Build plugin runtime` before final acceptance.

PR #15 remains Draft. This document authorizes no merge, tag, release, auto-merge, or ready-for-review transition.
