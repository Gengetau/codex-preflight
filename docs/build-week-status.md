# Build Week Status

This document records the current public status of the Codex Preflight Guardian Build Week work on branch `codex/v0.4.0-build-week-guardian`.

## Baseline

- Released baseline: `v0.3.7@48a3b0e8d733cffe126da1fd97443039f011b98b`
- Build Week branch: `codex/v0.4.0-build-week-guardian`
- Draft pull request: `#15`
- Product flow: `Hook -> Detect -> Explain -> Approve -> Repair -> Verify -> Final Decision`

Only work after the released baseline is claimed as Build Week implementation.

## Checkpoint Status

- `BW0 Baseline`: complete.
- `BW1 Hook Gate and Explain`: engineering complete. Exact-runtime Bash `hook-active` certification remains explicitly deferred and is never inferred from packaging.
- `BW2 Exact Plan Approval`: complete. The closed remediation-plan and approval contracts, canonical plan identity, exact approval binding, rejection behavior, validity limits, and single-use enforcement are implemented and exercised.
- `BW3 Repair Capability Gate`: complete. The tested Windows Codex Desktop surface did not expose verified `apply_patch` Hook enforcement, so the supported path is `verified-isolated-repair` rather than `guarded-repair`.
- `BW4 Verify`: complete. The same planned command is deterministically rescanned and before/after evidence is compared without executing the command.
- `BW5 Plugin Experience`: complete. Clean install, capability probing, rejection behavior, fresh validity-conformant approval, single-use consumption, isolated repair, replay rejection, and deterministic verification all passed.
- `BW6 Submission Candidate`: active. Final public-document folding, evidence packaging, video/Devpost confirmation, final exact-head workflows, release diagnostics, and final review remain pending.

## Selected Codex Feedback Session

```text
019f6891-7fa8-7640-a629-379ee5ec0627
```

## Verified Windows Desktop Product Path

The clean-environment product path was exercised with:

- Windows 11 Pro x64
- Codex Desktop `26.715.21425`
- app-server API `v2`
- plugin version `0.3.7`
- marketplace ref `codex/v0.4.0-build-week-guardian`
- bundled Windows runtime SHA-256 `e165f00f8fc6452d9b65d534c46df164cd96e1cc2fb86abd52e69c6ce8777dbf`

Observed capability classification:

```text
Protection mode: skill-only
Bash Hook status: not verified
apply_patch Hook coverage: unsupported
Repair mode: verified-isolated-repair
```

This classification is intentionally conservative. The Desktop surface exposed PowerShell-based command execution and structured `apply_patch`, but no canonical `Bash` tool path. Pre-edit Hook enforcement is not claimed for that surface.

## Linux/Bash Certification Status

A native Linux Codex certification attempt was completed using a local-controller/remote-executor topology.

```text
Remote platform: Ubuntu 22.04 LTS, x86_64
Remote Codex version: 0.144.6
Remote Codex execution: native on Linux
Controller transport: SSH
shellToolObserved: exec_command
shell interpreter: /bin/bash
canonicalBashSurfaceAvailable: false
Hook event observed: false
Hook launcher observed: false
```

The remote Codex CLI installation, exact candidate checkout, and bundled Linux runtime digest checks passed. Certification did not pass because the model-visible tool API was `exec_command`, not the canonical `Bash` surface matched by `^Bash$`. Using `/bin/bash` as the interpreter does not change the tool identity.

```text
Linux/Bash hook-active certification: DEFERRED
Bash Hook status: NOT VERIFIED
Protection mode: skill-only
Reason: remote shellToolObserved was exec_command, not Bash
```

No Linux Hook-enforcement claim is made.

## BW5 Accepted-Plan Conformance History

The original accepted-plan attempt used a 55-minute validity window:

```text
createdAt: 2026-07-21T01:29:06Z
expiresAt: 2026-07-21T02:24:06Z
validity duration: 3300 seconds
contract maximum: 900 seconds
conformance result: FAIL
```

That plan, approval, target, session, and consumption identity remain invalid for conformance and must never be reused.

A fresh rerun was completed against candidate `9b414692667437ee1a5acbbb5bf72a2ea7a55262`.

### Fresh plan validity

```text
createdAt: 2026-07-21T04:14:30Z
expiresAt: 2026-07-21T04:24:30Z
validity duration: 600 seconds / 10 minutes
contract maximum: 900 seconds / 15 minutes
validity conformance: PASS
```

The plan and approval were unexpired immediately before consumption. The approval had 106 seconds remaining at the recorded pre-consumption check.

### Initial deterministic result

```text
Decision: BLOCK
Risk score: 50
Blocking rule: NODE_LIFECYCLE_REMOTE_EXEC
Before report: sha256:d5bf4171a57f21082ecd594a062dd9b36b645bb13082f4e2cfe4c22102401765
Command digest: sha256:fea6b934e37748291bdea99a3dbb76b3c889a7c00d06eced4516a6442abd954a
```

### Approval and repair

```text
Plan ID: guardian-plan-v1:sha256:a64d46d2735e617145643240c0b2d5c641892578dea01c2bd3d22713340dd038
Approval ID: guardian-approval-v1:sha256:9bbf5f61a600db6fd1978b27332d6421e760f11bd440169f55707e174d501d25
Approval records created: 1
Approval consumption count: 1
Approval replay: REJECTED
Approved paths: package.json
Actual changed paths: package.json
Approved postimage matched: yes
Target drift: false
Unexpected changes: 0
Outside-target changes: 0
```

### Final deterministic result

```text
Decision: ALLOW
Risk score: 0
After report: sha256:b87713d01caa98c322beb3f25d3f2cd35e94503c57c8896b5a6e7b93c7e314f
Command digest unchanged: yes
Removed rule: NODE_LIFECYCLE_REMOTE_EXEC
New blocking findings: none
Uncertainty: false
```

### Safety counters

```text
command_execution: 0
plannedCommandExecutions: 0
packageManagerCommandsExecuted: 0
npmInstallExecuted: 0
fixtureCommandsExecuted: 0
fixtureContentExecuted: 0
networkAccessDuringTest: 0
productSourceModifications: 0
pluginSourceModifications: 0
unexpectedChanges: 0
outsideTargetChanges: 0
```

The setup used one authorized Git fetch and a fresh clean detached checkout. The original dirty worktree remained unchanged. Setup-only Git network activity is recorded separately and is not test-phase network access.

Full report-level evidence is recorded in `docs/bw5-accepted-plan-pass.md`.

## Evidence Boundary

Public evidence must remain redacted: do not publish local usernames, absolute user-profile paths, server addresses, credentials, or unrelated machine identifiers.

The deterministic scanner remains the sole authority for `ALLOW`, `WARN`, `ASK_USER`, and `BLOCK`. GPT-5.6 explanation and plan proposal are advisory. The model cannot choose `planId`, create approval, consume approval, or authorize command execution.

## Exact-Head CI Record

Candidate `9b414692667437ee1a5acbbb5bf72a2ea7a55262` passed both:

- `CI`
- `Build plugin runtime`

The evidence and status documentation commits create a newer candidate head. Exact-head workflows must pass again before final acceptance.

## Remaining BW6 Gates

Before the Draft PR can be marked ready:

1. Fold the final status, installation guidance, supported-platform language, and known limitations into `README.md` and `BUILD_WEEK.md`.
2. Package redacted evidence and the final demo script.
3. Confirm video, Devpost, and repository links.
4. Record the final candidate commit.
5. Run Windows and Linux CI, packaged-runtime smoke tests, marketplace synchronization checks, release diagnostics, and exact-head review on that candidate.
6. Keep merge, tag, release, auto-merge, and ready-for-review disabled until all gates pass.
