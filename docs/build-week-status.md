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
- `BW1 Hook Gate and Explain`: engineering complete. Exact-runtime Bash `hook-active` certification is explicitly deferred and is never inferred from packaging.
- `BW2 Exact Plan Approval`: complete. Closed remediation-plan and approval contracts, canonical plan identity, exact approval binding, rejection behavior, and single-use enforcement are implemented and exercised.
- `BW3 Repair Capability Gate`: complete. The tested Windows Codex Desktop surface did not expose verified `apply_patch` Hook enforcement, so the supported path is `verified-isolated-repair` rather than `guarded-repair`.
- `BW4 Verify`: complete. The same planned command is deterministically rescanned and before/after evidence is compared without executing the command.
- `BW5 Plugin Experience`: blocked and not complete. Clean install, capability probing, rejection behavior, and accepted-repair mechanics passed, but the accepted-plan validity window was 55 minutes and violated the contract maximum of 15 minutes. A fresh accepted-plan rerun is required.
- `BW6 Submission Candidate`: preparation only. It must not be treated as active until BW5 passes the fresh validity-conformant rerun.

## Selected Codex Feedback Session

```text
019f6891-7fa8-7640-a629-379ee5ec0627
```

This is the primary `/feedback` Session ID selected for the Build Week submission record.

## Verified Windows Desktop Product Path

The clean-environment product path was exercised with:

- Windows 11 Pro x64
- Codex Desktop `26.715.21425`
- app-server API `v2`
- plugin version `0.3.7`
- marketplace ref `codex/v0.4.0-build-week-guardian`
- marketplace head `ea54ff0248756c686eac3655307491fd58a22a79`
- bundled Windows runtime SHA-256 `e165f00f8fc6452d9b65d534c46df164cd96e1cc2fb86abd52e69c6ce8777dbf`

Observed capability classification:

```text
Protection mode: skill-only
Bash Hook status: not verified
apply_patch Hook coverage: unsupported
Repair mode: verified-isolated-repair
```

This classification is intentionally conservative. The Desktop surface exposed PowerShell-based command execution and structured `apply_patch`, but no canonical `Bash` tool path. The `apply_patch` capability probe produced a successful isolated sentinel write without a Hook deny, so pre-edit Hook enforcement is not claimed.

## Linux/Bash Certification Status

A native Linux Codex certification attempt was completed using a local-controller/remote-executor topology.

Observed environment and topology:

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

The remote Codex CLI was installed successfully with `npm install -g @openai/codex`, a fresh native session was started from the exact upgraded binary, the candidate HEAD matched, and the bundled Linux runtime digest matched its manifest.

The certification still did not pass because the remote tool API was `exec_command`, not the canonical `Bash` surface matched by `^Bash$`. Using `/bin/bash` as the interpreter does not change the model-visible tool identity.

Final certification result:

```text
Linux/Bash hook-active certification: DEFERRED
Bash Hook status: NOT VERIFIED
Protection mode: skill-only
Reason: remote shellToolObserved was exec_command, not Bash
```

No allow, deny, or scanner probe was attempted after the hard gate failed. Probe-network access, package-manager execution during probes, fixture execution, product source modification, and plugin source modification all remained zero. Installation metadata created `.codex-marketplace-install.json`, so the installed marketplace worktree was not clean; this is recorded as installation metadata rather than a product-source change.

## BW5 Accepted-Plan Conformance Correction

The previously reported accepted-plan attempt demonstrated repair mechanics but cannot satisfy BW5 conformance.

Invalid attempt timing:

```text
createdAt: 2026-07-21T01:29:06Z
expiresAt: 2026-07-21T02:24:06Z
validity duration: 55 minutes / 3300 seconds
contract maximum: 15 minutes / 900 seconds
conformance result: FAIL
```

The previous approval and plan identities from that attempt must not be reused.

What remains valid from the attempt:

```text
Initial decision: BLOCK
Initial risk score: 50
Blocking rule: NODE_LIFECYCLE_REMOTE_EXEC
Repair mode: verified-isolated-repair
Approved paths: package.json
Actual changed paths: package.json
Actual content matched approved postimage: yes
Approval records created: 1
Approval consumption count: 1
Approval replay: REJECTED
After decision: ALLOW
After risk score: 0
Command digest unchanged: yes
Unexpected changes: 0
Outside-target changes: 0
command_execution: 0
npm install executed: 0
fixture content executed: 0
fixtureCommandsExecuted: 0
network access: 0
```

These results establish accepted-repair mechanics only. They do not establish accepted-plan validity conformance.

The separate user-rejection branch remains valid: rejecting the exact plan created no approval, consumed no authority, changed no file, and left the deterministic result at `BLOCK`.

## Required BW5 Rerun

The fresh rerun must use:

- a fresh isolated target;
- fresh `targetId`, `sessionId`, `rootDigest`, and `reportDigest`;
- a fresh plan and fresh `planId`;
- a validity interval of at most 900 seconds;
- the same planned `npm install` command treated only as data;
- exact `package.json`-only operation and complete postimage;
- one approval record, one successful consumption, and replay rejection;
- deterministic rescan of the same command digest;
- final `ALLOW` or `WARN` with maximum risk score `0` and no blockers;
- zero command, package-manager, fixture, and network execution.

The executable plan is documented in `docs/bw5-accepted-plan-rerun.md`.

## Evidence Boundary

The results above are report-level evidence from real product-path runs. Public evidence must remain redacted: do not publish local usernames, absolute user-profile paths, server addresses, credentials, or unrelated machine identifiers.

The deterministic scanner remains the sole authority for `ALLOW`, `WARN`, `ASK_USER`, and `BLOCK`. GPT-5.6 explanation and plan proposal are advisory. The model cannot choose `planId`, create approval, consume approval, or authorize command execution.

## Exact-Head CI Record

Candidate `de73ebb0fc1cba85fabf0b7ebf7bbdac3c289e0d` passed both:

- `CI`
- `Build plugin runtime`

This correction and rerun-plan update create newer candidate commits, so exact-head workflows must pass again before any final acceptance.

## Remaining Release Gates

Before the Draft PR can be marked ready:

1. Complete the fresh BW5 accepted-plan rerun and record a validity-conformant PASS.
2. Fold the final corrected status and installation guidance into `README.md` and `BUILD_WEEK.md`.
3. Package redacted evidence and the final demo script.
4. Confirm video, Devpost, repository links, supported-platform wording, and known limitations.
5. Record the final candidate commit.
6. Run Windows and Linux CI, packaged-runtime smoke tests, marketplace synchronization checks, release diagnostics, and exact-head review on that candidate.
7. Keep merge, tag, release, auto-merge, and ready-for-review disabled until all gates pass.
