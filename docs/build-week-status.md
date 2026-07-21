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
- `BW5 Plugin Experience`: complete on a clean Windows 11 Codex Desktop installation.
- `BW6 Submission Candidate`: active. The selected `/feedback` Session ID is recorded; Linux/Bash certification is documented as deferred; final public-document folding, evidence packaging, video, final exact-head CI, and exact-head review remain pending.

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

A Linux/Bash Hook-active certification attempt was made from the available Codex Desktop session, but the execution-topology gate did not pass.

Observed topology:

```text
Observed platform: Windows x64
Codex surface: Codex Desktop agent session
shellToolObserved: exec_command
canonicalBashSurfaceAvailable: false
hookHost: none observed
remoteTransportUsed: false
```

The configured cloud server was not used through a local SSH wrapper because that would test the local `exec_command` and transport path, not a Codex runtime and `PreToolUse` Hook executing natively on the Linux host.

Final certification result:

```text
Linux/Bash hook-active certification: DEFERRED
Bash Hook status: NOT VERIFIED
Protection mode: skill-only
Reason: the actual Codex tool was exec_command, not the canonical Bash surface matched by ^Bash$
```

No allow or deny probe was attempted after the topology gate failed. No package manager, fixture content, network request, product edit, plugin edit, or Hook configuration change occurred. The project makes no Linux Hook-enforcement claim from this attempt.

## Safe Synthetic Judge Path

The accepted-plan path completed with the planned command `npm install` treated only as data.

Before repair:

```text
Decision: BLOCK
Risk score: 50
Blocking rule: NODE_LIFECYCLE_REMOTE_EXEC
Command digest: sha256:fea6b934e37748291bdea99a3dbb76b3c889a7c00d06eced4516a6442abd954a
```

Plan and approval:

```text
Plan ID: guardian-plan-v1:sha256:4a115d1234d504bd5a2b9f577589d01f62994a9439d12aad7bf28b1e5894dc15
Approval ID: guardian-approval-v1:sha256:f4424a85e512a35119fb9f1e32f5798dd6c552f518ab621235908e3e357a9284
Approval records created: 1
Approval consumption count: 1
Approval replay: REJECTED
```

Repair verification:

```text
Approved paths: package.json
Actual changed paths: package.json
Actual content matched approved postimage: yes
Unexpected changes: 0
Outside-target changes: 0
Target drift: false
```

After repair:

```text
Decision: ALLOW
Risk score: 0
Command digest unchanged: yes
Removed rule: NODE_LIFECYCLE_REMOTE_EXEC
New blocking findings: none
Uncertainty: false
```

Safety counters:

```text
command_execution: 0
npm install executed: 0
fixture content executed: 0
fixtureCommandsExecuted: 0
network access: 0
product source modifications: 0
```

The user-rejection path was also exercised separately. Rejecting the exact plan created no approval, consumed no authority, changed no file, and left the deterministic result at `BLOCK`.

## Evidence Boundary

The results above are report-level evidence from real product-path runs. Public evidence must remain redacted: do not publish local usernames, absolute user-profile paths, server addresses, credentials, or unrelated machine identifiers.

The deterministic scanner remains the sole authority for `ALLOW`, `WARN`, `ASK_USER`, and `BLOCK`. GPT-5.6 explanation and plan proposal are advisory. The model cannot choose `planId`, create approval, consume approval, or authorize command execution.

## Exact-Head CI Record

Candidate `be56dbd5a258c63abd60866c1fed3955042306e1` passed both:

- `CI`
- `Build plugin runtime`

This documentation update creates a newer candidate commit, so those workflows must pass again before final exact-head acceptance.

## Remaining Release Gates

Before the Draft PR can be marked ready:

1. Fold the final status and installation guidance into `README.md` and `BUILD_WEEK.md`.
2. Package redacted evidence and the final demo script.
3. Confirm video, Devpost, repository links, supported-platform wording, and known limitations.
4. Record the final candidate commit.
5. Run Windows and Linux CI, packaged-runtime smoke tests, marketplace synchronization checks, release diagnostics, and exact-head review on that candidate.
6. Keep merge, tag, and release disabled until all gates pass.
