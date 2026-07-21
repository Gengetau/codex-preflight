# Build Week Status

Current public status for Codex Preflight Guardian on branch `codex/v0.4.0-build-week-guardian`.

## Baseline

- Released baseline: `v0.3.7@48a3b0e8d733cffe126da1fd97443039f011b98b`
- Draft pull request: `#15`
- Product flow: `Hook -> Detect -> Explain -> Approve -> Repair -> Verify -> Final Decision`

Only work after the released baseline is claimed as Build Week implementation.

## Checkpoints

- `BW0 Baseline`: complete.
- `BW1 Hook Gate and Explain`: engineering complete; exact-runtime Bash Hook-active certification remains deferred.
- `BW2 Exact Plan Approval`: complete.
- `BW3 Repair Capability Gate`: complete with `verified-isolated-repair` on the tested Codex surfaces.
- `BW4 Verify`: complete.
- `BW5 Plugin Experience`: complete after a fresh validity-conformant accepted-plan run.
- `BW6 Submission Candidate`: active; public links, final freeze, and exact-head review remain.

## Tested Product Modes

### Windows Codex Desktop

```text
Platform: Windows 11 x64
Codex Desktop: 26.715.21425
Protection mode: skill-only
Bash Hook status: NOT VERIFIED
apply_patch Hook coverage: unsupported on the tested surface
Repair mode: verified-isolated-repair
```

The tested Desktop surface exposed PowerShell-backed `exec_command` and structured `apply_patch`, not the canonical `Bash` tool matched by the current `^Bash$` Hook matcher.

### Native Linux Codex

```text
Platform: Ubuntu 22.04 x64
Codex CLI: 0.144.6
Remote Codex execution: native on Linux
shellToolObserved: exec_command
shell interpreter: /bin/bash
PreToolUse event observed: false
Hook launcher observed: false
Linux/Bash Hook-active certification: NOT VERIFIED / DEFERRED
Protection mode: skill-only
```

The exact candidate and bundled Linux runtime digest matched. Using `/bin/bash` as the interpreter does not make the model-visible tool API `Bash`. No Linux or Windows Bash Hook-enforcement claim is made.

## BW5 Public Result Summary

A fresh accepted-plan run used a `600`-second validity window, within the `900`-second contract maximum.

```text
Initial: BLOCK / 50 / NODE_LIFECYCLE_REMOTE_EXEC
Approval records created: 1
Approval consumption count: 1
Approval replay: REJECTED
Approved paths: package.json
Actual changed paths: package.json
Approved postimage matched: yes
Target drift: false
Final: ALLOW / 0
Command digest unchanged: yes
```

Safety result:

```text
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

The string `npm install` was treated only as command data and was never executed.

## Validation Coverage

The latest fully validated evidence candidate passed:

- Windows and Ubuntu test, lint, marketplace-copy, and release-readiness jobs;
- Windows and Ubuntu MCP runtime smoke tests;
- Windows x64 and Linux x64 standalone runtime builds and platform smoke tests;
- assembled installed-plugin launcher smoke tests.

The final submission commit must pass the same exact-head workflows after the YouTube and Devpost links are added.

## Evidence Boundary

This public page contains a redacted result summary only. Detailed execution runbooks, approval identities, raw report digests, session records, correction history, recording scripts, and account-bound submission controls are maintained outside the product repository.

The deterministic scanner remains policy authority. GPT-5.6 explanation and remediation-plan proposal are advisory. The model cannot choose `planId`, create or consume approval, or authorize execution.

## Remaining BW6 Gates

1. Publish the YouTube demo.
2. Complete the Devpost project.
3. Add the public links to `README.md`, `BUILD_WEEK.md`, and PR #15.
4. Freeze the resulting branch HEAD.
5. Require exact-head `CI` and `Build plugin runtime` success.
6. Perform final claim and evidence review.

Keep PR #15 Draft. Do not merge, tag, release, enable auto-merge, or mark ready until the final submission freeze is complete.
