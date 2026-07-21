# BW5 Accepted-Plan Conformance Rerun

This plan closes the remaining BW5 conformance gap. It replaces no production behavior and authorizes no command execution.

## Purpose

The previous accepted-plan attempt demonstrated approval, single-use consumption, isolated repair, replay rejection, and deterministic `BLOCK -> ALLOW` mechanics. It did not satisfy the validity contract because its plan window was 55 minutes (`3300` seconds), greater than the maximum permitted 15 minutes (`900` seconds).

This rerun must prove the same mechanics with a fresh plan whose validity interval is at most 900 seconds.

## Non-Reuse Rule

Do not reuse any identity from the invalid attempt, including:

- target directory;
- `targetId`;
- `sessionId`;
- `rootDigest`;
- `reportDigest`;
- `planId`;
- `approvalId`;
- approval record;
- approval-consumption state.

A copied or regenerated plan with an old identity is a failure.

## Safety Boundary

- Treat `npm install` only as command data.
- Never execute `npm install`, another package manager, a lifecycle script, fixture content, downloaded content, or a build/test command.
- Use a fresh operating-system temporary directory outside the product repository and plugin installation.
- The synthetic target may contain only the minimum fixture needed for the known `NODE_LIFECYCLE_REMOTE_EXEC` finding.
- The only authorized repair path is `package.json` inside the isolated target.
- Do not modify product source, plugin source, Hook configuration, marketplace metadata, or unrelated files.
- Do not commit, push, merge, tag, release, enable auto-merge, or mark PR #15 ready.
- Stop on uncertainty, drift, digest mismatch, unexpected paths, expired authority, or malformed evidence.

## Required Starting State

Before creating the isolated target:

1. Fetch branch `codex/v0.4.0-build-week-guardian`.
2. Record the exact current branch HEAD with `git rev-parse HEAD`.
3. Confirm the product worktree is clean.
4. Confirm the plugin/runtime identity used for the run.
5. Confirm the deterministic scanner and approval store are the intended current implementation.
6. Create a fresh session identity for this rerun.

Do not use a stale checkout. Documentation-only commits may have advanced the branch since the previous candidate.

## Phase A — Fresh Isolated Target

Create a fresh temporary target outside the repository.

Record:

- redacted target path;
- `targetId`;
- `sessionId`;
- `rootDigest`;
- initial file list and hashes;
- symlink status;
- product repository HEAD;
- runtime identity and digest.

Reject the target if it is a symlink, is inside the repository/plugin tree, or contains unexpected files.

Create the minimum synthetic `package.json` fixture that deterministically produces `NODE_LIFECYCLE_REMOTE_EXEC`. Do not execute its content.

## Phase B — Initial Deterministic Scan

Call the scanner with planned command string:

```text
npm install
```

The command is data only.

Required initial result:

```yaml
decision: BLOCK
riskScore: 50
blockingRuleIds:
  - NODE_LIFECYCLE_REMOTE_EXEC
uncertainty: false
commandExecuted: false
networkAccess: false
fixtureExecuted: false
```

Record:

- `reportDigest`;
- `commandDigest`;
- target/root digest;
- finding evidence;
- exact preimage of `package.json`.

Stop if the initial result differs.

## Phase C — Generate a Fresh Closed Plan

Generate one complete `guardian-remediation-plan/v1` bound to the fresh identities and initial evidence.

The plan must include:

- exact source, target, session, root, report, and command binding;
- exact preimage digest;
- one operation affecting only `package.json`;
- complete approved postimage;
- prohibited operations and paths;
- deterministic verification requirements;
- `createdAt` and `expiresAt`;
- a fresh canonical `planId` calculated by the implementation.

Validity requirements:

```text
expiresAt - createdAt <= 900 seconds
recommended duration: 600 seconds
```

The executor must calculate and print the interval explicitly in both seconds and minutes.

The plan must be unexpired when presented for approval. Do not pre-create approval authority.

### Mandatory Stop Point

After generating the complete plan:

- print the complete plan;
- print the fresh `planId`;
- print `createdAt`;
- print `expiresAt`;
- print the computed validity duration;
- print the remaining time at the moment of presentation;
- stop before approval creation, repair, or file modification.

The human approval response must bind to this exact plan. Anything other than the exact approval response is rejection.

If the plan expires before approval or execution, discard it and restart from Phase A with all-new identities.

## Phase D — Approval Validation

Continue only after explicit approval of the exact fresh plan.

Required behavior:

1. Create exactly one `guardian-plan-approval/v1` record.
2. Bind it to the exact fresh `planId`, target, session, report, command, preimage, postimage, and validity interval.
3. Confirm the plan and approval are both unexpired.
4. Validate authority without consuming it during dry validation.
5. Record the fresh `approvalId`.

Stop on any mismatch.

## Phase E — Single-Use Consumption and Isolated Repair

Immediately before mutation:

- re-hash the target;
- prove the preimage and root have not drifted;
- prove only `package.json` is authorized;
- confirm no symlinks or path escapes;
- confirm the plan and approval remain unexpired.

Then:

1. Consume the approval exactly once.
2. Apply the exact complete approved postimage to `package.json`.
3. Do not run a shell/package-manager command to perform the repair when a bounded file write is available.
4. Record all changed paths and hashes.
5. Attempt replay and require rejection.

Required repair evidence:

```yaml
approvalRecordsCreated: 1
approvalConsumptionCount: 1
approvalReplay: REJECTED
approvedPaths:
  - package.json
actualChangedPaths:
  - package.json
actualContentMatchedApprovedPostimage: true
unexpectedChanges: 0
outsideTargetChanges: 0
targetDrift: false
```

## Phase F — Deterministic Rescan

Rescan the same target with the exact same planned command string and command digest.

Required final result:

```yaml
decision: ALLOW
riskScore: 0
blockingRuleIds: []
removedRuleIds:
  - NODE_LIFECYCLE_REMOTE_EXEC
uncertainty: false
commandDigestUnchanged: true
commandExecuted: false
networkAccess: false
fixtureExecuted: false
```

`WARN` is acceptable only if maximum risk remains `0`, there are no blocking findings, and the warning is unrelated to the repaired finding. Any blocker is a failure.

## Phase G — Integrity Review

Verify:

- product worktree unchanged;
- plugin worktree unchanged from its pre-run state;
- isolated target changed only at `package.json`;
- final content equals the approved complete postimage;
- no process executed the planned command;
- no package manager or lifecycle process ran;
- no fixture content ran;
- no network request occurred;
- no files outside the isolated target changed;
- no unexpected child process remains.

Required safety counters:

```yaml
safety:
  command_execution: 0
  packageManagerCommandsExecuted: 0
  npmInstallExecuted: 0
  fixtureCommandsExecuted: 0
  fixtureContentExecuted: 0
  networkAccess: 0
  productSourceModifications: 0
  pluginSourceModifications: 0
  unexpectedChanges: 0
  outsideTargetChanges: 0
```

## Pass Criteria

Declare `BW5 accepted-plan rerun: PASS` only when all of the following are true:

1. all target/session/evidence/plan/approval identities are fresh;
2. the plan validity interval is no greater than 900 seconds;
3. the plan was unexpired at approval creation and consumption;
4. initial scan is `BLOCK / 50` with `NODE_LIFECYCLE_REMOTE_EXEC`;
5. exactly one approval record is created;
6. authority is consumed exactly once;
7. replay is rejected;
8. only `package.json` changes;
9. actual content matches the approved complete postimage;
10. deterministic rescan uses the same command digest;
11. final result is `ALLOW / 0` with no blockers;
12. all execution, fixture, network, unexpected-change, and outside-target counters are zero.

Any failed item leaves BW5 blocked.

## Copy-Paste Instruction for Codex

```text
Execute the BW5 accepted-plan conformance rerun exactly as specified in docs/bw5-accepted-plan-rerun.md on the latest clean HEAD of branch codex/v0.4.0-build-week-guardian.

Treat npm install only as data. Do not execute package managers, lifecycle scripts, fixture content, build/test commands, or network actions.

Use a fresh isolated target and fresh targetId, sessionId, rootDigest, reportDigest, planId, approvalId, and approval state. Do not reuse any identity from the previous invalid attempt.

Generate a complete guardian-remediation-plan/v1 with a validity interval of at most 900 seconds; use 600 seconds unless the implementation requires a shorter value. Calculate and print the exact duration.

Stop after printing the complete fresh plan, planId, createdAt, expiresAt, duration, and remaining validity. Do not create approval, modify files, or continue repair until the exact plan receives explicit human approval.

Maintain zero command, package-manager, fixture, and network execution. Do not modify product/plugin source or GitHub state.
```

## Result Template

```yaml
bw5AcceptedPlanRerun:
  branchHead: null
  targetId: null
  sessionId: null
  rootDigest: null
  beforeReportDigest: null
  afterReportDigest: null
  commandDigest: null
  planId: null
  approvalId: null
  createdAt: null
  expiresAt: null
  validitySeconds: null
  validityConformant: false
  initial:
    decision: null
    riskScore: null
    blockingRuleIds: []
  approval:
    recordsCreated: 0
    consumptionCount: 0
    replayRejected: false
  repair:
    approvedPaths: []
    actualChangedPaths: []
    postimageMatch: false
    targetDrift: null
    unexpectedChanges: null
    outsideTargetChanges: null
  final:
    decision: null
    riskScore: null
    blockingRuleIds: []
    commandDigestUnchanged: false
  safety:
    command_execution: 0
    packageManagerCommandsExecuted: 0
    npmInstallExecuted: 0
    fixtureCommandsExecuted: 0
    fixtureContentExecuted: 0
    networkAccess: 0
    productSourceModifications: 0
    pluginSourceModifications: 0
  result: null
```
