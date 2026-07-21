# BW5 Accepted-Plan Conformance Rerun

This plan closes the remaining BW5 conformance gap. It replaces no production behavior and authorizes no execution of the planned command.

## Purpose

The previous accepted-plan attempt demonstrated approval, single-use consumption, isolated repair, replay rejection, and deterministic `BLOCK -> ALLOW` mechanics. It did not satisfy the validity contract because its plan window was 55 minutes (`3300` seconds), greater than the maximum permitted 15 minutes (`900` seconds).

This rerun must prove the same mechanics with a fresh plan whose validity interval is at most 900 seconds.

## Prior Synchronization Block

A first attempt to start this rerun stopped before creating any target, identity, plan, approval, or repair because the local checkout was dirty and stale and the instruction prohibited the Git network operation required to obtain the current branch and this document.

That stop is not a BW5 conformance result. It created no reusable authority or test identity.

This corrected plan distinguishes setup activity from test activity:

- setup-only Git network access is allowed solely to fetch the exact Build Week branch and prepare a fresh isolated checkout;
- read-only Git and filesystem inspection commands are allowed and must be recorded separately;
- after the test-phase boundary is declared, network access must remain zero;
- the planned command `npm install`, package managers, lifecycle scripts, fixture content, and downloaded content must never be executed.

## Non-Reuse Rule

Do not reuse any identity from the invalid 55-minute attempt, including:

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

The synchronization-blocked attempt created none of these identities, so it contributes nothing to the rerun other than the setup correction above.

## Safety and Counter Semantics

Treat these categories separately.

### Setup operations

Allowed before the test-phase boundary:

- `git fetch` for `codex/v0.4.0-build-week-guardian`;
- read-only Git inspection;
- creation of a fresh detached worktree from the fetched commit, or a fresh single-branch clone;
- read-only verification of the candidate, runtime, scanner, and approval-store identity.

Setup operations must be recorded as:

```yaml
setup:
  gitFetchOperations: 0
  setupNetworkOperations: 0
  readOnlyOrchestrationCommands: 0
```

Setup network operations do not count as test-phase network access.

### Test operations

From the declared test-phase boundary onward:

- `networkAccessDuringTest` must remain `0`;
- `plannedCommandExecutions` must remain `0`;
- `packageManagerCommandsExecuted` must remain `0`;
- `fixtureCommandsExecuted` and `fixtureContentExecuted` must remain `0`.

The legacy field `command_execution` means execution of the planned command or fixture payload. It does not mean ordinary read-only orchestration commands used to inspect Git state, hashes, or evidence.

## Hard Safety Boundary

- Treat `npm install` only as command data.
- Never execute `npm install`, another package manager, a lifecycle script, fixture content, downloaded content, or a build/test command.
- Use a fresh operating-system temporary directory outside the product repository and plugin installation.
- The synthetic target may contain only the minimum fixture needed for the known `NODE_LIFECYCLE_REMOTE_EXEC` finding.
- The only authorized repair path is `package.json` inside the isolated target.
- Do not modify product source, plugin source, Hook configuration, marketplace metadata, or unrelated files.
- Do not reset, clean, switch, stash, or modify the user's dirty local worktree.
- Do not commit, push, merge, tag, release, enable auto-merge, or mark PR #15 ready.
- Stop on uncertainty, drift, digest mismatch, unexpected paths, expired authority, or malformed evidence.

## Phase 0 — Synchronize Without Touching the Dirty Worktree

The local dirty worktree is evidence-preserving and must remain untouched.

1. Record its current branch, HEAD, and `git status --porcelain` for context only.
2. Fetch exactly the Build Week branch:

   ```text
   git fetch --no-tags origin codex/v0.4.0-build-week-guardian
   ```

3. Record the fetched commit from `FETCH_HEAD`.
4. Verify this document exists in the fetched commit:

   ```text
   git show FETCH_HEAD:docs/bw5-accepted-plan-rerun.md
   ```

5. Create a fresh detached worktree outside the dirty worktree:

   ```text
   git worktree add --detach <fresh-worktree-path> FETCH_HEAD
   ```

   A fresh single-branch clone is also acceptable when worktree creation is unavailable.

6. In the fresh checkout, require:

   ```text
   git rev-parse HEAD == fetched FETCH_HEAD
   git status --porcelain == empty
   ```

7. Record the exact fresh candidate HEAD. Do not assume a previously reported SHA remains current.
8. Confirm that the dirty original worktree was not changed.

Stop if the fetch fails, this document is absent, or the fresh checkout is not clean.

## Phase 1 — Verify Current Candidate Identity

In the fresh clean checkout:

- record branch source and exact detached HEAD;
- confirm `docs/bw5-accepted-plan-rerun.md` is the fetched version;
- confirm product source is clean;
- confirm the plugin/runtime identity used for the run;
- confirm the deterministic scanner and approval store are the intended current implementation;
- record any pre-existing plugin-installation metadata separately from product-source cleanliness.

Do not create test identities yet.

## Test-Phase Boundary

Immediately before creating the isolated target, print and record:

```yaml
testPhaseBoundary:
  candidateHead: null
  startedAt: null
  setupComplete: true
  networkDisabledForTest: true
```

From this point onward, no network operation is allowed.

## Phase A — Fresh Isolated Target

Create a fresh temporary target outside the repository and plugin installation.

Record:

- redacted target path;
- fresh `targetId`;
- fresh `sessionId`;
- fresh `rootDigest`;
- initial file list and hashes;
- symlink status;
- product candidate HEAD;
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

- fresh `reportDigest`;
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

Calculate and print the interval explicitly in seconds and minutes.

The plan must be unexpired when presented for approval. Do not pre-create approval authority.

### Mandatory Stop Point

After generating the complete plan:

- print the complete plan;
- print the fresh `planId`;
- print `createdAt`;
- print `expiresAt`;
- print the computed validity duration;
- print the remaining time at presentation;
- print all fresh target/session/evidence identities;
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
3. Use a bounded file write, not a package-manager or lifecycle command.
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

- the dirty original worktree remains exactly as it was before setup;
- the fresh candidate checkout remains clean;
- plugin state is unchanged from its recorded pre-run state;
- the isolated target changed only at `package.json`;
- final content equals the approved complete postimage;
- no process executed the planned command;
- no package manager or lifecycle process ran;
- no fixture content ran;
- no network request occurred after the test-phase boundary;
- no files outside the isolated target changed;
- no unexpected child process remains.

Required counters:

```yaml
setup:
  gitFetchOperations: 1
  setupNetworkOperations: 1
  readOnlyOrchestrationCommands: null
safety:
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

## Pass Criteria

Declare `BW5 accepted-plan rerun: PASS` only when all of the following are true:

1. the remote branch was fetched and a fresh clean checkout was used without modifying the dirty original worktree;
2. all target/session/evidence/plan/approval identities are fresh;
3. the plan validity interval is no greater than 900 seconds;
4. the plan was unexpired at approval creation and consumption;
5. initial scan is `BLOCK / 50` with `NODE_LIFECYCLE_REMOTE_EXEC`;
6. exactly one approval record is created;
7. authority is consumed exactly once;
8. replay is rejected;
9. only `package.json` changes;
10. actual content matches the approved complete postimage;
11. deterministic rescan uses the same command digest;
12. final result is `ALLOW / 0` with no blockers;
13. all planned-command, package-manager, fixture, test-network, unexpected-change, and outside-target counters are zero.

Any failed item leaves BW5 blocked.

## Copy-Paste Instruction for Codex

```text
Execute the BW5 accepted-plan conformance rerun from docs/bw5-accepted-plan-rerun.md.

The current local checkout may be dirty and stale. Do not reset, clean, switch, stash, or modify it.

You are authorized to perform setup-only Git network access for exactly this purpose:
1. git fetch --no-tags origin codex/v0.4.0-build-week-guardian
2. verify docs/bw5-accepted-plan-rerun.md exists in FETCH_HEAD
3. create a fresh detached worktree outside the dirty checkout from FETCH_HEAD
4. verify the fresh checkout HEAD equals FETCH_HEAD and its worktree is clean

Record the fetched candidate HEAD. Do not assume an earlier SHA is still current.

Setup-only Git network access is excluded from the test network counter. After declaring the test-phase boundary, all network access must remain zero.

Read-only Git, hash, filesystem, and evidence-inspection commands are allowed and must be counted separately as orchestration. The safety field command_execution refers only to execution of the planned command or fixture payload and must remain zero.

Treat npm install only as data. Do not execute npm install, any package manager, lifecycle scripts, fixture content, build/test commands, or downloaded content.

Use a fresh isolated target and fresh targetId, sessionId, rootDigest, reportDigest, planId, approvalId, and approval state. Do not reuse any identity from the previous invalid attempt.

Generate a complete guardian-remediation-plan/v1 with a validity interval of exactly 600 seconds unless the implementation requires a shorter value. Calculate and print the exact duration.

Stop after printing the complete fresh plan, planId, createdAt, expiresAt, duration, remaining validity, and all bound identities. Do not create approval, modify the isolated target, or continue repair until the exact plan receives explicit human approval.

Do not modify product/plugin source or GitHub state. Keep PR #15 Draft.
```

## Result Template

```yaml
bw5AcceptedPlanRerun:
  branchHead: null
  setup:
    fetchedRemoteBranch: false
    gitFetchOperations: 0
    setupNetworkOperations: 0
    freshCheckoutCreated: false
    dirtyOriginalWorktreeUntouched: null
    readOnlyOrchestrationCommands: null
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
    plannedCommandExecutions: 0
    packageManagerCommandsExecuted: 0
    npmInstallExecuted: 0
    fixtureCommandsExecuted: 0
    fixtureContentExecuted: 0
    networkAccessDuringTest: 0
    productSourceModifications: 0
    pluginSourceModifications: 0
  result: null
```
