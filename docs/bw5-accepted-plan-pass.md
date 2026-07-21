# BW5 Accepted-Plan Conformance PASS

This document records the validity-conformant BW5 accepted-plan rerun completed against candidate `9b414692667437ee1a5acbbb5bf72a2ea7a55262`.

## Result

```text
BW5 accepted-plan rerun: PASS
```

The rerun used a fresh clean detached checkout without modifying the user's existing dirty worktree. Setup-only Git network access was separated from the test phase. After the test-phase boundary, network access and all planned-command, package-manager, lifecycle, fixture, and downloaded-content execution remained zero.

## Plan validity

```text
createdAt: 2026-07-21T04:14:30Z
expiresAt: 2026-07-21T04:24:30Z
plan validity: 600 seconds / 10 minutes
contract maximum: 900 seconds / 15 minutes
validity conformance: PASS
```

The plan and approval were both unexpired immediately before consumption. The approval had 106 seconds remaining at the recorded pre-consumption check.

## Identity and evidence

```yaml
branchHead: 9b414692667437ee1a5acbbb5bf72a2ea7a55262
targetId: isolated-target:bw5:a89991911cc74ca48e3cef1f0abd3e14
sessionId: session:bw5:ec97e0399de148b7845bba8be09ca4c2
rootDigest: sha256:e139e059c7e9940dd29bd00297ab4d150a60f5f10bde830cd08f00874fcc5dd1
beforeReportDigest: sha256:d5bf4171a57f21082ecd594a062dd9b36b645bb13082f4e2cfe4c22102401765
afterReportDigest: sha256:b87713d01caa98c322beb3f25d3f2cd35e94503c57c8896b5a6e7b93c7e314f
commandDigest: sha256:fea6b934e37748291bdea99a3dbb76b3c889a7c00d06eced4516a6442abd954a
planId: guardian-plan-v1:sha256:a64d46d2735e617145643240c0b2d5c641892578dea01c2bd3d22713340dd038
approvalId: guardian-approval-v1:sha256:9bbf5f61a600db6fd1978b27332d6421e760f11bd440169f55707e174d501d25
```

All target, session, report, plan, approval, and consumption identities were fresh and were not reused from the invalid 55-minute attempt.

## Initial deterministic result

```yaml
decision: BLOCK
riskScore: 50
blockingRuleIds:
  - NODE_LIFECYCLE_REMOTE_EXEC
uncertainty: false
preimageDigest: sha256:110fac7a525db8cac1fc58c82fca1e92f757a50685b1c3ab3607f0ad07116c2c
```

The planned command string was `npm install`, treated only as data.

## Approval and repair

```yaml
approvalRecordsCreated: 1
approvalConsumptionCount: 1
approvalReplay: REJECTED
singleUse: true
approvedPaths:
  - package.json
actualChangedPaths:
  - package.json
beforeDigest: sha256:110fac7a525db8cac1fc58c82fca1e92f757a50685b1c3ab3607f0ad07116c2c
afterDigest: sha256:4cd0d820ca5a299448fb7d3784851118a11c76f2ac94a45d7b7bd6eeba6e89c4
approvedPostimageDigest: sha256:4cd0d820ca5a299448fb7d3784851118a11c76f2ac94a45d7b7bd6eeba6e89c4
postimageMatch: true
targetDrift: false
symlinks: 0
unexpectedFiles: 0
unexpectedChanges: 0
outsideTargetChanges: 0
```

Only `package.json` inside the isolated target changed, and the resulting content matched the complete approved postimage exactly.

## Final deterministic result

```yaml
decision: ALLOW
riskScore: 0
blockingRuleIds: []
removedRuleIds:
  - NODE_LIFECYCLE_REMOTE_EXEC
uncertainty: false
commandDigestUnchanged: true
```

## Setup and integrity

```yaml
setup:
  fetchedRemoteBranch: true
  gitFetchOperations: 1
  setupNetworkOperations: 1
  freshCheckoutCreated: true
  freshCheckoutClean: true
  dirtyOriginalWorktreeUntouched: true
  readOnlyOrchestrationCommands: 20
  worktreeCreateAttempts: 2
  worktreeCreateSuccessful: 1
integrity:
  isolatedTargetEntries:
    - package.json
  candidateCheckoutClean: true
  originalWorktreeStatusUnchanged: true
  productSourceUnchanged: true
  pluginStateUnchanged: true
  githubStateUnchanged: true
```

Setup-only Git network access is not test-phase network access.

## Safety counters

```yaml
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

## Conclusion

The fresh accepted-plan rerun satisfies the closed plan-validity contract and all BW5 pass criteria:

- fresh isolated identities;
- 600-second validity interval;
- unexpired plan and approval at consumption;
- one approval record and one successful consumption;
- replay rejection;
- `package.json`-only bounded repair;
- exact approved-postimage match;
- deterministic `BLOCK / 50` to `ALLOW / 0` transition using the unchanged command digest;
- zero planned-command, package-manager, fixture, test-network, unexpected-change, and outside-target counters.

This closes the BW5 accepted-plan conformance gap. PR #15 remains Draft; this evidence authorizes no merge, tag, release, auto-merge, or ready-for-review transition.
