# Build Week Video Script

This script is the public demo plan for **Codex Preflight Guardian — Hook, Explain, Approve, Repair, and Verify Before Execution**.

Target length: 4–5 minutes.

## Recording Safety

- Use only the checked-in synthetic fixture and an isolated temporary target.
- Treat `npm install` only as command data. Never execute it.
- Do not execute package managers, lifecycle scripts, fixture content, build commands, tests, Docker, or downloaded content.
- Do not show usernames, absolute home paths, server addresses, credentials, tokens, private repository data, or unrelated machine identifiers.
- Keep PR #15 Draft during recording.
- Do not claim Linux/Bash Hook enforcement. The verified product mode for the demonstrated Codex surfaces is `skill-only`, with `verified-isolated-repair` for repair.

## 0:00–0:20 — Title and Problem

On screen:

```text
Codex Preflight Guardian
Explain, Approve, Repair, and Verify Before Execution
```

Narration:

> AI coding agents often need to run dependency installation, build, test, Docker, or shell commands in repositories they have not fully reviewed. Codex Preflight Guardian checks the planned command and its reachable execution chain before execution, then keeps deterministic policy separate from model explanation.

## 0:20–0:50 — Product Identity

Show the Codex plugin and repository.

Narration:

> The product is a Codex plugin experience. It bundles a local deterministic scanner, MCP tools, Skill guidance, and platform runtimes. Normal plugin installation does not require a separate API key, cloud backend, user Python environment, or local web application.

Show:

```text
Hook -> Detect -> Explain -> Approve -> Repair -> Verify -> Final Decision
```

## 0:50–1:15 — Honest Protection Status

Show the observed capability classification:

```text
Protection mode: skill-only
Bash Hook status: NOT VERIFIED
Repair mode: verified-isolated-repair
```

Narration:

> Hook coverage is reported only after a live probe proves that the exact Codex build and tool surface reach the Hook. The tested Windows and Linux Codex sessions exposed `exec_command`, not the canonical `Bash` tool matched by the current Hook. The demo therefore makes no Linux or Windows Bash Hook-enforcement claim.

## 1:15–1:55 — Deterministic Detection

Prepare a fresh isolated temporary target containing only the safe synthetic `package.json` fixture.

Call `preflight_check` with the planned command string:

```text
npm install
```

Do not run the command.

Show the deterministic result:

```text
Decision: BLOCK
Risk score: 50
Blocking rule: NODE_LIFECYCLE_REMOTE_EXEC
Command executed: no
Fixture executed: no
Network access: no
```

Narration:

> The scanner reads bounded local evidence and detects a lifecycle path that could reach remote execution. The deterministic engine returns BLOCK. Repository content is treated as untrusted data.

## 1:55–2:20 — Advisory Explanation

Show the Codex explanation separated into two labeled sections:

```text
Deterministic Result
GPT Advisory Explanation
```

Narration:

> GPT-5.6 explains only the bounded evidence returned by the scanner. It cannot change the policy result, declare the repository safe, choose a plan ID, create approval, or authorize execution.

## 2:20–2:55 — Exact Plan and Approval

Show the complete closed remediation plan and highlight:

```text
schemaVersion: guardian-remediation-plan/v1
validity: 600 seconds
approved path: package.json
complete intended postimage: present
planId: guardian-plan-v1:sha256:...
```

Narration:

> The complete plan is canonicalized locally. Its stable plan ID binds the target, session, source evidence, command digest, preimage, exact postimage, prohibited operations, verification requirements, and expiry.

Show the separate approval record:

```text
schemaVersion: guardian-plan-approval/v1
singleUse: true
approval records created: 1
```

## 2:55–3:30 — Isolated Repair

Show that the repair occurs only in the isolated target.

Show:

```text
Approved paths: package.json
Actual changed paths: package.json
Postimage match: true
Target drift: false
Unexpected changes: 0
Outside-target changes: 0
```

Narration:

> Because pre-edit Hook enforcement was not verified on this Codex surface, the product uses verified isolated repair. The approval is consumed exactly once, the resulting content must match the complete approved postimage, and replay is rejected.

Show:

```text
Approval consumption count: 1
Approval replay: REJECTED
```

## 3:30–4:00 — Deterministic Verification

Rescan the same target using the exact same `npm install` command string as data and the same command digest.

Show:

```text
Decision: ALLOW
Risk score: 0
Blocking rules: none
Removed rule: NODE_LIFECYCLE_REMOTE_EXEC
Command digest unchanged: yes
Uncertainty: false
```

Narration:

> The same planned command is rescanned after the isolated repair. The deterministic result changes from BLOCK 50 to ALLOW 0, and the original blocking rule disappears. No command is executed automatically after verification.

## 4:00–4:25 — Safety Evidence

Show the final counters:

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

Narration:

> The demo proves the review, approval, isolated repair, replay rejection, and deterministic verification path without executing the planned command or fixture content.

## 4:25–4:45 — Final Claim

Show:

```text
BW5 Plugin Experience: COMPLETE
BW6 Submission Candidate: ACTIVE
Linux/Bash Hook-active certification: NOT VERIFIED / DEFERRED
```

Narration:

> Codex Preflight Guardian provides deterministic pre-execution analysis, bounded explanation, exact human approval, verified isolated repair, and same-command verification. Hook enforcement is claimed only for tool surfaces that pass an exact live probe; no unsupported Hook claim is made here.

End with the public repository and submission links.

## Recording Checklist

- [ ] Repository and plugin name are visible.
- [ ] Exact Codex surface and protection mode are shown.
- [ ] `npm install` is visibly treated as data only.
- [ ] Initial `BLOCK / 50` result is shown.
- [ ] Deterministic and advisory sections are visibly separated.
- [ ] Complete plan, 600-second validity, and `planId` are shown.
- [ ] Separate single-use approval is shown.
- [ ] Only isolated `package.json` changes.
- [ ] Replay rejection is shown.
- [ ] Final `ALLOW / 0` and unchanged command digest are shown.
- [ ] All execution and test-network counters are zero.
- [ ] Linux/Bash Hook limitation is disclosed.
- [ ] No sensitive paths, credentials, server details, or private data appear.
