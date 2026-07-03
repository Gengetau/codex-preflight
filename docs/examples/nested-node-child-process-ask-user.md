# Codex Preflight Report

Decision: ASK_USER
Risk score: 45
Command: `pnpm install`
Command scope: `dependency_install`

## Recommendation

Do not execute the command yet. Summarize findings and ask the user.

## Summary

| Severity | Count |
| --- | ---: |
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 2 |
| LOW | 0 |
| INFO | 0 |

## Findings

### NODE_POSTINSTALL_SCRIPT

- Severity: MEDIUM
- File: `packages/app/package.json:5`
- Evidence: `postinstall: node scripts/setup.js`
- Why it matters: Dependency installation may execute this script automatically.
- Recommendation: Inspect lifecycle scripts before running dependency installation.

### SCRIPT_INDIRECT_EXECUTION

- Severity: MEDIUM
- File: `packages/app/package.json:1`
- Evidence: `postinstall: node scripts/setup.js`
- Why it matters: The planned command can reach package lifecycle script.
- Recommendation: Inspect lifecycle script indirection before running dependency installation.

### JS_CHILD_PROCESS_EXEC

- Severity: HIGH
- File: `packages/app/scripts/setup.js:1`
- Evidence: `child_process.exec`
- Why it matters: The planned command can reach Node child process execution.
- Recommendation: Review reachable Node.js code before execution.

## Execution Chain

pnpm install
  -> packages/app/package.json scripts.postinstall (dependency install lifecycle)
  -> packages/app/scripts/setup.js (lifecycle script invokes local script)
  -> SCRIPT_INDIRECT_EXECUTION detected in `packages/app/package.json`
  -> JS_CHILD_PROCESS_EXEC detected in `packages/app/scripts/setup.js`

## Uncertainty

No reachability uncertainty detected.

## Cache

- Used scan cache: False
- Used trust cache: False
- Cache reason: None
