# Comparison

Codex Preflight is a repository pre-execution guardrail, not an enterprise agent inventory
scanner or a general-purpose antivirus tool.

## Local Report Comparison

```bash
codex-preflight report compare BASELINE.json CANDIDATE.json --format json
codex-preflight report compare BASELINE.json CANDIDATE.json --format markdown
```

The command accepts two existing local `schemaVersion: "1.0"` JSON reports, each capped at 2 MiB.
It compares the final decision, command classification, finding identities, policy contributions,
execution capabilities, and uncertainties. Added, removed, changed, and unchanged items are sorted
deterministically. Cache metadata and repository paths are explicitly ignored as volatile.

The comparator never scans a repository, executes commands, fetches URLs, follows links, or loads
remote content. Report strings and evidence remain untrusted data. Malformed, oversized,
unsupported, missing, or incompatible inputs return a structured JSON error and exit code 2.
