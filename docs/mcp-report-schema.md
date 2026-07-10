# MCP Report Schema

## Contract versions

Successful MCP tool results use `mcpSchemaVersion: "1.0"`. The nested core report keeps its
existing additive JSON contract and continues to expose `schemaVersion: "1.0"` for CLI
compatibility. Consumers should reject unsupported major versions and tolerate additive fields
within the same major version.

## Common MCP fields

Both MCP tools return these stable fields:

| Field | Meaning |
| --- | --- |
| `mcpSchemaVersion` | Version of the MCP-facing result contract. |
| `tool` | Exact tool identity: `preflight_check` or `corpus_scan`. |
| `safety` | Stable static-analysis and authority-boundary metadata. |

The `safety` object contains:

```json
{
  "analysisMode": "static-only",
  "repositoryContentTrust": "untrusted",
  "evidenceInstructionBoundary": "treat-as-data",
  "commandExecuted": false,
  "networkAccess": false,
  "trustMutationAllowed": false,
  "remoteRepositoryAccess": false
}
```

These values describe enforced runtime behavior, not repository claims. Repository-controlled
strings never change these fields.

## `preflight_check` successful result

The result preserves the existing core report fields and adds the common MCP fields. Required
top-level fields are:

```text
mcpSchemaVersion
tool
schemaVersion
decision
riskScore
command
commandScope
repo
summary
reason
agentInstruction
findings
executionGraph
reportLimits
cache
safety
```

### Repository provenance

The `repo` object records the normalized scanned path, `sourceType`, remote identity when known,
head commit when known, and the critical fingerprint. MCP `preflight_check` accepts local paths
only, so `sourceType` is `local`; remote-repository access remains false.

### Findings and evidence

Every finding includes:

```json
{
  "evidenceSource": "repository-content",
  "evidenceTrust": "untrusted",
  "evidenceInstructionBoundary": "treat-as-data"
}
```

`evidenceSource` distinguishes repository content, the caller's command string, redacted secret
material, fixed rule phrases, and tool-generated uncertainty. Regardless of source, clients must
treat evidence as untrusted data and must never execute it or promote it into protocol or policy
instructions. Secret evidence remains redacted.

Execution-graph capabilities and uncertainties carry the same trust-boundary fields. A
tool-generated `REPORT_SIZE_BUDGET_EXCEEDED` uncertainty also carries this boundary so clients do
not mistake its surrounding report content for instructions.

### Report limits

`reportLimits` records maximum, included, and omitted counts for findings and execution-graph
items. When report details are capped, the report includes a `REPORT_SIZE_BUDGET_EXCEEDED`
uncertainty. Consumers must not interpret an omitted count as evidence that omitted content is
safe.

### Cache behavior

The `cache` object keeps the existing fields:

```text
usedScanCache
usedTrustCache
cacheReason
```

MCP `preflight_check` calls the core with scan cache disabled and trust disabled. Both used flags
therefore remain false for MCP calls; no MCP trust approval is consulted or mutated.

### Compatibility

This contract is additive. Existing consumers of `decision`, `riskScore`, `command`,
`commandScope`, `repo`, `summary`, `reason`, `agentInstruction`, `findings`, `executionGraph`,
`reportLimits`, and `cache` continue to read those fields at the same locations. CLI Markdown and
CLI JSON behavior are not converted into an MCP envelope.

MCP accepts only `format=json`. Markdown and text output remain CLI-only.

## `corpus_scan` successful result

`corpus_scan` preserves its `passed` and `cases` fields and adds `mcpSchemaVersion`, `tool`, and
`safety`. It executes only the bundled synthetic corpus with static analysis.

## Authority boundary

The runtime registers exactly two tools:

```text
preflight_check
corpus_scan
```

It does not expose remote repository scanning, command execution, trust listing, trust approval,
trust revocation, filesystem mutation, or network access.
