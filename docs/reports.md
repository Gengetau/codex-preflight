# Reports

Reports are available as JSON and Markdown and include a Codex-facing `agentInstruction` field.
Each report includes the decision, risk score, command, command scope, repository identity,
severity summary, findings, policy explanation, execution graph, and cache status.

JSON reports include `executionGraph` with `entryCommand`, `nodes`, `edges`, `capabilities`, and
`uncertainties`. Markdown reports include `## Execution Chain` and `## Uncertainty` sections so a
human can see how the planned command reaches local scripts or where static analysis became
uncertain.

## Policy Explanation

The additive JSON `policyExplanation` object records:

- `finalDecision` and `commandScope`
- deterministic `selectedBy` metadata for a hard-block rule, policy-matrix minimum, risk score,
  command scope, safe-readonly adjustment, trust override, or no gate
- the bounded command risk-score contribution
- one stable, rule-ID-sorted contribution for every applicable finding rule
- the matched matrix minimum, hard-block flag, rationale, finding count, and rule risk score
- `affectedFinalGate` and `reportOnly` flags

Existing report fields retain their meaning. Markdown reports render the complete bounded selector
type, selector decision, selected rule, command risk score, command minimum, command gate effect,
and per-rule data in a `Policy Explanation` section.

## Local Comparison

Use `codex-preflight report compare BASELINE.json CANDIDATE.json` to compare two existing local
JSON reports. The command reads bounded files only and does not scan repositories, execute report
content, access the network, or follow links. UNC, URL, scp-like, and clone-like input and output
paths are rejected before filesystem access. JSON and Markdown output compare decisions, command
classifications, policy selectors, command contributions, findings, policy rule contributions,
execution capabilities, and uncertainties using stable identities and deterministic ordering.
