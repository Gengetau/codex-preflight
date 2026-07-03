# Reports

Reports are available as JSON and Markdown and include a Codex-facing `agentInstruction` field.
Each report includes the decision, risk score, command, command scope, repository identity,
severity summary, findings, execution graph, and cache status.

JSON reports include `executionGraph` with `entryCommand`, `nodes`, `edges`, `capabilities`, and
`uncertainties`. Markdown reports include `## Execution Chain` and `## Uncertainty` sections so a
human can see how the planned command reaches local scripts or where static analysis became
uncertain.
