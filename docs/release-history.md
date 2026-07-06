# Release History

## v0.1.9

Reachability parser precision:

- Improved reachability parsing for shell `-c` command forms.
- Added support for Python and Node interpreter flags that previously hid reachable scripts.
- Added environment-wrapper handling for commands such as `env VAR=value bash script.sh`.
- Improved package-manager and task-runner wrapper handling with explicit uncertainty where local
  resolution is not possible.
- Added first-pass Windows command-form handling for PowerShell, `cmd /c`, and backslash paths.
- Added regression tests for interpreter flags, shell `-c`, environment wrappers,
  package-manager wrappers, Windows command forms, and mixed path separators.
- Preserved command self-risk behavior, CLI behavior, Codex plugin packaging, and marketplace
  packaging.

## v0.1.8

Command self-risk hardening:

- Added planned-command risk analysis so dangerous commands can produce findings even in empty
  repositories.
- Added command findings for remote shell pipelines, encoded PowerShell, dangerous Docker flags,
  sensitive Docker mounts, broad-access server startup patterns, and inline interpreter execution.
- Integrated command findings into policy evaluation and JSON/Markdown reports.
- Fixed `codex-preflight exec` command serialization so preflight scans a quoted representation of
  the argv that will be executed.
- Added regression tests for command self-risk and exec blocking behavior.
- Preserved CLI, Codex plugin, and marketplace packaging behavior.

## v0.1.7

Codex marketplace wrapper:

- Added a repository-local marketplace wrapper at `.agents/plugins/marketplace.json`.
- Added a marketplace-packaged plugin copy at `.agents/plugins/plugins/codex-preflight`.
- Documented Codex UI marketplace installation with HTTPS source and `.agents/plugins` sparse path.
- Documented the difference between plugin root manifests and marketplace root manifests.
- Added marketplace packaging tests.
- Bumped Python package, core package, and Codex plugin manifest versions to `0.1.7`.
- Kept MCP and App integration intentionally undeclared.

## v0.1.6

Codex plugin marketplace polish:

- Bumped the Python package, core package, and Codex plugin manifest versions to `0.1.6`.
- Added marketplace-ready plugin presentation metadata using real repository URLs.
- Kept MCP and App integration intentionally undeclared because this release does not implement
  those components.
- Updated plugin documentation to avoid stale release-specific wording.
- Added tests for marketplace presentation metadata.

## v0.1.5

Analysis budget hardening and reachability cleanup:

- Added a wide-fanout reachability budget regression case.
- Reported reachability node budget exhaustion as explicit `SCRIPT_NODE_BUDGET_EXCEEDED`
  uncertainty.
- Added report-size caps with explicit `REPORT_SIZE_BUDGET_EXCEEDED` summary uncertainty.
- Consolidated Node package script extraction through the reachability package helper.
- Removed the legacy path-based trust revoke API in favor of identity-based revocation.
- Added Windows Python 3.12 CI coverage.

## v0.1.4

Codex plugin packaging:

- Added `.codex-plugin/plugin.json`.
- Added the English `skills/codex-preflight/SKILL.md` Codex skill.
- Added plugin packaging tests.
- Preserved existing Python CLI behavior.
- Kept MCP and App integration intentionally undeclared because this release does not implement
  real MCP servers or Apps.

## v0.1.3.1

Reachability safety polish:

- Switched reachability file reads to bounded safe reads.
- Skipped `.codex-preflight-fixtures` directories during reachability traversal.
- Reported symlink, oversized, binary, outside-repository, and incomplete reachable targets as
  uncertainty instead of reading them directly.
- Added `npm test`, `npm start`, and `npm build` shorthand script resolution.

## v0.1.3

Indirect execution reachability:

- Added best-effort execution graph construction for reachable local scripts/files.
- Added `executionGraph` to JSON reports.
- Added Markdown execution chain and uncertainty sections.
- Added capability and uncertainty findings for reachable Node.js, Python, shell, and Docker paths.
- Added conservative policy handling for unknown or incomplete high-risk execution paths.

## v0.1.2.2

Composite command target collection fix:

- Reused shell segment splitting for command target collection.
- Collected target files from later composite command segments such as
  `git status && bash install.sh`.
- Preserved in-repository path and symlink safety checks.

## v0.1.2.1

Security bypass fixes:

- Collected nested monorepo critical files instead of only root-level matches.
- Classified composite commands by their riskiest segment.
- Hardened clone protocol handling and rejected unsafe clone URLs before `git clone`.
- Fixed trust revoke scope to match repository identity.
- Cached only `ALLOW` and `WARN` scan reports.

## v0.1.2

External and corpus scanning:

- Added external GitHub repository scanning via `--repo`.
- Added synthetic historical attack-pattern corpus.
- Added batch scan support for configured public repositories.
- Expanded documentation around external scan and corpus safety.

## v0.1.1

Dogfood and UX hardening:

- Added trust/cache management.
- Added temporary clone support.
- Added `exec` wrapper report UX improvements.
- Added CI and dogfooding workflows.

## v0.1.0

CLI scanner MVP:

- Added local CLI preflight command.
- Added command classification, critical file collection, static scanner rules, policy decisions,
  and JSON/Markdown report output.
