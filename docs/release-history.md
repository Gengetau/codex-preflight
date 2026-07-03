# Release History

## v1.3.1

Reachability safety polish:

- Switched reachability file reads to bounded safe reads.
- Skipped `.codex-preflight-fixtures` directories during reachability traversal.
- Reported symlink, oversized, binary, outside-repository, and incomplete reachable targets as
  uncertainty instead of reading them directly.
- Added `npm test`, `npm start`, and `npm build` shorthand script resolution.

## v1.3

Indirect execution reachability:

- Added best-effort execution graph construction for reachable local scripts/files.
- Added `executionGraph` to JSON reports.
- Added Markdown execution chain and uncertainty sections.
- Added capability and uncertainty findings for reachable Node.js, Python, shell, and Docker paths.
- Added conservative policy handling for unknown or incomplete high-risk execution paths.

## v1.2.2

Composite command target collection fix:

- Reused shell segment splitting for command target collection.
- Collected target files from later composite command segments such as
  `git status && bash install.sh`.
- Preserved in-repository path and symlink safety checks.

## v1.2.1

Security bypass fixes:

- Collected nested monorepo critical files instead of only root-level matches.
- Classified composite commands by their riskiest segment.
- Hardened clone protocol handling and rejected unsafe clone URLs before `git clone`.
- Fixed trust revoke scope to match repository identity.
- Cached only `ALLOW` and `WARN` scan reports.

## v1.2

External and corpus scanning:

- Added external GitHub repository scanning via `--repo`.
- Added synthetic historical attack-pattern corpus.
- Added batch scan support for configured public repositories.
- Expanded documentation around external scan and corpus safety.

## v1.1

Dogfood and UX hardening:

- Added trust/cache management.
- Added temporary clone support.
- Added `exec` wrapper report UX improvements.
- Added CI and dogfooding workflows.

## v1.0

CLI scanner MVP:

- Added local CLI preflight command.
- Added command classification, critical file collection, static scanner rules, policy decisions,
  and JSON/Markdown report output.
