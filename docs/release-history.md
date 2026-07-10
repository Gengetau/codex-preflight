# Release History

## v0.2.4

MCP integration documentation and client examples:

- Added accurate PyPI and source-checkout installation, stdio startup, tool schema, compatibility,
  safety-boundary, and troubleshooting documentation.
- Added generic executable/argument-array client configuration without client-certification claims.
- Added runnable Python stdio examples for `preflight_check` and `corpus_scan`.
- Made Git identity metadata lookup non-interactive and bounded so stdio scans cannot inherit the
  protocol input stream or wait indefinitely for Git metadata.
- Added machine-checked request, successful response, and structured local-path error JSON examples.
- Added documentation tests that keep tool names, input schemas, response contracts, internal links,
  marketplace packaging, and version references synchronized.

## v0.2.3

MCP local-path UX and structured errors:

- Added stable MCP error codes with concise messages, remediation, retryability, input-field, and
  safety-boundary metadata.
- Distinguished missing, empty, URL-like, regular-file, nonexistent, permission-denied, and
  invalid `cwd` failures without exposing raw tracebacks.
- Added local path normalization, home and relative-path expansion, explicit symlink behavior, and
  Windows drive/UNC classification that avoids URL misclassification.
- Preserved the v0.2.2 successful-response contract and the exact two-tool MCP runtime surface.

## v0.2.2

MCP report schema and evidence-boundary stabilization:

- Added a versioned MCP response contract while preserving the existing CLI JSON report fields.
- Added explicit tool identity and static-analysis safety metadata to MCP results.
- Added stable untrusted, treat-as-data metadata to execution-graph uncertainty items.
- Documented and regression-tested report limits, cache behavior, provenance, and the unchanged
  `preflight_check` and `corpus_scan` tool set.

## v0.2.1

MCP runtime and package stabilization:

- Improved MCP runtime error messages for missing optional MCP dependencies, unsupported
  `preflight_check` arguments, and non-JSON MCP output requests.
- Documented source-checkout and installed-package MCP extra installation paths.
- Preserved the MCP tool set as exactly `preflight_check` and `corpus_scan`.
- Preserved local-path-only, read-only MCP behavior with no command execution, trust mutation, or
  remote repository scanning tools.

## v0.2.0

README link-poisoning detection:

- Added static README/documentation rules for fake release links, non-release installer/download
  hosts, raw source archive downloads, and security-warning bypass wording.
- Added `README_FAKE_RELEASE_LINK`, `README_INSTALLER_FROM_NON_RELEASE_HOST`,
  `README_RAW_SOURCE_ARCHIVE_DOWNLOAD`, and `README_DEFEAT_SECURITY_WARNING`.
- Added policy matrix coverage so safe read-only commands warn while install, build, and
  script-execution scopes require user review.
- Added real-world-inspired corpus cases for fake release links and security-warning bypass text.
- Kept detection static-only: no linked-page fetching, artifact download, browser automation,
  recursive linked-repository scanning, GitHub metadata scoring, or MCP tool expansion.
- Preserved evidence trust-boundary labels as repository-controlled untrusted data.

## v0.1.13

0.1.x stabilization and release hygiene:

- Added a `0.1.x` stabilization summary covering completed areas, stable interfaces,
  intentional non-inclusions, and known limitations.
- Added a release process document with version sync, validation, annotated tag, and GitHub
  Release guidance.
- Added a reusable release notes template for future releases.
- Added release hygiene tests for documentation presence, version alignment, and tag/release
  guidance.
- Preserved CLI behavior, command self-risk behavior, reachability behavior, policy matrix
  behavior, evidence trust-boundary metadata, cache locking, MCP read-only boundaries, Codex
  plugin packaging, marketplace packaging, and marketplace sync automation.

## v0.1.12.1

MCP runtime smoke coverage:

- Added optional MCP runtime smoke tests for `create_mcp_server()`.
- Added CI coverage that installs `.[dev,mcp]` and verifies `codex-preflight-mcp --list-tools`.
- Preserved the first MCP tool set as read-only and local-path-only.
- Preserved remote repository scanning and trust mutation as intentionally not exposed through MCP.
- Preserved CLI behavior, Node module reachability, evidence trust-boundary metadata, cache locking,
  policy matrix behavior, Codex plugin packaging, marketplace packaging, and marketplace sync
  automation.

## v0.1.12

Pre-MCP hardening bundle:

- Added cross-file Node.js module reachability for local `require()` and `import` chains.
- Added uncertainty for dynamic or unresolved module references.
- Hardened Node.js child-process detection for direct chained `require("child_process").exec(...)`
  patterns.
- Added evidence trust-boundary metadata so repository-controlled evidence is labeled as
  untrusted data.
- Added MCP-facing documentation that evidence snippets must never be treated as instructions.
- Added file locking for local scan and trust caches, with atomic replace where supported and a
  locked Windows fallback.
- Added a minimal read-only MCP-facing package with local-path-only `preflight_check` and bundled
  `corpus_scan` tools.
- Kept remote repository scanning and trust mutation out of the first MCP tool set.
- Preserved CLI behavior, command self-risk behavior, reachability parser behavior, policy matrix
  behavior, Codex plugin packaging, marketplace packaging, and marketplace sync automation.

## v0.1.11

Marketplace copy sync automation:

- Added `scripts/sync_marketplace_plugin.py` to generate the marketplace plugin copy from the
  root plugin package.
- Added `--check` mode so stale marketplace plugin copies fail validation.
- Added tests for marketplace sync behavior and stale-copy detection.
- Added CI coverage for marketplace plugin copy freshness.
- Preserved the Codex marketplace root at `.agents/plugins` and the plugin source path
  `./plugins/codex-preflight`.
- Preserved CLI behavior, command self-risk behavior, reachability parser behavior, policy matrix
  behavior, Codex plugin packaging, and marketplace packaging.

## v0.1.10

Policy matrix and decision calibration:

- Added an explicit policy matrix mapping known rule IDs and command scopes to minimum decisions.
- Migrated hard-block and user-review policy behavior into tested matrix entries.
- Added policy coverage tests for known scanner, command-risk, reachability capability, uncertainty,
  and report-only rule IDs.
- Made hard-block behavior, safe-readonly downgrade behavior, and `CRITICAL` severity behavior
  explicit through tests.
- Preserved command self-risk behavior, reachability parser behavior, CLI behavior, Codex plugin
  packaging, and marketplace packaging.

## v0.1.9.1

Reachability parser edge-case cleanup:

- Treated Windows drive-letter absolute paths as outside-repository targets instead of
  repository-relative missing files.
- Continued Python script target parsing after `-X` and `-W` value flags.
- Preserved `python -c` inline-code behavior as a terminating parser form.
- Added regression tests for Windows drive-letter paths and Python value flags.
- Preserved command self-risk behavior, CLI behavior, Codex plugin packaging, and marketplace
  packaging.

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
