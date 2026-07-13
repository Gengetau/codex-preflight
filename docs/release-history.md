# Release History

## v0.3.7

Deterministic release automation and supported-integration diagnostics:

- Added `codex-preflight release verify` with stable `release-readiness/v1` JSON and human-readable
  Markdown output. The command is non-mutating and suitable for local use and protected CI.
- Added exact checks for five version sources, three root/marketplace plugin-copy files, and all
  eight supported static and runtime MCP authority inventories without adding an MCP tool or
  runtime authority.
- Added supported Python, Git, and optional MCP integration diagnostics. Optional dependencies are
  never installed automatically; missing MCP support reports the exact supported install command.
- Added explicit, bounded, read-only helpers for local tag targets, published GitHub Release
  targets, and merged-branch cleanup. Repository and remote evidence remains untrusted data.
- Added clean, drift, stale-state, missing-integration, read-only failure, and Windows/Linux
  path/process regression coverage while preserving existing CLI, plugin, report, and MCP
  authority boundaries.

## v0.3.6

Warning-oriented Java and Kotlin ecosystem coverage:

- Added static findings for Maven plugin executions, Gradle plugin repositories, init scripts,
  `buildSrc` and included build logic, and insecure or unpinned wrapper distributions.
- Added deterministic reachability and build/test classification for `mvn`/`mvnw` and
  `gradle`/`gradlew` command forms without adding runtime authority.
- Included nonstandard files selected by Maven `-f`/`--file` and Gradle `-I`/`--init-script`, while
  limiting wrapper and init-script reachability to the command forms that actually load them.
- Added active and clean Java/Kotlin corpus cases with representative Maven, Gradle, Java, and
  Kotlin surfaces plus comment/string, malformed-POM, and pinned-wrapper negative controls.
- Preserved CLI/MCP schemas and all eight optional-authority inventories. Static analysis does not run Maven, Gradle, wrappers,
  plugins, Java/Kotlin compilers, tests, package managers, or repository code and performs no
  ecosystem-related network access.

## v0.3.5

Warning-oriented Ruby ecosystem coverage:

- Added static findings for Bundler git and local path sources, gemspec native extensions,
  RubyGems install/uninstall hooks, `extconf.rb`, and command-running Rake tasks.
- Added deterministic reachability for `bundle install`, `bundle exec rake`, and direct Rake test
  and build forms without adding an MCP tool or changing optional authority flags.
- Added active and clean Ruby corpus cases plus commented-indicator negative controls.
- Preserved CLI/MCP schemas and the existing remote scan, trust-read, and trust-mutation authority
  boundaries. The scanner does not run Ruby, Bundler, Rake, extconf, compilers, hooks, tests,
  package managers, or repository code.

## v0.3.4

Confirmation-gated default-off MCP trust mutation:

- Added `trust_approve` and `trust_revoke` only for exact
  `CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION=1`, preserving all eight independently scoped optional
  authority inventories and keeping the bundled plugin flags absent.
- Added process-local, operation-bound, single-use 300-second confirmation challenges with a
  mandatory human stop and one confirmed retry. Stdio identity remains unavailable and is not an
  authenticated actor claim.
- Added exact local approval/revoke scope, source-specific v2 provenance, CLI list provenance/audit
  display, and compatibility with existing CLI trust matching and revocation.
- Added separate redacted owner-only HMAC-chained mutation audit, write-ahead persistence, startup
  audit recovery, and explicit `MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING` handling. A committed
  pending response is terminal and must not be retried.
- Preserved MCP preflight trust blindness and remote-confirmation authority separation: MCP
  preflight does not consume trust, and remote confirmation cannot create, satisfy, read, or mutate
  trust.
- Added exact request/challenge/retry/result examples, default-off plugin copy validation, focused
  CLI compatibility checks, and synchronized all release versions to `0.3.4`.

## v0.3.3

Default-off bounded MCP trust reads:

- Added `trust_list` only when the process starts with exact
  `CODEX_PREFLIGHT_ENABLE_TRUST_READ=1`; default, remote-only, trust-read-only, and combined tool
  inventories remain independently gated.
- Added exact repository-identity and command-scope filters, a 1-100 result cap, deterministic
  sorting, process-local HMAC privacy hashes, and reusable 300-second cursors bound to filters,
  limit, and the current trust snapshot.
- Added a locked metadata-only migration to stored UUIDv4 entry IDs, entry version `1`, and
  provenance while preserving all approval values, counts, expiry, and matching semantics.
- Added a 1 MiB trust-store cap, at most three permission-preserving migration backups, pre-replace
  size checks, full entry validation, atomic replacement, and fail-closed corruption/schema/lock
  handling shared with existing CLI approve and revoke behavior.
- Added a dedicated bounded `trust-read/audit.jsonl` namespace with redacted HMAC identities,
  fixed stdio runtime identity, locked/fsynced append, rotation, and fail-closed audit behavior.
- Preserved MCP `preflight_check` as trust-blind and remote confirmation as unable to read, create,
  satisfy, or mutate trust. No MCP trust approval or revocation tool is registered.
- Added local deterministic coverage for registration, schema, migration invariants, storage
  validation, concurrency, redaction, pagination, cursor drift/restart/expiry, audit, stable errors,
  docs, plugin metadata, and all four startup inventories.

## v0.3.2

Default-off public GitHub HTTPS remote MCP scan:

- Added `remote_repository_scan` only when the process starts with exact
  `CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1`; the default inventory remains exactly
  `preflight_check` and `corpus_scan`.
- Added a process-local HMAC confirmation challenge bound to canonical URL, explicit ref, host
  policy, every fixed resource limit, random challenge identity, process key, and 300-second
  expiry, with atomic one-time consumption before network access.
- Enforced public GitHub HTTPS-only URL/ref policy, public DNS classification, validated-address
  pinning, zero redirects, stripped credentials/proxies, and hardened shell-free Git settings.
- Added shallow bare acquisition with no checkout, regular-blob-only materialization, path/mode
  collision defenses, symlink/submodule/LFS skipping, fixed time/disk/byte/file/depth/concurrency
  limits, isolated static scanning, process-tree cancellation, and verified cleanup.
- Added a dedicated immutable-commit/policy-keyed, process-HMAC-protected remote cache plus bounded
  redacted audit JSONL, both partitioned from local scan and trust state and fail-closed on error.
- Preserved MCP schema `1.0`, report caps, policy explanation, and untrusted treat-as-data evidence;
  successful remote results add bounded provenance and never create or consult trust.
- Added synthetic and local-subprocess coverage for registration, confirmation, SSRF/address
  policy, Git isolation, DNS pinning, limits, unsafe trees, cancellation, cleanup, cache, audit,
  deterministic errors, evidence boundaries, and default-off rollback without live CI network use.

## v0.3.1

Coverage calibration and report explainability:

- Added deterministic, additive policy explanations to JSON and Markdown reports.
- Added local-only `codex-preflight report compare` JSON/Markdown comparison with bounded input,
  strict local-path rejection, stable identities, complete policy contribution comparison,
  volatile metadata normalization, and structured errors.
- Grouped corpus output by category and exposed expected/actual rules plus negative-control labels.
- Added representative clean Rust and Go corpus fixtures plus commented single-line and block-form
  replacement controls while preserving warning-oriented Cargo and Go policy.
- Preserved existing CLI and MCP request shapes and kept the MCP runtime exactly
  `preflight_check` and `corpus_scan`.
- Added no network, remote-scan, trust, command-execution, browser, or artifact-download authority.

## v0.3.0

Rust and Go ecosystem coverage foundation:

- Added warning-oriented static Rust/Cargo findings for `build.rs`, package build scripts, Cargo
  source replacement, Cargo aliases, and git-sourced `Cargo.lock` entries.
- Added warning-oriented static Go findings for `//go:generate`, `TestMain`, cgo imports, Go module
  replacement, and local module redirection.
- Connected `cargo build`, `cargo test`, `go build`, `go test`, and `go generate` commands to
  Rust/Go metadata and source files in the execution graph.
- Added deterministic Rust and Go corpus fixtures with clean static-only safety notes.
- Preserved existing CLI and MCP request shapes and kept the MCP runtime tool set exactly
  `preflight_check` and `corpus_scan`.
- Kept the release local and static: no Cargo or Go execution, no package-manager execution, no
  remote repository scanning, no trust tools, no cache mutation through MCP, no browser automation,
  and no artifact download.

## v0.2.9

Instruction-capable MCP runtime hotfix:

- Raised the optional MCP SDK floor to `mcp>=1.3.0`, the lowest verified release that explicitly
  accepts and preserves FastMCP server instructions.
- Added capability-based, fail-closed startup validation so legacy, manually downgraded, shadowed,
  or instruction-dropping runtimes cannot start a partially compliant stdio server.
- Added actionable, traceback-free compatibility remediation:
  `python -m pip install --upgrade "codex-preflight[mcp]"`.
- Extended non-mutating doctor diagnostics to distinguish missing, present but
  instruction-incompatible, and instruction-capable MCP runtimes without starting the server.
- Preserved optional-runtime-free static tool listing and the exact runtime authority:
  `preflight_check` and `corpus_scan`.
- Corrected the v0.2.8 safety-contract defect without adding scanner rules or capabilities.

## v0.2.8

First-class Codex MCP integration without scanner authority expansion:

- Added plugin-root `.mcp.json` configuration and declared it from both root and marketplace plugin
  manifests.
- Extended marketplace synchronization to prevent bundled MCP configuration drift.
- Added fixed server-wide safety instructions whose first 512 characters preserve the static-only,
  untrusted-evidence, no-execution, stop-on-`ASK_USER`/`BLOCK`, no-remote, and no-trust-mutation
  boundaries.
- Added non-mutating `codex-preflight mcp config --client codex` and
  `codex-preflight mcp doctor --client codex` onboarding diagnostics.
- Documented plugin, standalone Codex MCP, and source-checkout flows with an explicit
  `codex-preflight[mcp]` Python prerequisite.
- Preserved the exact runtime tool set: `preflight_check` and `corpus_scan`.

## v0.2.7

Open-source licensing and release metadata:

- Added the Apache License 2.0 and project attribution notice.
- Declared Apache-2.0 licensing in Python package metadata and README documentation.
- Synchronized Python package, MCP package, root plugin, and marketplace plugin versions.
- Preserved scanner behavior, MCP runtime authority, trust behavior, and remote-repository boundaries.

## v0.2.6

MCP trust-management design only:

- Added implementation-ready future contracts for read-only `trust_list` and confirmation-gated
  `trust_approve` and `trust_revoke` operations.
- Defined separate scan-read, trust-read, and trust-mutate authority, exact-operation one-time
  confirmation, audit, storage migration, atomicity, locking, permissions, recovery, CLI
  compatibility, threat mitigations, and rollback controls.
- Added design/boundary tests proving MCP scans remain trust-blind and remote scan confirmation
  cannot create trust.
- Did not implement or register trust tools; the runtime tool set remains exactly
  `preflight_check` and `corpus_scan`.

## v0.2.5

Remote-repository MCP design only:

- Added an implementation-ready design for a future separate, confirmation-gated
  `remote_repository_scan` tool.
- Defined HTTPS/host/SSRF/redirect policy, bounded isolated clone controls, cleanup, provenance,
  cache separation, prompt-injection boundaries, threat mitigations, and rollout/rollback gates.
- Added tests proving the design's required sections while keeping remote URLs rejected by local
  `preflight_check`.
- Did not implement or register remote scanning; the runtime tool set remains exactly
  `preflight_check` and `corpus_scan`.

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
