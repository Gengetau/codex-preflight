# Case Corpus

`case_corpus/` contains safe, synthetic fixtures inspired by historical repository attack
patterns. The corpus is meant to test static detection behavior without including malware, live
payloads, working secrets, or commands that should be executed.

Each case includes a `case.yml` file with:

- `id`
- `title`
- `category`
- `command`
- `expectedDecision`
- `expectedRules`
- `description`
- `safetyNote`

Run the full corpus:

```bash
codex-preflight corpus scan
codex-preflight corpus scan --format json
```

Run one case:

```bash
codex-preflight corpus scan --case npm-postinstall-remote-exec
```

The corpus includes Rust and Go ecosystem calibration fixtures:

- `rust-clean-minimal`
- `rust-build-script-source-replacement`
- `go-clean-minimal`
- `go-commented-replace-block`
- `go-commented-replace-single-line`
- `go-generation-testmain-cgo`
- `go-replace-block`
- `ruby-bundler-rake-native`
- `ruby-clean-minimal`

The clean Rust fixture includes a minimal Cargo library target, and the clean Go fixture includes a
minimal ordinary Go source file. Commented single-line and block-form replacements have separate
public negative controls.

The Ruby positive fixture covers Bundler git/local sources, a command-running Rake task, gemspec
extension and lifecycle declarations, and `extconf.rb`. The clean Ruby fixture contains ordinary
Bundler metadata, a non-command-running Rake task, a gemspec, and representative library source.
Corpus scans never run Ruby, Bundler, Rake, lifecycle hooks, extconf, compilers, or package tasks.

The scanner compares the actual decision and rule IDs with the expected values. JSON retains the
top-level `cases` array and adds deterministic `groups` by category. Markdown shows category,
expected and actual decisions, expected and actual rule IDs, and whether a case is a negative
control. The command exits nonzero if any expectation fails.

Safety rules:

- Corpus scans only read files.
- Tests must not run package installs, setup scripts, Docker, shell scripts, MCP servers, or GitHub
  workflows from the fixtures.
- Tests must not run Cargo, Go, Ruby, Bundler, Rake, build scripts, generators, extconf, compilers,
  package managers, lifecycle hooks, or test hooks from the fixtures.
- URLs use inert documentation domains such as `example.invalid`.
- Secret fixtures use non-working markers and must not contain real credentials.
