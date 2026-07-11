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

The corpus includes Rust and Go ecosystem fixtures for v0.3.0:

- `rust-build-script-source-replacement`
- `go-generation-testmain-cgo`

The scanner compares the actual decision and rule IDs with the expected values. The command exits
nonzero if any expectation fails.

Safety rules:

- Corpus scans only read files.
- Tests must not run package installs, setup scripts, Docker, shell scripts, MCP servers, or GitHub
  workflows from the fixtures.
- Tests must not run Cargo, Go, build scripts, generators, compilers, package managers, or test
  hooks from the fixtures.
- URLs use inert documentation domains such as `example.invalid`.
- Secret fixtures use non-working markers and must not contain real credentials.
