# Rules

V1 statically inspects package lifecycle scripts, shell patterns, secrets, GitHub Actions, MCP
configs, agent instructions, Docker files, Makefiles, Rust/Cargo files, and Go module/source files.

Rule IDs are stable because Codex summaries and golden tests depend on them. High-risk examples
include `NODE_LIFECYCLE_REMOTE_EXEC`, `SHELL_CURL_PIPE_BASH`, `SECRET_OPENAI_KEY`,
`GHA_PULL_REQUEST_TARGET`, `MCP_SHELL_COMMAND`, `AGENT_SECRET_EXFILTRATION_REQUEST`, and
`DOCKER_PRIVILEGED_CONTAINER`.

Rust and Go ecosystem rule IDs are warning-oriented in v0.3.0:

- `RUST_BUILD_SCRIPT`
- `RUST_CARGO_SOURCE_REPLACEMENT`
- `RUST_CARGO_ALIAS`
- `RUST_CARGO_GIT_SOURCE`
- `GO_GENERATE_DIRECTIVE`
- `GO_TESTMAIN`
- `GO_CGO_USAGE`
- `GO_MODULE_REPLACE`
- `GO_LOCAL_MODULE_REPLACE`

These rules are static only. They identify Cargo and Go files that can influence build, test, or
generation workflows, but the scanner does not run Cargo, Go, build scripts, generators, tests,
compilers, package managers, or repository code.
