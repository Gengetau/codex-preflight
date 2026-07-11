# Rules

V1 statically inspects package lifecycle scripts, shell patterns, secrets, GitHub Actions, MCP
configs, agent instructions, Docker files, Makefiles, Rust/Cargo files, and Go module/source files.

Rule IDs are stable because Codex summaries and golden tests depend on them. High-risk examples
include `NODE_LIFECYCLE_REMOTE_EXEC`, `SHELL_CURL_PIPE_BASH`, `SECRET_OPENAI_KEY`,
`GHA_PULL_REQUEST_TARGET`, `MCP_SHELL_COMMAND`, `AGENT_SECRET_EXFILTRATION_REQUEST`, and
`DOCKER_PRIVILEGED_CONTAINER`.

Rust and Go ecosystem rule IDs are warning-oriented in v0.3.x:

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

Common Cargo registry mirrors, Cargo aliases, and Go module replacements can be legitimate. They
remain warnings because they alter dependency resolution or command meaning and should be visible
before build and test commands. Clean minimal Cargo and Go projects remain `ALLOW`; active and
commented single-line and block-form replacement forms have separate positive and negative
controls. Clean controls include representative minimal Rust and Go source files.
