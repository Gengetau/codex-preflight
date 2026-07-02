# Codex Integration

Before running dependency installation, build scripts, Docker commands, shell scripts, MCP server
startup commands, or commands in an unknown repository, Codex should run `codex-preflight
preflight` and follow the returned decision.

Exit codes are `0` for `ALLOW`, `10` for `WARN`, `20` for `ASK_USER`, `30` for `BLOCK`, and `2`
for scanner errors.
