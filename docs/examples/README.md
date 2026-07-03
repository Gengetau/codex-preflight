# Demo Reports

These Markdown reports are generated from existing safe synthetic fixtures. They are static scans
only: Codex Preflight reads repository files and writes reports, but it does not execute package
installs, shell scripts, Docker, MCP servers, or fixture commands.

- [safe-node-allow.md](safe-node-allow.md): safe dependency install path with an `ALLOW` decision.
- [malicious-postinstall-block.md](malicious-postinstall-block.md): direct package lifecycle
  remote shell pattern with a `BLOCK` decision.
- [nested-node-child-process-ask-user.md](nested-node-child-process-ask-user.md): indirect
  package lifecycle execution chain reaching Node.js `child_process`, resulting in `ASK_USER`.
- [docker-compose-block.md](docker-compose-block.md): Docker compose reaching a Dockerfile remote
  shell pattern, resulting in `BLOCK`.
