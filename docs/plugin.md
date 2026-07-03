# Codex Plugin Packaging

Codex Preflight is packaged as a Codex-recognizable plugin while preserving the existing Python CLI.

## Shape

The plugin packaging files are:

- `.codex-plugin/plugin.json`: plugin manifest.
- `skills/codex-preflight/SKILL.md`: Codex skill instructions.

The manifest declares the real skill directory through `skills: "./skills/"`. It does not declare
MCP servers or Apps because this repository does not implement those integrations.

## How Codex Should Use It

Codex should use the skill before risky commands such as dependency installation, shell scripts,
Docker commands, build/test/lint commands, MCP startup commands, or commands in unfamiliar
repositories.

The default preflight command is:

```bash
codex-preflight preflight --cwd . --command "<planned command>" --format markdown
```

Codex must not ignore `ASK_USER` or `BLOCK`. It also must not create trust approvals unless the
user explicitly asks for a scoped approval.

## Marketplace Notes

Local plugin installation and refresh behavior depends on the user's Codex plugin marketplace
setup. The official Plugin Creator workflow recommends using the plugin manifest, marketplace
entries when needed, cachebuster updates for local plugin iteration, reinstalling the plugin, and
starting a new Codex thread so the updated skill is loaded.

This repository does not declare fake MCP servers, Apps, screenshots, logos, privacy policy URLs, or
terms URLs. If a user wants local marketplace registration, use the official Plugin Creator workflow
for their selected marketplace.

## Limits

This plugin packaging adds skill-based discovery and usage guidance. It does not add a web
dashboard, SaaS backend, cloud upload, database server, browser extension, IDE extension, MCP
server, or App integration.
