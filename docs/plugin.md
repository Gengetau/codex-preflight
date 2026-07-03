# Codex Plugin Packaging

Codex Preflight is packaged as a Codex-recognizable plugin while preserving the existing Python CLI.

## Shape

The plugin package files at the repository root are:

- `.codex-plugin/plugin.json`: plugin manifest.
- `skills/codex-preflight/SKILL.md`: Codex skill instructions.

The Codex marketplace wrapper files are:

- `.agents/plugins/marketplace.json`: marketplace root manifest.
- `.agents/plugins/plugins/codex-preflight/`: plugin package referenced by the marketplace entry.

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

To add this repository through the Codex UI "Add marketplace" flow, use:

- Source: `https://github.com/Gengetau/codex-preflight.git`
- Git ref: `master`
- Sparse path: `.agents/plugins`

Do not use sparse path `.codex-plugin` when adding a marketplace. `.codex-plugin/plugin.json` is
the plugin manifest. `.agents/plugins/marketplace.json` is the marketplace root manifest.

Do not use `git@github.com:Gengetau/codex-preflight.git` unless SSH host keys and credentials are
configured in the Codex runtime. If SSH fails with "Host key verification failed", use the HTTPS
source URL above.

If Codex reports that the marketplace root does not contain a supported manifest, the selected
sparse path is not a marketplace root. Use `.agents/plugins` for this repository.

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
