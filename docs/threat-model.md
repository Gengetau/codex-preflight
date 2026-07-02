# Threat Model

Codex Preflight protects Codex-style coding agents from executing risky repository-controlled
commands without first reading critical files and returning a command-aware decision.

It does not execute repository code, start MCP servers, run package managers, build Docker images,
or upload repository data. The main protected actions are dependency installation, script
execution, Docker startup, build/test commands, and MCP server startup commands.
