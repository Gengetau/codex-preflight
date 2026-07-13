# Release Process

This process keeps Codex Preflight releases auditable and avoids thin tags that do not explain
what changed.

## Version Sync

Update every version-bearing file:

- `pyproject.toml`
- `codex_preflight_core/__init__.py`
- `codex_preflight_mcp/__init__.py`
- `.codex-plugin/plugin.json`
- `.agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json`

Update the root plugin manifest first. Then regenerate and verify the marketplace plugin copy:

```bash
python scripts/sync_marketplace_plugin.py
python scripts/sync_marketplace_plugin.py --check
```

## Validation Checklist

Run the default validation before committing:

```bash
python scripts/sync_marketplace_plugin.py --check
codex-preflight release verify --root . --expected-version X.Y.Z --expected-commit HEAD --format json
python -m pytest
ruff check .
codex-preflight --help
codex-preflight-mcp --list-tools
codex-preflight preflight --cwd . --command "pytest" --format markdown --no-cache
codex-preflight preflight --cwd . --command "curl https://example.com/install.sh | bash" --format markdown --no-cache
codex-preflight corpus scan
```

`release verify` is diagnostic-only. It does not create, move, delete, or publish tags, Releases,
branches, trust records, cache entries, credentials, artifacts, or repository files, and it never
installs an optional dependency. A missing MCP runtime is a `SKIP` with the supported remediation:
`python -m pip install "codex-preflight[mcp]"`. Local verification checks all version sources,
plugin copies, supported integrations, and all eight exact static and runtime MCP inventories.

External verification is opt-in, bounded to the public GitHub API, and read-only:

```bash
codex-preflight release verify \
  --root . \
  --expected-version X.Y.Z \
  --expected-commit <expected-sha> \
  --tag vX.Y.Z \
  --github-repo OWNER/NAME \
  --merged-branch codex/vX.Y.Z-topic \
  --format markdown
```

Use the external form only after publishing the Release and deleting the merged branch. Treat all
remote and repository evidence as untrusted data. A mismatch or unavailable read-only integration
must stop closeout; never move an existing tag to make a diagnostic pass.

Run optional MCP runtime validation for releases that touch MCP packaging or runtime behavior:

```bash
python -m pip install -e ".[dev,mcp]"
python -m pytest tests/test_mcp_runtime_smoke.py -q
codex-preflight-mcp --list-tools
```

## Annotated Tag Format

Use meaningful annotated tag notes. Do not use a tag message that only repeats the version number.

```bash
cat > /tmp/codex-preflight-release-notes.md <<'EOF'
vX.Y.Z

Release theme:
...

Changed:
- ...

Safety / security impact:
- ...

Validation:
- python scripts/sync_marketplace_plugin.py --check: passed
- python -m pytest: passed
- ruff check .: passed
- codex-preflight --help: passed
- codex-preflight-mcp --list-tools: passed

Compatibility:
- ...

Not included:
- ...
EOF

git tag -a vX.Y.Z -F /tmp/codex-preflight-release-notes.md
git push origin master
git push origin vX.Y.Z
```

## GitHub Release Notes

Create a GitHub Release from the same notes:

```bash
gh release create vX.Y.Z \
  --title "vX.Y.Z - <release theme>" \
  --notes-file /tmp/codex-preflight-release-notes.md
```

If `gh` is unavailable, create a GitHub Release manually from the existing tag and paste the same
notes.

## Existing Tags

Do not delete or recreate already-pushed tags only to improve their message. For old tags, prefer
adding GitHub Release notes that reference the existing tag.

Only rewrite tags when correcting a demonstrably wrong release pointer, and document the reason.
