# Release Process

This process keeps Codex Preflight releases auditable and avoids thin tags that do not explain
what changed.

## Version Sync

Update every version-bearing file:

- `pyproject.toml`
- `codex_preflight_core/__init__.py`
- `codex_preflight_mcp/__init__.py`
- `.codex-plugin/plugin.json`
- `plugins/codex-preflight/.codex-plugin/plugin.json`

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
installs an optional dependency. A missing MCP runtime makes both the integration check and
`mcp.inventory.runtime` a `SKIP`; no runtime subprocess is invoked, and the supported remediation is
`python -m pip install "codex-preflight[mcp]"`. Local verification always checks all version sources,
plugin copies, supported integrations, and all eight exact static MCP inventories. It checks all
eight runtime inventories only when the optional MCP runtime is installed.
The target checkout is read through bounded no-follow handles and strict static parsers, and is never
added to a runtime probe's `PYTHONPATH`. Runtime probes require a Codex Preflight package root whose
resolved module path is outside the target; filesystem overlap fails before a probe starts. This
proves filesystem separation only and does not determine editable-install metadata or independent
provenance for a package built from the target. Runtime probes replace only side-effectful trust
service factories with inert in-memory services, then invoke the same default `create_mcp_server()`
path and pure shared registration function as normal startup. They read the actual FastMCP Tool
Manager without trust-store construction, recovery, or registration audit writes. The target must
be the exact Git worktree root and `HEAD` must equal the requested
canonical commit. Every file consumed by diagnostics is read no-follow and content-matched against
its tracked regular-blob commit entry. Symlink/submodule modes fail even if materialized as files.
All downstream parsing uses the same immutable verified byte snapshot, eliminating a second-read
window. Only safe CRLF-to-LF conversion is accepted; repository filters never run. Dynamic global
writes fail the strict AST contract. Thus `assume-unchanged` and `skip-worktree` cannot hide drift. Git environment
overrides are discarded, `git status` and repository fsmonitor hooks are not invoked, and a supplied
release tag must be annotated.
Git discovery is pinned to one canonical absolute executable outside the target checkout; every
read-only Git plumbing call uses that exact path rather than re-resolving a literal `git`.

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
`--merged-branch` requires `--github-repo`; `--github-repo` requires at least `--tag` or
`--merged-branch`. Repository metadata must positively identify an accessible public repository
before a branch `404` is accepted as deletion. Repository and branch components are validated before
network access, redirects are rejected, and every GitHub response is size bounded.

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
