# Cache Design

Codex Preflight uses a scan cache and a trust cache under the user's local `.codex-preflight`
directory. Scan cache entries are reused only for `ALLOW` and `WARN` reports when the repository
identity, command scope, policy version, ruleset version, and critical fingerprint match. Trust
entries are scoped by command scope, commit, fingerprint, policy version, ruleset version, and TTL.

## Trust cache v2

v0.3.3 keeps the trust store as a JSON array and adds metadata to each entry:

```text
entryId: stored UUIDv4
entryVersion: 1
provenance.schema: trust-cache-array-v2
provenance.source: legacy-migration | cli-trust-approve
provenance.migrationVersion: v0.3.3-trust-read-foundation
```

The first read of a valid legacy array acquires the same sidecar lock used by CLI approve/revoke,
validates every entry, creates a permission-preserving bounded backup, adds metadata, fsyncs a
temporary file, and atomically replaces the trust file. At most three migration backups are kept.
The migration is idempotent and preserves repository identity, path, URL, commit, fingerprint,
scope, approved command, decision, timestamps, actor, policy/ruleset, expiry, approval count, and
matching behavior exactly at the JSON value level.

Both legacy and v2 files are capped at 1 MiB before parsing. New writes are size-checked before
replacement. Corrupt JSON, non-array top levels, invalid fields, partial/future metadata, lock
timeouts, backup failures, and atomic-write failures fail closed. Missing and empty stores list as
empty; expired entries remain stored but do not match or appear in live listings.

## Trust-read state

MCP trust reads use only the normal trust-cache resolver, including the existing
`CODEX_PREFLIGHT_HOME` behavior. They do not accept a cache path, repository path, URL, output path,
or destination. Read audit state is separate at `trust-read/audit.jsonl`; it is not scan cache,
remote cache, remote audit, or trust data. The active audit segment is capped at 1 MiB with three
rotated segments and 4096-byte records.
