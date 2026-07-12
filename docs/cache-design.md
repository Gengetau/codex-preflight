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
provenance.source: legacy-migration | cli-trust-approve | mcp-trust-approve
provenance.migrationVersion: v0.3.3-trust-read-foundation | v0.3.4-trust-mutation
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

## Trust mutation state

With exact `CODEX_PREFLIGHT_ENABLE_TRUST_MUTATION=1`, confirmed MCP approval creates a normal v2
entry with exact private provenance: `source: mcp-trust-approve`, migration version
`v0.3.4-trust-mutation`, the server-issued `createdAt`, bounded `approvalReason`, and prepared
`mutationAuditEventId`. Existing entries remain unchanged. Local CLI `trust list` can display this
provenance and audit ID; CLI matching and identity-based revoke use the same existing store and
matching key without a migration or broader approval semantics.

Mutation audit state is separate under `trust-mutation/audit.jsonl` and `trust-mutation/audit.key`.
It is owner-only where supported, HMAC-chained, fsynced, redacted, and bounded to 4096-byte records,
one 1 MiB active segment, three rotated segments, and 4 MiB total. The write-ahead sequence is a
prepared audit record, atomic trust-file replacement, then a committed audit record. If replacement
commits but final audit persistence fails, return
`MCP_TRUST_MUTATION_COMMITTED_AUDIT_PENDING` with `committed: true`; never retry the write. Restart
performs audit recovery of the sole unmatched prepared event or fails closed. There is no MCP
recovery, audit-read, or reset tool.
