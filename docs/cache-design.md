# Cache Design

Codex Preflight uses a scan cache and a trust cache under the user's local `.codex-preflight`
directory. Scan cache entries are reused only for `ALLOW` and `WARN` reports when the repository
identity, command scope, policy version, ruleset version, and critical fingerprint match. Trust
entries are scoped by command scope, commit, fingerprint, policy version, ruleset version, and TTL.
