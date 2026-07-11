# Threat Model

Codex Preflight protects Codex-style coding agents from executing risky repository-controlled
commands without first reading critical files and returning a command-aware decision.

It does not execute repository code, start MCP servers, run package managers, build Docker images,
or upload repository data. The main protected actions are dependency installation, script
execution, Docker startup, build/test commands, and MCP server startup commands.

## v0.3.2 remote MCP authority

Remote MCP authority is absent by default. Exact startup flag
`CODEX_PREFLIGHT_ENABLE_REMOTE_SCAN=1` registers one confirmation-gated tool for public GitHub
HTTPS repositories. This authority permits a bounded network fetch and static scan only; it does
not permit planned-command execution, credentials, arbitrary destinations, proxy control,
redirects, submodule/LFS target fetch, or trust creation.

| Threat | Control |
| --- | --- |
| SSRF | Exact `github.com` HTTPS syntax, no ports/IP literals, public-address classification. |
| DNS rebinding | The public addresses validated immediately before fetch are pinned with Git/libcurl resolve configuration. |
| Redirect to another host | Git redirects are disabled and provenance reports zero followed redirects. |
| Credential or proxy leakage | User info is rejected; environment/config, helpers, prompts, headers, cookies, and proxies are disabled. |
| Protocol/helper escape | Shell-free argv and an HTTPS-only Git protocol allowlist. |
| Repository execution | Bare fetch, object reads, no checkout, regular-file-only materialization, isolated static worker. |
| Path/special-file escape | POSIX/Windows traversal, ADS, device, collision, mode, symlink, and junction controls. |
| Resource exhaustion | Fixed DNS/Git/scan/total deadlines, disk/expanded/file/count/depth/concurrency/report caps. |
| Cancellation residue | Core token, process-tree termination, shielded wait, and verified owned-root cleanup. |
| Confirmation replay | Process-local HMAC, complete policy/limit binding, 300-second expiry, atomic one-time consume. |
| Cache poisoning | Separate namespace, immutable commit/policy key, process-key HMAC, TTL/size caps, fail-closed errors. |
| Audit disclosure | Fixed redacted schema with URL/ref hashes and no token, path, environment, output, or evidence fields. |
| Remote prompt injection | Fixed server instructions plus `untrusted` and `treat-as-data` evidence labels. |

The first challenge call does no DNS, network, Git, snapshot, scan, or remote-cache access. Remote
cache reads occur only after confirmation and immutable ref resolution. Confirmation cannot be
derived from remote content or local trust and can never create, modify, or revoke trust.

Rollback removes the startup flag and restarts the process, which removes tool registration and
invalidates outstanding tokens. Remote cache/audit state is partitioned under the `remote`
namespace so incident cleanup does not touch local scan or trust data.
