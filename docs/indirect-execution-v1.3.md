# V1.3 Indirect Execution And Uncertainty Policy

V1.3 adds best-effort static reachability analysis. Codex Preflight now starts from the planned
command, builds an execution graph of statically reachable local files, and reports capabilities
and uncertainties found along that chain.

The analyzer remains static. It does not run package install scripts, shell scripts, Docker,
tests from fixtures, MCP servers, or repository code.

## Execution Graph

JSON reports include `executionGraph`:

- `entryCommand`: the planned command.
- `nodes`: commands, package lifecycle scripts, and reachable files.
- `edges`: why one node reaches another.
- `capabilities`: reachable behavior such as child process execution, dynamic eval, network
  access, shell downloads, Docker socket mounts, or Dockerfile remote shell patterns.
- `uncertainties`: missing targets, outside-repository targets, unknown interpreters, parse
  uncertainty, dynamic command construction, or exceeded script-chain depth.

Markdown reports include `## Execution Chain` and `## Uncertainty` sections.

## Entry Points

The resolver follows these command scopes:

- Dependency installs: Node package lifecycle scripts (`preinstall`, `install`, `postinstall`,
  `prepare`, `prepack`, `postpack`) and local scripts they reference.
- Script execution: `bash`, `sh`, `python`, `node`, `powershell`, and `pwsh` local targets.
- Docker: compose files and statically visible Dockerfiles.
- Build/test package scripts: `make`, `npm/pnpm/yarn run <script>`, and shorthand commands such
  as `npm test`, `npm start`, and `npm build`.

Only relative in-repository paths are followed. Absolute paths and paths outside the repository
become uncertainty findings instead of being scanned.

Reachable files are read through the same bounded safe reader used by the scanner. Oversized,
binary, unreadable, and symlink targets are reported as uncertainty instead of being directly read.
Directories marked with `.codex-preflight-fixtures` are skipped during reachability traversal.

## Policy

Unknown is not safe. For high-risk command scopes, reachability uncertainty raises the result to
`ASK_USER` at minimum. Reachable remote shell execution, encoded command execution, real token or
private key findings, and destructive commands remain blocking conditions.

The graph is best-effort and bounded by a maximum chain depth and node count. If the limit is
exceeded, the report includes `SCRIPT_CHAIN_DEPTH_EXCEEDED`.

## Limitations

The scanner is still static, heuristic, and best-effort. It never executes repository code, and it
cannot prove a repository is safe, evaluate all language semantics, resolve dynamic imports, or
model runtime environment changes. V1.3 closes known indirection gaps by surfacing reachable local
scripts and uncertainty rather than treating unknown paths as safe.
