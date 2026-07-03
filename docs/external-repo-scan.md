# External Repository Scan

`codex-preflight preflight --repo` clones a Git repository into a temporary directory, reads
critical files, produces a preflight report, and removes the clone unless `--keep-temp` is used.
It never runs repository code.

Example:

```bash
codex-preflight preflight --repo https://github.com/octocat/Hello-World.git --ref master --command "cat README" --format json
```

Options:

- `--repo`: Git clone URL to scan.
- `--ref`: optional branch, tag, or commit-ish to fetch and check out.
- `--depth`: clone/fetch depth, default `1`.
- `--temp-dir`: parent directory for temporary clones.
- `--keep-temp`: preserve the clone and print its path to stderr for debugging.

By default external scans only allow `https://` clone URLs. Local paths, `file://`, `ssh://`,
`git://`, `ext::`, and values starting with `-` are rejected before git is invoked. Clone and fetch
also run with git protocol restrictions for `ext`, `file`, and `ssh`.

Reports for external repositories include:

- `repo.sourceType`: `github`
- `repo.cloneUrl`
- `repo.requestedRef`
- `repo.resolvedCommit`

Clone errors are printed to stderr with the failed repository or ref and the underlying git
message. Exit code `2` means the scanner could not complete.

Safety limitations:

- Codex Preflight reads files statically. It does not execute install scripts, tests, Docker,
  shell scripts, or MCP servers.
- It is not a CVE scanner, dependency audit service, malware dynamic analyzer, or full SAST.
- Local trust approvals are not applied to ephemeral external clone paths.

Batch scans can read a YAML file:

```bash
codex-preflight batch scan examples/public-repos.yml --format markdown
```

Batch scans are intended for manual checks and are not part of CI by default.
