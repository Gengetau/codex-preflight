# Build Week Submission Checklist

This checklist separates repository work from account-bound publication work.

## Repository Work — Assistant-Owned

- [x] BW0–BW5 implementation and evidence recorded.
- [x] Fresh 600-second accepted-plan conformance rerun passed.
- [x] Windows and Ubuntu CI passed on the evidence candidate.
- [x] Windows x64 and Linux x64 packaged runtimes built and smoke-tested.
- [x] Marketplace synchronization and release-readiness checks passed in CI.
- [x] MCP smoke tests passed on Windows and Ubuntu.
- [x] Public status records Linux/Bash Hook certification as `NOT VERIFIED / DEFERRED`.
- [x] Public video script added at `docs/build-week-video-script.md`.
- [ ] Add final YouTube and Devpost URLs after publication.
- [ ] Fold final submission links and final candidate SHA into `README.md` and `BUILD_WEEK.md`.
- [ ] Update PR #15 body with the final links and candidate SHA.
- [ ] Confirm final exact-head `CI` and `Build plugin runtime` are green.
- [ ] Record final exact-head review result.

## Account-Bound Publication — User-Owned

The following actions require the project owner's authenticated accounts and an explicit public-publish decision:

- [ ] Record the video using `docs/build-week-video-script.md`.
- [ ] Upload the video to YouTube and make it publicly accessible or unlisted as required by the event.
- [ ] Create or finish the Devpost project page.
- [ ] Add the public GitHub repository URL.
- [ ] Add the YouTube URL.
- [ ] Complete required project description, track, team, and submission fields.
- [ ] Review the public claims and known limitations.
- [ ] Click the final Devpost submit action.

Codex or the assistant should not click final public submission, publish a video, or change account visibility without the owner's direct review.

## Required Public Claims

Use these claims:

```text
Product flow: Hook -> Detect -> Explain -> Approve -> Repair -> Verify -> Final Decision
BW5 Plugin Experience: COMPLETE
Repair mode on the tested Codex surface: verified-isolated-repair
Deterministic verification: BLOCK / 50 -> ALLOW / 0
Planned command executions: 0
Fixture content executions: 0
Network access during the test phase: 0
```

## Required Limitation Disclosure

Use this wording or a materially equivalent statement:

> The tested Windows and native Linux Codex sessions exposed `exec_command`, not the canonical `Bash` tool matched by the plugin's current `^Bash$` Hook matcher. Linux/Bash Hook-active certification therefore remains `NOT VERIFIED / DEFERRED`, and the demonstrated protection mode is `skill-only` with `verified-isolated-repair`. No unsupported Hook-enforcement claim is made.

## Submission Inputs Needed From the Owner

Provide these two URLs after publication:

```text
YouTube URL:
Devpost project/submission URL:
```

The repository URL is:

```text
https://github.com/Gengetau/codex-preflight
```

The selected Codex `/feedback` Session ID is:

```text
019f6891-7fa8-7640-a629-379ee5ec0627
```

## Final Freeze Procedure

After the two public URLs are available:

1. Update `README.md`, `BUILD_WEEK.md`, PR #15, and this checklist with the links.
2. Record the resulting branch HEAD as the final submission candidate.
3. Do not make unrelated code or documentation changes after the freeze.
4. Require exact-head success for `CI` and `Build plugin runtime`.
5. Confirm PR #15 remains Draft unless the event workflow explicitly requires otherwise.
6. Do not merge, tag, or publish a software release solely for the competition submission unless separately authorized.
