from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codex_preflight_core.cache.atomic_json import read_json, write_json_atomic


class TrustCache:
    def __init__(self, path: Path) -> None:
        self.path = path

    def list(self) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        entries = list(read_json(self.path, []))
        return [
            entry
            for entry in entries
            if datetime.fromisoformat(entry["expiresAt"]) > now
        ]

    def approve(
        self,
        *,
        repo_id: str,
        path: Path,
        remote_url: str | None,
        head_commit: str | None,
        critical_fingerprint: str,
        command_scope: str,
        approved_command: str,
        expires_at: datetime,
        policy_version: str = "default-v1",
        ruleset_version: str = "2026.07.02",
    ) -> None:
        entries = self.list()
        entries.append(
            {
                "repoId": repo_id,
                "path": str(path),
                "remoteUrl": remote_url,
                "headCommit": head_commit,
                "criticalFingerprint": critical_fingerprint,
                "commandScope": command_scope,
                "approvedCommand": approved_command,
                "decision": "USER_APPROVED",
                "approvedAt": datetime.now(UTC).isoformat(),
                "expiresAt": expires_at.isoformat(),
                "approvedBy": "local-user",
                "policyVersion": policy_version,
                "rulesetVersion": ruleset_version,
            }
        )
        write_json_atomic(self.path, entries)

    def match(
        self,
        *,
        repo_id: str,
        head_commit: str | None,
        critical_fingerprint: str,
        command_scope: str,
        policy_version: str = "default-v1",
        ruleset_version: str = "2026.07.02",
    ) -> dict[str, Any] | None:
        for entry in self.list():
            if (
                entry["repoId"] == repo_id
                and entry["headCommit"] == head_commit
                and entry["criticalFingerprint"] == critical_fingerprint
                and entry["commandScope"] == command_scope
                and entry.get("policyVersion") == policy_version
                and entry.get("rulesetVersion") == ruleset_version
            ):
                return entry
        return None

    def revoke_identity(self, repo_id: str, command_scope: str | None = None) -> int:
        entries = self.list()
        kept = [
            entry
            for entry in entries
            if not (
                entry["repoId"] == repo_id
                and (command_scope is None or entry["commandScope"] == command_scope)
            )
        ]
        removed = len(entries) - len(kept)
        write_json_atomic(self.path, kept)
        return removed
