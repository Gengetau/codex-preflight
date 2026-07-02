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
                "policyVersion": "default-v1",
                "rulesetVersion": "2026.07.02",
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
    ) -> dict[str, Any] | None:
        for entry in self.list():
            if (
                entry["repoId"] == repo_id
                and entry["headCommit"] == head_commit
                and entry["criticalFingerprint"] == critical_fingerprint
                and entry["commandScope"] == command_scope
            ):
                return entry
        return None

    def revoke(self, path: Path) -> None:
        target = str(path)
        write_json_atomic(self.path, [entry for entry in self.list() if entry["path"] != target])
