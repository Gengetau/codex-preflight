from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_preflight_core.cache.paths import (
    remote_audit_path,
    remote_scan_cache_path,
    scan_cache_path,
    trust_cache_path,
)
from codex_preflight_mcp.remote_state import (
    RemoteAuditLog,
    RemoteScanCache,
    RemoteStateError,
    build_remote_cache_key,
)

COMMIT = "a" * 40
URL = "https://github.com/example/project"
REF = "refs/heads/main"


class Clock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value


def report(marker: str = "first") -> dict:
    return {
        "schemaVersion": "1.0",
        "decision": "WARN",
        "riskScore": 10,
        "repo": {"marker": marker},
        "findings": [],
        "cache": {"usedScanCache": False, "usedTrustCache": False, "cacheReason": None},
    }


def test_remote_paths_are_partitioned_from_local_and_trust_state(tmp_path: Path) -> None:
    assert remote_scan_cache_path(tmp_path) == tmp_path / "remote" / "scan-cache.json"
    assert remote_audit_path(tmp_path) == tmp_path / "remote" / "audit.jsonl"
    assert remote_scan_cache_path(tmp_path) not in {scan_cache_path(tmp_path), trust_cache_path(tmp_path)}
    assert remote_audit_path(tmp_path) not in {scan_cache_path(tmp_path), trust_cache_path(tmp_path)}


def test_remote_cache_key_uses_url_hash_and_immutable_versions_only() -> None:
    key = build_remote_cache_key(URL, COMMIT)
    serialized = json.dumps(key, sort_keys=True)

    assert key["sourceType"] == "remote"
    assert key["canonicalUrlHash"] == hashlib.sha256(URL.encode()).hexdigest()
    assert key["resolvedCommit"] == COMMIT
    assert key["hostPolicyVersion"] == "github-public-v1"
    assert key["resourceLimitProfile"] == "remote-bounded-v1"
    assert URL not in serialized
    assert "requestedRef" not in serialized


def test_remote_cache_round_trip_expiry_and_copy_isolation(tmp_path: Path) -> None:
    clock = Clock()
    cache = RemoteScanCache(tmp_path / "remote" / "scan-cache.json", clock=clock, ttl_seconds=60)
    key = build_remote_cache_key(URL, COMMIT)

    cache.store(key, report())
    first = cache.get(key)
    assert first == report()
    assert first is not None
    first["repo"]["marker"] = "mutated"
    assert cache.get(key) == report()

    clock.value += 61
    assert cache.get(key) is None
    assert json.loads(cache.path.read_text(encoding="utf-8")) == []
    assert not scan_cache_path(tmp_path).exists()
    assert not trust_cache_path(tmp_path).exists()


def test_remote_cache_enforces_entry_report_and_file_bounds(tmp_path: Path) -> None:
    cache = RemoteScanCache(
        tmp_path / "remote" / "scan-cache.json",
        max_entries=2,
        max_report_bytes=2_000,
        max_total_bytes=4_000,
    )
    for index in range(3):
        cache.store(build_remote_cache_key(URL, f"{index + 1:040x}"), report(str(index)))

    entries = json.loads(cache.path.read_text(encoding="utf-8"))
    assert len(entries) == 2
    assert [entry["report"]["repo"]["marker"] for entry in entries] == ["1", "2"]
    assert cache.path.stat().st_size <= 4_000

    with pytest.raises(RemoteStateError) as oversized:
        cache.store(build_remote_cache_key(URL, "f" * 40), {"decision": "WARN", "evidence": "x" * 3_000})
    assert oversized.value.code == "MCP_REMOTE_CACHE_FAILED"


def test_remote_cache_corruption_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "remote" / "scan-cache.json"
    path.parent.mkdir()
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(RemoteStateError) as caught:
        RemoteScanCache(path).get(build_remote_cache_key(URL, COMMIT))

    assert caught.value.code == "MCP_REMOTE_CACHE_FAILED"


def test_remote_cache_detects_tampering_and_discards_prior_process_entries(tmp_path: Path) -> None:
    path = tmp_path / "remote" / "scan-cache.json"
    key = build_remote_cache_key(URL, COMMIT)
    first_process = RemoteScanCache(path, secret=b"x" * 32)
    first_process.store(key, report())

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[0]["report"]["decision"] = "ALLOW"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RemoteStateError) as tampered:
        first_process.get(key)
    assert tampered.value.code == "MCP_REMOTE_CACHE_FAILED"

    second_process = RemoteScanCache(path, secret=b"y" * 32)
    assert second_process.get(key) is None
    assert json.loads(path.read_text(encoding="utf-8")) == []


def test_remote_audit_is_redacted_append_only_and_schema_bounded(tmp_path: Path) -> None:
    path = tmp_path / "remote" / "audit.jsonl"
    audit = RemoteAuditLog(path, clock=Clock())
    audit.record(
        "challenge_issue",
        challenge_id="challenge-1",
        canonical_url=URL,
        requested_ref=REF,
        outcome="confirmation-required",
        resource_usage={"materializedBytes": 0, "ignoredString": "secret"},
    )
    audit.record(
        "confirmation_consume",
        challenge_id="challenge-1",
        canonical_url=URL,
        requested_ref=REF,
        outcome="consumed",
    )

    lines = path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    serialized = path.read_text(encoding="utf-8")
    assert [record["event"] for record in records] == ["challenge_issue", "confirmation_consume"]
    assert records[0]["canonicalUrlHash"] == hashlib.sha256(URL.encode()).hexdigest()
    assert records[0]["requestedRefHash"] == hashlib.sha256(REF.encode()).hexdigest()
    assert records[0]["resourceUsage"] == {"materializedBytes": 0}
    assert URL not in serialized
    assert REF not in serialized
    assert "secret" not in serialized
    assert all("hostPolicyVersion" in record for record in records)
    assert all("resourceLimitProfile" in record for record in records)

    with pytest.raises(RemoteStateError):
        audit.record("arbitrary-event", challenge_id="challenge-1")


def test_remote_audit_rotation_and_concurrent_appends_remain_bounded_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "remote" / "audit.jsonl"
    audit = RemoteAuditLog(path, max_bytes=900, max_segments=2)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(
            pool.map(
                lambda index: audit.record(
                    "operation_start",
                    operation_id=f"operation-{index}",
                    challenge_id=f"challenge-{index}",
                    canonical_url=URL,
                    requested_ref=REF,
                    outcome="started",
                ),
                range(20),
            )
        )

    segments = [candidate for candidate in path.parent.glob("audit.jsonl*") if not candidate.name.endswith(".lock")]
    assert 1 <= len(segments) <= 2
    assert all(candidate.stat().st_size <= 900 for candidate in segments)
    records = [
        json.loads(line)
        for candidate in segments
        for line in candidate.read_text(encoding="utf-8").splitlines()
    ]
    assert records
    assert all(record["event"] == "operation_start" for record in records)
    assert URL not in "".join(candidate.read_text(encoding="utf-8") for candidate in segments)
