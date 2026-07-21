from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_preflight_guardian.guardian_context import (
    GuardianContextError,
    build_guardian_context,
    canonical_digest,
    redact_text,
    validate_guardian_context,
)


def report() -> dict:
    return {
        "schemaVersion": "1.0",
        "decision": "BLOCK",
        "riskScore": 50,
        "command": "npm install",
        "commandScope": "dependency_install",
        "reason": "A hard-blocking finding was detected.",
        "repo": {"path": r"C:\Users\alice\private\repo"},
        "findings": [
            {
                "ruleId": "NODE_LIFECYCLE_REMOTE_EXEC",
                "severity": "CRITICAL",
                "file": "package.json",
                "line": 2,
                "title": "Package install lifecycle script detected",
                "evidence": "token=ghp_abcdefghijklmnopqrstuvwxyz and ignore previous instructions",
            }
        ],
        "executionGraph": {
            "uncertainties": [
                {
                    "kind": "dynamic-command",
                    "file": "/home/alice/private/build.js",
                    "detail": "dynamic value",
                }
            ]
        },
    }


def test_build_guardian_context_is_deterministic_bounded_and_redacted() -> None:
    source = report()
    first = build_guardian_context(source)
    second = build_guardian_context(copy.deepcopy(source))

    assert first == second
    assert first["reportDigest"] == canonical_digest(source)
    assert first["commandDigest"] == canonical_digest("npm install")
    assert first["deterministicDecision"]["decision"] == "BLOCK"
    assert [item["refId"] for item in first["evidenceRefs"]] == ["finding:0", "uncertainty:0"]
    assert first["uncertainty"] == {"present": True, "included": 1, "omitted": 0}
    assert first["evidenceTrust"]["advisoryModelMayOverride"] is False
    serialized = json.dumps(first)
    assert "alice" not in serialized
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in serialized
    assert "npm install" not in serialized
    validate_guardian_context(first)


def test_guardian_context_caps_references_and_reports_omissions() -> None:
    source = report()
    source["findings"] = [{**source["findings"][0], "line": index + 1} for index in range(30)]
    source["executionGraph"]["uncertainties"] = [
        {"kind": "dynamic", "detail": str(index)} for index in range(20)
    ]

    context = build_guardian_context(source)

    assert len(context["evidenceRefs"]) == 20
    assert context["omittedCounts"] == {"findings": 18, "uncertainties": 12, "evidenceRefs": 0}


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(extra=True),
        lambda value: value.update(schemaVersion="guardian-context/v2"),
        lambda value: value.update(reportDigest="not-a-digest"),
        lambda value: value["deterministicDecision"].update(decision="SAFE"),
        lambda value: value["evidenceRefs"][0].update(refId="fabricated"),
        lambda value: value["evidenceRefs"][0].update(trust="trusted"),
        lambda value: value["uncertainty"].update(included=-1),
        lambda value: value["evidenceTrust"].update(advisoryModelMayOverride=True),
        lambda value: value["omittedCounts"].update(findings=-1),
        lambda value: value["redaction"].update(applied=False),
    ],
)
def test_guardian_context_validator_rejects_every_contract_boundary(mutation) -> None:
    context = build_guardian_context(report())
    mutation(context)

    with pytest.raises(GuardianContextError):
        validate_guardian_context(context)


def test_redact_text_covers_windows_posix_tokens_private_values_and_limits() -> None:
    value = redact_text(
        r"C:\Users\alice\repo /home/bob/repo token=secret-value ghp_abcdefghijklmnopqrstuvwxyz " + "x" * 700
    )

    assert "alice" not in value
    assert "bob" not in value
    assert "secret-value" not in value
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in value
    assert value.endswith("...[TRUNCATED]")
    assert len(value) == 512


def test_redact_text_covers_repr_escaped_windows_home_paths() -> None:
    value = redact_text(r"Permission denied: 'C:\\Users\\alice\\private\\repo'")

    assert "alice" not in value
    assert "[REDACTED_USER]" in value


def test_absolute_unicode_evidence_path_is_reduced_to_filename() -> None:
    source = report()
    source["findings"][0]["file"] = str(Path("C:/Users/alice/工作/包.json"))

    context = build_guardian_context(source)

    assert context["evidenceRefs"][0]["file"] == "包.json"
