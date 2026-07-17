from __future__ import annotations

import json
from pathlib import Path

from jsonschema import FormatChecker, validate

from codex_preflight_guardian.plan_approval import (
    build_plan_approval,
    plan_approval_schema,
)
from codex_preflight_guardian.remediation_plan import (
    PROHIBITED_OPERATIONS,
    build_remediation_plan,
    remediation_plan_schema,
)

ROOT = Path(__file__).resolve().parents[1]
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64


def _plan() -> dict:
    return build_remediation_plan(
        {
            "schemaVersion": "guardian-remediation-plan/v1",
            "source": {
                "reportDigest": DIGEST_A,
                "commandDigest": DIGEST_B,
                "originalDecision": "BLOCK",
            },
            "target": {
                "isolation": "required",
                "targetId": "isolated-target:schema-test",
                "rootDigest": DIGEST_C,
            },
            "operations": [
                {
                    "operationId": "operation:0",
                    "kind": "replace-file",
                    "path": "package.json",
                    "preimageDigest": DIGEST_D,
                    "postimageDigest": DIGEST_E,
                }
            ],
            "prohibitedOperations": list(PROHIBITED_OPERATIONS),
            "verification": {
                "commandDigest": DIGEST_B,
                "acceptableDecisions": ["ALLOW", "WARN"],
                "maximumRiskScore": 20,
                "requiredAbsentRuleIds": ["NODE_LIFECYCLE_REMOTE_EXEC"],
                "requireNoNewBlockingFindings": True,
            },
            "expectedImprovement": {
                "summary": "Remove the blocking lifecycle finding.",
                "removedRuleIds": ["NODE_LIFECYCLE_REMOTE_EXEC"],
                "remainingRiskStatement": "Residual risk remains subject to deterministic verification.",
            },
            "evidenceReferences": ["finding:0"],
            "validity": {
                "sessionId": "session:schema-test",
                "createdAt": "2026-07-16T12:00:00Z",
                "expiresAt": "2026-07-16T12:30:00Z",
            },
        }
    )


def test_checked_in_remediation_plan_schema_matches_code_contract() -> None:
    checked_in = json.loads(
        (ROOT / "schemas" / "guardian-remediation-plan-v1.schema.json").read_text(encoding="utf-8")
    )

    assert checked_in == remediation_plan_schema()
    validate(instance=_plan(), schema=checked_in, format_checker=FormatChecker())


def test_checked_in_plan_approval_schema_matches_code_contract() -> None:
    checked_in = json.loads(
        (ROOT / "schemas" / "guardian-plan-approval-v1.schema.json").read_text(encoding="utf-8")
    )
    plan = _plan()
    approval = build_plan_approval(
        plan,
        approved_at="2026-07-16T12:05:00Z",
        expires_at="2026-07-16T12:10:00Z",
        nonce="1" * 32,
    )

    assert checked_in == plan_approval_schema()
    validate(instance=approval, schema=checked_in, format_checker=FormatChecker())
