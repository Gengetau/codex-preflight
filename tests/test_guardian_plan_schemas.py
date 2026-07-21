from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import FormatChecker, validate

from codex_preflight_guardian.guardian_context import build_guardian_context
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
POSTIMAGE_CONTENT = '{"name":"safe-demo","scripts":{}}\n'
POSTIMAGE_DIGEST = "sha256:" + hashlib.sha256(POSTIMAGE_CONTENT.encode("utf-8")).hexdigest()


def _context() -> dict:
    return build_guardian_context(
        {
            "decision": "BLOCK",
            "riskScore": 50,
            "command": "npm install",
            "commandScope": "dependency_install",
            "reason": "A hard-blocking finding was detected.",
            "findings": [
                {
                    "ruleId": "NODE_LIFECYCLE_REMOTE_EXEC",
                    "severity": "CRITICAL",
                    "file": "package.json",
                    "line": 2,
                    "title": "Lifecycle script",
                    "evidence": "remote lifecycle execution pattern",
                }
            ],
            "executionGraph": {"uncertainties": []},
        }
    )


def _plan(context: dict) -> dict:
    return build_remediation_plan(
        {
            "schemaVersion": "guardian-remediation-plan/v1",
            "source": {
                "reportDigest": context["reportDigest"],
                "commandDigest": context["commandDigest"],
                "originalDecision": "BLOCK",
            },
            "target": {
                "isolation": "required",
                "targetId": "isolated-target:schema-test",
                "rootDigest": DIGEST_A,
            },
            "operations": [
                {
                    "operationId": "operation:0",
                    "kind": "replace-file",
                    "path": "package.json",
                    "preimageDigest": DIGEST_B,
                    "postimageDigest": POSTIMAGE_DIGEST,
                    "postimageContent": POSTIMAGE_CONTENT,
                }
            ],
            "prohibitedOperations": list(PROHIBITED_OPERATIONS),
            "verification": {
                "commandDigest": context["commandDigest"],
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
        },
        context,
    )


def test_checked_in_remediation_plan_schema_matches_code_contract() -> None:
    checked_in = json.loads(
        (ROOT / "schemas" / "guardian-remediation-plan-v1.schema.json").read_text(encoding="utf-8")
    )
    context = _context()

    assert checked_in == remediation_plan_schema()
    validate(instance=_plan(context), schema=checked_in, format_checker=FormatChecker())


def test_checked_in_plan_approval_schema_matches_code_contract() -> None:
    checked_in = json.loads(
        (ROOT / "schemas" / "guardian-plan-approval-v1.schema.json").read_text(encoding="utf-8")
    )
    context = _context()
    plan = _plan(context)
    approval = build_plan_approval(
        plan,
        context,
        approved_at="2026-07-16T12:05:00Z",
        expires_at="2026-07-16T12:10:00Z",
        nonce="1" * 32,
    )

    assert checked_in == plan_approval_schema()
    validate(instance=approval, schema=checked_in, format_checker=FormatChecker())
