from __future__ import annotations

import copy

import pytest

from codex_preflight_guardian.plan_approval import (
    ApprovalLedger,
    GuardianApprovalError,
    build_plan_approval,
    validate_plan_approval,
)
from codex_preflight_guardian.remediation_plan import (
    PROHIBITED_OPERATIONS,
    GuardianPlanError,
    build_remediation_plan,
    validate_remediation_plan,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64


def plan_payload() -> dict:
    return {
        "schemaVersion": "guardian-remediation-plan/v1",
        "source": {
            "reportDigest": DIGEST_A,
            "commandDigest": DIGEST_B,
            "originalDecision": "BLOCK",
        },
        "target": {
            "isolation": "required",
            "targetId": "isolated-target:demo-1",
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
            "summary": "Remove the remote lifecycle execution finding.",
            "removedRuleIds": ["NODE_LIFECYCLE_REMOTE_EXEC"],
            "remainingRiskStatement": "Residual findings must remain within the verification gate.",
        },
        "evidenceReferences": ["finding:0"],
        "validity": {
            "sessionId": "session:demo-1",
            "createdAt": "2026-07-16T12:00:00Z",
            "expiresAt": "2026-07-16T12:30:00Z",
        },
    }


def plan() -> dict:
    return build_remediation_plan(plan_payload())


def approval(source: dict | None = None, *, nonce: str = "1" * 32) -> dict:
    return build_plan_approval(
        source or plan(),
        approved_at="2026-07-16T12:05:00Z",
        expires_at="2026-07-16T12:10:00Z",
        nonce=nonce,
    )


def test_plan_id_is_stable_across_mapping_insertion_order() -> None:
    original = plan_payload()
    reordered = dict(reversed(list(original.items())))
    reordered["source"] = dict(reversed(list(original["source"].items())))
    reordered["verification"] = dict(reversed(list(original["verification"].items())))

    first = build_remediation_plan(original)
    second = build_remediation_plan(reordered)

    assert first["planId"] == second["planId"]
    assert first["planId"].startswith("guardian-plan-v1:sha256:")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["source"].update(reportDigest=DIGEST_C),
        lambda value: value["source"].update(originalDecision="ASK_USER"),
        lambda value: value["target"].update(targetId="isolated-target:demo-2"),
        lambda value: value["target"].update(rootDigest=DIGEST_D),
        lambda value: value["operations"][0].update(path="package-lock.json"),
        lambda value: value["operations"][0].update(preimageDigest=DIGEST_A),
        lambda value: value["operations"][0].update(postimageDigest=DIGEST_B),
        lambda value: value["verification"].update(acceptableDecisions=["ALLOW"]),
        lambda value: value["verification"].update(maximumRiskScore=10),
        lambda value: value["verification"].update(requiredAbsentRuleIds=[]),
        lambda value: value["expectedImprovement"].update(summary="Different expected improvement."),
        lambda value: value["expectedImprovement"].update(removedRuleIds=[]),
        lambda value: value.update(evidenceReferences=["finding:0", "uncertainty:0"]),
        lambda value: value["validity"].update(sessionId="session:demo-2"),
        lambda value: value["validity"].update(expiresAt="2026-07-16T12:45:00Z"),
    ],
)
def test_each_valid_bound_field_mutation_changes_plan_id(mutation) -> None:
    original = plan_payload()
    changed = copy.deepcopy(original)
    mutation(changed)

    assert build_remediation_plan(changed)["planId"] != build_remediation_plan(original)["planId"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(extra="unknown"),
        lambda value: value["source"].update(extra="unknown"),
        lambda value: value["operations"][0].update(extra="unknown"),
        lambda value: value["operations"][0].update(path="../package.json"),
        lambda value: value["operations"][0].update(path="/tmp/package.json"),
        lambda value: value["operations"][0].update(path="folder\\package.json"),
        lambda value: value["operations"][0].update(operationId="operation:1"),
        lambda value: value["operations"][0].update(kind="create-file"),
        lambda value: value.update(prohibitedOperations=list(reversed(PROHIBITED_OPERATIONS))),
        lambda value: value["verification"].update(commandDigest=DIGEST_C),
        lambda value: value["verification"].update(requireNoNewBlockingFindings=False),
        lambda value: value["validity"].update(expiresAt="2026-07-16T13:30:01Z"),
    ],
)
def test_invalid_or_incomplete_plan_contract_is_rejected(mutation) -> None:
    value = plan_payload()
    mutation(value)

    with pytest.raises(GuardianPlanError):
        build_remediation_plan(value)


def test_operation_order_is_bound_to_plan_identity() -> None:
    original = plan_payload()
    original["operations"].append(
        {
            "operationId": "operation:1",
            "kind": "create-file",
            "path": "SECURITY.md",
            "preimageDigest": "absent",
            "postimageDigest": DIGEST_A,
        }
    )
    first = build_remediation_plan(original)

    reordered = copy.deepcopy(original)
    reordered["operations"].reverse()
    for index, operation in enumerate(reordered["operations"]):
        operation["operationId"] = f"operation:{index}"
    second = build_remediation_plan(reordered)

    assert first["planId"] != second["planId"]


def test_plan_id_cannot_be_supplied_or_reused_after_drift() -> None:
    value = plan_payload()
    value["planId"] = "guardian-plan-v1:sha256:" + "0" * 64
    with pytest.raises(GuardianPlanError, match="must not provide planId"):
        build_remediation_plan(value)

    valid = plan()
    valid["target"]["rootDigest"] = DIGEST_D
    with pytest.raises(GuardianPlanError, match="planId does not match"):
        validate_remediation_plan(valid)


def test_approval_is_separate_exact_and_single_use() -> None:
    source = plan()
    record = approval(source)
    ledger = ApprovalLedger()

    assert record["planId"] == source["planId"]
    assert record["targetId"] == source["target"]["targetId"]
    assert record["sessionId"] == source["validity"]["sessionId"]
    assert record["singleUse"] is True
    assert ledger.consume(record, source, now="2026-07-16T12:06:00Z") is record
    assert ledger.is_consumed(record["approvalId"]) is True

    with pytest.raises(GuardianApprovalError, match="already been consumed"):
        ledger.consume(record, source, now="2026-07-16T12:07:00Z")


def test_approval_identity_binds_nonce_and_all_record_fields() -> None:
    first = approval(nonce="1" * 32)
    second = approval(nonce="2" * 32)

    assert first["approvalId"] != second["approvalId"]

    first["expiresAt"] = "2026-07-16T12:09:00Z"
    with pytest.raises(GuardianApprovalError, match="approvalId does not match"):
        validate_plan_approval(first, plan(), now="2026-07-16T12:06:00Z")


@pytest.mark.parametrize(
    ("now", "message"),
    [
        ("2026-07-16T12:04:59Z", "not active yet"),
        ("2026-07-16T12:10:00Z", "has expired"),
    ],
)
def test_approval_time_window_is_enforced(now: str, message: str) -> None:
    source = plan()
    record = approval(source)

    with pytest.raises(GuardianApprovalError, match=message):
        validate_plan_approval(record, source, now=now)


def test_approval_rejects_plan_target_session_and_unknown_field_drift() -> None:
    source = plan()
    record = approval(source)

    changed_plan_payload = plan_payload()
    changed_plan_payload["target"]["targetId"] = "isolated-target:demo-2"
    changed_plan = build_remediation_plan(changed_plan_payload)
    with pytest.raises(GuardianApprovalError, match="exact planId"):
        validate_plan_approval(record, changed_plan, now="2026-07-16T12:06:00Z")

    changed = copy.deepcopy(record)
    changed["sessionId"] = "session:demo-2"
    with pytest.raises(GuardianApprovalError, match="session"):
        validate_plan_approval(changed, source, now="2026-07-16T12:06:00Z")

    changed = copy.deepcopy(record)
    changed["extra"] = "unknown"
    with pytest.raises(GuardianApprovalError, match="fields are invalid"):
        validate_plan_approval(changed, source, now="2026-07-16T12:06:00Z")


def test_approval_lifetime_is_bounded_by_plan() -> None:
    source = plan()

    with pytest.raises(GuardianApprovalError, match="fifteen-minute"):
        build_plan_approval(
            source,
            approved_at="2026-07-16T12:05:00Z",
            expires_at="2026-07-16T12:21:00Z",
            nonce="1" * 32,
        )

    with pytest.raises(GuardianApprovalError, match="outlive the plan"):
        build_plan_approval(
            source,
            approved_at="2026-07-16T12:20:00Z",
            expires_at="2026-07-16T12:31:00Z",
            nonce="1" * 32,
        )
