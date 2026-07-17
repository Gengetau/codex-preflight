from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Any

from codex_preflight_guardian.remediation_plan import (
    PLAN_ID_PREFIX,
    GuardianPlanError,
    validate_remediation_plan,
)

SCHEMA_VERSION = "guardian-plan-approval/v1"
APPROVAL_ID_PREFIX = "guardian-approval-v1:sha256:"
MAX_APPROVAL_LIFETIME = timedelta(minutes=15)

_APPROVAL_ID_PATTERN = re.compile(r"guardian-approval-v1:sha256:[0-9a-f]{64}")
_NONCE_PATTERN = re.compile(r"[0-9a-f]{32,128}")
_TARGET_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SESSION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


class GuardianApprovalError(ValueError):
    """Raised when a plan approval violates the closed BW2 contract."""


def plan_approval_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://codex-preflight.local/schemas/guardian-plan-approval-v1.schema.json",
        "title": "Codex Preflight Guardian Plan Approval v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schemaVersion",
            "approvalId",
            "planId",
            "targetId",
            "sessionId",
            "approvedAt",
            "expiresAt",
            "nonce",
            "singleUse",
        ],
        "properties": {
            "schemaVersion": {"const": SCHEMA_VERSION},
            "approvalId": {
                "type": "string",
                "pattern": r"^guardian-approval-v1:sha256:[0-9a-f]{64}$",
            },
            "planId": {
                "type": "string",
                "pattern": r"^guardian-plan-v1:sha256:[0-9a-f]{64}$",
            },
            "targetId": {
                "type": "string",
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
            },
            "sessionId": {
                "type": "string",
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
            },
            "approvedAt": {"type": "string", "format": "date-time"},
            "expiresAt": {"type": "string", "format": "date-time"},
            "nonce": {"type": "string", "pattern": r"^[0-9a-f]{32,128}$"},
            "singleUse": {"const": True},
        },
    }


def build_plan_approval(
    plan: dict[str, Any],
    *,
    approved_at: str,
    expires_at: str,
    nonce: str,
) -> dict[str, Any]:
    validated_plan = validate_remediation_plan(plan)
    approval = {
        "schemaVersion": SCHEMA_VERSION,
        "approvalId": f"{APPROVAL_ID_PREFIX}{'0' * 64}",
        "planId": validated_plan["planId"],
        "targetId": validated_plan["target"]["targetId"],
        "sessionId": validated_plan["validity"]["sessionId"],
        "approvedAt": approved_at,
        "expiresAt": expires_at,
        "nonce": nonce,
        "singleUse": True,
    }
    _validate_structure(approval, validated_plan)
    approval["approvalId"] = compute_approval_id(approval)
    return validate_plan_approval(approval, validated_plan, now=approved_at)


def canonical_approval_bytes(approval: object) -> bytes:
    value = _approval_object(approval)
    payload = {key: item for key, item in value.items() if key != "approvalId"}
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise GuardianApprovalError("approval contains a non-canonical JSON value") from exc
    return encoded.encode("utf-8")


def compute_approval_id(approval: object) -> str:
    digest = hashlib.sha256(canonical_approval_bytes(approval)).hexdigest()
    return f"{APPROVAL_ID_PREFIX}{digest}"


def validate_plan_approval(
    approval: object,
    plan: dict[str, Any],
    *,
    now: str,
) -> dict[str, Any]:
    validated_plan = validate_remediation_plan(plan)
    value = _validate_structure(approval, validated_plan)
    expected = compute_approval_id(value)
    if value["approvalId"] != expected:
        raise GuardianApprovalError("approvalId does not match the complete canonical approval")
    current = _timestamp(now, "now")
    approved_at = _timestamp(value["approvedAt"], "approvedAt")
    expires_at = _timestamp(value["expiresAt"], "expiresAt")
    if current < approved_at:
        raise GuardianApprovalError("approval is not active yet")
    if current >= expires_at:
        raise GuardianApprovalError("approval has expired")
    return value


class ApprovalLedger:
    """Process-local single-use enforcement for validated approval records."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def consume(
        self,
        approval: object,
        plan: dict[str, Any],
        *,
        now: str,
    ) -> dict[str, Any]:
        value = validate_plan_approval(approval, plan, now=now)
        approval_id = value["approvalId"]
        if approval_id in self._consumed:
            raise GuardianApprovalError("approval has already been consumed")
        self._consumed.add(approval_id)
        return value

    def is_consumed(self, approval_id: str) -> bool:
        return approval_id in self._consumed


def _validate_structure(approval: object, plan: dict[str, Any]) -> dict[str, Any]:
    value = _approval_object(approval)
    if value["schemaVersion"] != SCHEMA_VERSION:
        raise GuardianApprovalError("schemaVersion is invalid")
    if not isinstance(value["approvalId"], str) or not _APPROVAL_ID_PATTERN.fullmatch(value["approvalId"]):
        raise GuardianApprovalError("approvalId is invalid")
    if not isinstance(value["planId"], str) or not value["planId"].startswith(PLAN_ID_PREFIX):
        raise GuardianApprovalError("planId is invalid")
    if value["planId"] != plan["planId"]:
        raise GuardianApprovalError("approval is not bound to the exact planId")
    _pattern_text(value["targetId"], "targetId", _TARGET_ID_PATTERN)
    if value["targetId"] != plan["target"]["targetId"]:
        raise GuardianApprovalError("approval target does not match the plan")
    _pattern_text(value["sessionId"], "sessionId", _SESSION_ID_PATTERN)
    if value["sessionId"] != plan["validity"]["sessionId"]:
        raise GuardianApprovalError("approval session does not match the plan")
    approved_at = _timestamp(value["approvedAt"], "approvedAt")
    expires_at = _timestamp(value["expiresAt"], "expiresAt")
    plan_created_at = _timestamp(plan["validity"]["createdAt"], "plan.validity.createdAt")
    plan_expires_at = _timestamp(plan["validity"]["expiresAt"], "plan.validity.expiresAt")
    if approved_at < plan_created_at:
        raise GuardianApprovalError("approval predates the plan")
    if expires_at <= approved_at:
        raise GuardianApprovalError("approval expiresAt must be after approvedAt")
    if expires_at - approved_at > MAX_APPROVAL_LIFETIME:
        raise GuardianApprovalError("approval lifetime exceeds the fifteen-minute maximum")
    if expires_at > plan_expires_at:
        raise GuardianApprovalError("approval cannot outlive the plan")
    if not isinstance(value["nonce"], str) or not _NONCE_PATTERN.fullmatch(value["nonce"]):
        raise GuardianApprovalError("nonce is invalid")
    if value["singleUse"] is not True:
        raise GuardianApprovalError("singleUse must be true")
    return value


def _approval_object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GuardianApprovalError("approval must be an object")
    expected = {
        "schemaVersion",
        "approvalId",
        "planId",
        "targetId",
        "sessionId",
        "approvedAt",
        "expiresAt",
        "nonce",
        "singleUse",
    }
    actual = set(value)
    if actual != expected:
        raise GuardianApprovalError(
            f"approval fields are invalid; missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}"
        )
    return value


def _pattern_text(value: object, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise GuardianApprovalError(f"{field} is invalid")
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GuardianApprovalError(f"{field} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GuardianApprovalError(f"{field} must be an RFC 3339 UTC timestamp") from exc
    if parsed.utcoffset() != timedelta(0):
        raise GuardianApprovalError(f"{field} must use UTC")
    return parsed


__all__ = [
    "ApprovalLedger",
    "GuardianApprovalError",
    "build_plan_approval",
    "compute_approval_id",
    "plan_approval_schema",
    "validate_plan_approval",
]
