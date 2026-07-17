from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Any

SCHEMA_VERSION = "guardian-remediation-plan/v1"
PLAN_ID_PREFIX = "guardian-plan-v1:sha256:"
MAX_OPERATIONS = 32
MAX_EVIDENCE_REFERENCES = 32
MAX_RULE_IDS = 64
MAX_TEXT_LENGTH = 512
MAX_PLAN_LIFETIME = timedelta(hours=1)

PROHIBITED_OPERATIONS = [
    "command-execution",
    "network-access",
    "outside-target-write",
    "symlink-follow",
    "permission-change",
]

_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_PLAN_ID_PATTERN = re.compile(r"guardian-plan-v1:sha256:[0-9a-f]{64}")
_REFERENCE_PATTERN = re.compile(r"(?:finding|uncertainty):\d+")
_RULE_ID_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_SESSION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_TARGET_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


class GuardianPlanError(ValueError):
    """Raised when a remediation plan violates the closed BW2 contract."""


def remediation_plan_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"}
    rule_id = {"type": "string", "pattern": r"^[A-Z][A-Z0-9_]{0,127}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://codex-preflight.local/schemas/guardian-remediation-plan-v1.schema.json",
        "title": "Codex Preflight Guardian Remediation Plan v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schemaVersion",
            "planId",
            "source",
            "target",
            "operations",
            "prohibitedOperations",
            "verification",
            "expectedImprovement",
            "evidenceReferences",
            "validity",
        ],
        "properties": {
            "schemaVersion": {"const": SCHEMA_VERSION},
            "planId": {
                "type": "string",
                "pattern": r"^guardian-plan-v1:sha256:[0-9a-f]{64}$",
            },
            "source": {
                "type": "object",
                "additionalProperties": False,
                "required": ["reportDigest", "commandDigest", "originalDecision"],
                "properties": {
                    "reportDigest": digest,
                    "commandDigest": digest,
                    "originalDecision": {"enum": ["ALLOW", "WARN", "ASK_USER", "BLOCK"]},
                },
            },
            "target": {
                "type": "object",
                "additionalProperties": False,
                "required": ["isolation", "targetId", "rootDigest"],
                "properties": {
                    "isolation": {"const": "required"},
                    "targetId": {
                        "type": "string",
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                    },
                    "rootDigest": digest,
                },
            },
            "operations": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_OPERATIONS,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "operationId",
                        "kind",
                        "path",
                        "preimageDigest",
                        "postimageDigest",
                    ],
                    "properties": {
                        "operationId": {
                            "type": "string",
                            "pattern": r"^operation:\d+$",
                        },
                        "kind": {"enum": ["create-file", "replace-file", "delete-file"]},
                        "path": {"type": "string", "minLength": 1, "maxLength": 512},
                        "preimageDigest": {
                            "oneOf": [digest, {"const": "absent"}],
                        },
                        "postimageDigest": {
                            "oneOf": [digest, {"const": "absent"}],
                        },
                    },
                },
            },
            "prohibitedOperations": {
                "type": "array",
                "prefixItems": [{"const": item} for item in PROHIBITED_OPERATIONS],
                "items": False,
                "minItems": len(PROHIBITED_OPERATIONS),
                "maxItems": len(PROHIBITED_OPERATIONS),
            },
            "verification": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "commandDigest",
                    "acceptableDecisions",
                    "maximumRiskScore",
                    "requiredAbsentRuleIds",
                    "requireNoNewBlockingFindings",
                ],
                "properties": {
                    "commandDigest": digest,
                    "acceptableDecisions": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 2,
                        "uniqueItems": True,
                        "items": {"enum": ["ALLOW", "WARN"]},
                    },
                    "maximumRiskScore": {"type": "integer", "minimum": 0, "maximum": 100},
                    "requiredAbsentRuleIds": {
                        "type": "array",
                        "maxItems": MAX_RULE_IDS,
                        "uniqueItems": True,
                        "items": rule_id,
                    },
                    "requireNoNewBlockingFindings": {"const": True},
                },
            },
            "expectedImprovement": {
                "type": "object",
                "additionalProperties": False,
                "required": ["summary", "removedRuleIds", "remainingRiskStatement"],
                "properties": {
                    "summary": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_LENGTH},
                    "removedRuleIds": {
                        "type": "array",
                        "maxItems": MAX_RULE_IDS,
                        "uniqueItems": True,
                        "items": rule_id,
                    },
                    "remainingRiskStatement": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_TEXT_LENGTH,
                    },
                },
            },
            "evidenceReferences": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_EVIDENCE_REFERENCES,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "pattern": r"^(?:finding|uncertainty):\d+$",
                },
            },
            "validity": {
                "type": "object",
                "additionalProperties": False,
                "required": ["sessionId", "createdAt", "expiresAt"],
                "properties": {
                    "sessionId": {
                        "type": "string",
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                    },
                    "createdAt": {"type": "string", "format": "date-time"},
                    "expiresAt": {"type": "string", "format": "date-time"},
                },
            },
        },
    }


def build_remediation_plan(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise GuardianPlanError("plan payload must be an object")
    if "planId" in payload:
        raise GuardianPlanError("plan payload must not provide planId")
    plan = dict(payload)
    plan["planId"] = f"{PLAN_ID_PREFIX}{'0' * 64}"
    _validate_structure(plan)
    plan["planId"] = compute_plan_id(plan)
    return validate_remediation_plan(plan)


def canonical_plan_bytes(plan: object) -> bytes:
    value = _validate_structure(plan)
    payload = {key: item for key, item in value.items() if key != "planId"}
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise GuardianPlanError("plan contains a non-canonical JSON value") from exc
    return encoded.encode("utf-8")


def compute_plan_id(plan: object) -> str:
    digest = hashlib.sha256(canonical_plan_bytes(plan)).hexdigest()
    return f"{PLAN_ID_PREFIX}{digest}"


def validate_remediation_plan(plan: object) -> dict[str, Any]:
    value = _validate_structure(plan)
    expected = compute_plan_id(value)
    if value["planId"] != expected:
        raise GuardianPlanError("planId does not match the complete canonical plan")
    return value


def _validate_structure(plan: object) -> dict[str, Any]:
    value = _object(plan, "plan")
    _exact_keys(
        value,
        {
            "schemaVersion",
            "planId",
            "source",
            "target",
            "operations",
            "prohibitedOperations",
            "verification",
            "expectedImprovement",
            "evidenceReferences",
            "validity",
        },
        "plan",
    )
    if value["schemaVersion"] != SCHEMA_VERSION:
        raise GuardianPlanError("schemaVersion is invalid")
    if not isinstance(value["planId"], str) or not _PLAN_ID_PATTERN.fullmatch(value["planId"]):
        raise GuardianPlanError("planId is invalid")

    source = _object(value["source"], "source")
    _exact_keys(source, {"reportDigest", "commandDigest", "originalDecision"}, "source")
    _digest(source["reportDigest"], "source.reportDigest")
    _digest(source["commandDigest"], "source.commandDigest")
    if source["originalDecision"] not in {"ALLOW", "WARN", "ASK_USER", "BLOCK"}:
        raise GuardianPlanError("source.originalDecision is invalid")

    target = _object(value["target"], "target")
    _exact_keys(target, {"isolation", "targetId", "rootDigest"}, "target")
    if target["isolation"] != "required":
        raise GuardianPlanError("target.isolation must be required")
    _pattern_text(target["targetId"], "target.targetId", _TARGET_ID_PATTERN)
    _digest(target["rootDigest"], "target.rootDigest")

    operations = value["operations"]
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_OPERATIONS:
        raise GuardianPlanError("operations must be a non-empty bounded list")
    seen_paths: set[str] = set()
    for index, operation_value in enumerate(operations):
        operation = _object(operation_value, f"operations[{index}]")
        _exact_keys(
            operation,
            {"operationId", "kind", "path", "preimageDigest", "postimageDigest"},
            f"operations[{index}]",
        )
        if operation["operationId"] != f"operation:{index}":
            raise GuardianPlanError("operationId must match the exact operation order")
        kind = operation["kind"]
        if kind not in {"create-file", "replace-file", "delete-file"}:
            raise GuardianPlanError("operation kind is invalid")
        path = _relative_path(operation["path"])
        if path in seen_paths:
            raise GuardianPlanError("operation paths must be unique")
        seen_paths.add(path)
        preimage = operation["preimageDigest"]
        postimage = operation["postimageDigest"]
        _digest_or_absent(preimage, f"operations[{index}].preimageDigest")
        _digest_or_absent(postimage, f"operations[{index}].postimageDigest")
        if kind == "create-file" and (preimage != "absent" or postimage == "absent"):
            raise GuardianPlanError("create-file digest contract is invalid")
        if kind == "replace-file" and (preimage == "absent" or postimage == "absent"):
            raise GuardianPlanError("replace-file digest contract is invalid")
        if kind == "delete-file" and (preimage == "absent" or postimage != "absent"):
            raise GuardianPlanError("delete-file digest contract is invalid")

    if value["prohibitedOperations"] != PROHIBITED_OPERATIONS:
        raise GuardianPlanError("prohibitedOperations must match the fixed safety boundary")

    verification = _object(value["verification"], "verification")
    _exact_keys(
        verification,
        {
            "commandDigest",
            "acceptableDecisions",
            "maximumRiskScore",
            "requiredAbsentRuleIds",
            "requireNoNewBlockingFindings",
        },
        "verification",
    )
    _digest(verification["commandDigest"], "verification.commandDigest")
    if verification["commandDigest"] != source["commandDigest"]:
        raise GuardianPlanError("verification.commandDigest must match source.commandDigest")
    decisions = verification["acceptableDecisions"]
    if (
        not isinstance(decisions, list)
        or not 1 <= len(decisions) <= 2
        or len(set(decisions)) != len(decisions)
        or any(item not in {"ALLOW", "WARN"} for item in decisions)
    ):
        raise GuardianPlanError("verification.acceptableDecisions is invalid")
    _integer(verification["maximumRiskScore"], "verification.maximumRiskScore", 0, 100)
    _rule_ids(verification["requiredAbsentRuleIds"], "verification.requiredAbsentRuleIds")
    if verification["requireNoNewBlockingFindings"] is not True:
        raise GuardianPlanError("verification.requireNoNewBlockingFindings must be true")

    improvement = _object(value["expectedImprovement"], "expectedImprovement")
    _exact_keys(improvement, {"summary", "removedRuleIds", "remainingRiskStatement"}, "expectedImprovement")
    _bounded_text(improvement["summary"], "expectedImprovement.summary")
    _rule_ids(improvement["removedRuleIds"], "expectedImprovement.removedRuleIds")
    _bounded_text(improvement["remainingRiskStatement"], "expectedImprovement.remainingRiskStatement")

    references = value["evidenceReferences"]
    if (
        not isinstance(references, list)
        or not 1 <= len(references) <= MAX_EVIDENCE_REFERENCES
        or len(set(references)) != len(references)
        or any(not isinstance(item, str) or not _REFERENCE_PATTERN.fullmatch(item) for item in references)
    ):
        raise GuardianPlanError("evidenceReferences is invalid")

    validity = _object(value["validity"], "validity")
    _exact_keys(validity, {"sessionId", "createdAt", "expiresAt"}, "validity")
    _pattern_text(validity["sessionId"], "validity.sessionId", _SESSION_ID_PATTERN)
    created_at = _timestamp(validity["createdAt"], "validity.createdAt")
    expires_at = _timestamp(validity["expiresAt"], "validity.expiresAt")
    if expires_at <= created_at:
        raise GuardianPlanError("validity.expiresAt must be after createdAt")
    if expires_at - created_at > MAX_PLAN_LIFETIME:
        raise GuardianPlanError("plan validity exceeds the one-hour maximum")
    return value


def _object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GuardianPlanError(f"{field} must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        raise GuardianPlanError(
            f"{field} fields are invalid; missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}"
        )


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise GuardianPlanError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _digest_or_absent(value: object, field: str) -> str:
    if value == "absent":
        return value
    return _digest(value, field)


def _pattern_text(value: object, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise GuardianPlanError(f"{field} is invalid")
    return value


def _bounded_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT_LENGTH:
        raise GuardianPlanError(f"{field} must be non-empty and at most {MAX_TEXT_LENGTH} characters")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise GuardianPlanError(f"{field} contains a control character")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise GuardianPlanError(f"{field} must be an integer from {minimum} to {maximum}")
    return value


def _rule_ids(value: object, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_RULE_IDS
        or len(set(value)) != len(value)
        or any(not isinstance(item, str) or not _RULE_ID_PATTERN.fullmatch(item) for item in value)
    ):
        raise GuardianPlanError(f"{field} is invalid")
    return value


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise GuardianPlanError("operation path is invalid")
    if "\\" in value or value.startswith("/") or "\x00" in value:
        raise GuardianPlanError("operation path must be a relative POSIX path")
    path = PurePosixPath(value)
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts):
        raise GuardianPlanError("operation path is not canonical")
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GuardianPlanError(f"{field} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GuardianPlanError(f"{field} must be an RFC 3339 UTC timestamp") from exc
    if parsed.utcoffset() != timedelta(0):
        raise GuardianPlanError(f"{field} must use UTC")
    return parsed
