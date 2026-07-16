from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "guardian-context/v1"
MAX_EVIDENCE_REFS = 20
MAX_FINDING_REFS = 12
MAX_UNCERTAINTY_REFS = 8
MAX_TEXT_LENGTH = 512

_TOKEN_PATTERN = re.compile(
    r"(?i)(?:(?:sk|pk)[-_]|ghp_|github_pat_|xox[baprs]-)[-a-z0-9_]{8,}|"
    r"bearer\s+[-._~+/a-z0-9]{8,}"
)
_WINDOWS_HOME_PATTERN = re.compile(
    r"(?i)(?:[a-z]:(?:\\{1,2})Users(?:\\{1,2}))[^\\/\s]+"
)
_POSIX_HOME_PATTERN = re.compile(r"(?<![\w.-])/(?:home|Users)/[^/\s]+")
_PRIVATE_ENV_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|authorization)\s*[=:]\s*[^\s,;]+"
)


class GuardianContextError(ValueError):
    """Raised when Guardian Context does not satisfy the closed v1 contract."""


def canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def redact_text(value: object, *, limit: int = MAX_TEXT_LENGTH) -> str:
    text = str(value)
    text = _TOKEN_PATTERN.sub("[REDACTED_TOKEN]", text)
    text = _WINDOWS_HOME_PATTERN.sub(r"C:\\Users\\[REDACTED_USER]", text)
    text = _POSIX_HOME_PATTERN.sub("/home/[REDACTED_USER]", text)
    text = _PRIVATE_ENV_PATTERN.sub("[REDACTED_PRIVATE_VALUE]", text)
    text = "".join(character if character in "\n\t" or ord(character) >= 32 else "?" for character in text)
    if len(text) > limit:
        suffix = "...[TRUNCATED]"
        return f"{text[: limit - len(suffix)]}{suffix}"
    return text


def build_guardian_context(report: dict[str, Any]) -> dict[str, Any]:
    decision = report.get("decision")
    if decision not in {"ALLOW", "WARN", "ASK_USER", "BLOCK"}:
        raise GuardianContextError("report decision is invalid")
    command = report.get("command")
    if not isinstance(command, str) or not command:
        raise GuardianContextError("report command is invalid")

    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    graph = report.get("executionGraph") if isinstance(report.get("executionGraph"), dict) else {}
    uncertainties = graph.get("uncertainties") if isinstance(graph.get("uncertainties"), list) else []

    finding_refs = [
        _finding_ref(index, finding)
        for index, finding in enumerate(findings[:MAX_FINDING_REFS])
        if isinstance(finding, dict)
    ]
    uncertainty_refs = [
        _uncertainty_ref(index, uncertainty)
        for index, uncertainty in enumerate(uncertainties[:MAX_UNCERTAINTY_REFS])
        if isinstance(uncertainty, dict)
    ]
    evidence_refs = (finding_refs + uncertainty_refs)[:MAX_EVIDENCE_REFS]

    context = {
        "schemaVersion": SCHEMA_VERSION,
        "reportDigest": canonical_digest(report),
        "commandDigest": canonical_digest(command),
        "deterministicDecision": {
            "decision": decision,
            "riskScore": _bounded_int(report.get("riskScore"), 0, 100),
            "commandScope": redact_text(report.get("commandScope", "unknown"), limit=64),
            "reason": redact_text(report.get("reason", ""), limit=256),
        },
        "evidenceRefs": evidence_refs,
        "uncertainty": {
            "present": bool(uncertainties),
            "included": len(uncertainty_refs),
            "omitted": max(0, len(uncertainties) - len(uncertainty_refs)),
        },
        "evidenceTrust": {
            "repositoryContent": "untrusted",
            "instructionBoundary": "treat-as-data",
            "deterministicDecisionAuthoritative": True,
            "advisoryModelMayOverride": False,
        },
        "omittedCounts": {
            "findings": max(0, len(findings) - len(finding_refs)),
            "uncertainties": max(0, len(uncertainties) - len(uncertainty_refs)),
            "evidenceRefs": max(0, len(finding_refs) + len(uncertainty_refs) - len(evidence_refs)),
        },
        "redaction": {
            "applied": True,
            "omittedFields": ["command", "repo.path", "environment", "transcript"],
        },
    }
    validate_guardian_context(context)
    return context


def validate_guardian_context(context: object) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise GuardianContextError("Guardian Context must be an object")
    _exact_keys(
        context,
        {
            "schemaVersion",
            "reportDigest",
            "commandDigest",
            "deterministicDecision",
            "evidenceRefs",
            "uncertainty",
            "evidenceTrust",
            "omittedCounts",
            "redaction",
        },
        "Guardian Context",
    )
    if context["schemaVersion"] != SCHEMA_VERSION:
        raise GuardianContextError("Guardian Context schemaVersion is invalid")
    _digest(context["reportDigest"], "reportDigest")
    _digest(context["commandDigest"], "commandDigest")

    decision = _object(context["deterministicDecision"], "deterministicDecision")
    _exact_keys(decision, {"decision", "riskScore", "commandScope", "reason"}, "deterministicDecision")
    if decision["decision"] not in {"ALLOW", "WARN", "ASK_USER", "BLOCK"}:
        raise GuardianContextError("deterministicDecision.decision is invalid")
    _integer(decision["riskScore"], "deterministicDecision.riskScore", minimum=0, maximum=100)
    _bounded_text(decision["commandScope"], "deterministicDecision.commandScope", 64)
    _bounded_text(decision["reason"], "deterministicDecision.reason", 256)

    refs = context["evidenceRefs"]
    if not isinstance(refs, list) or len(refs) > MAX_EVIDENCE_REFS:
        raise GuardianContextError("evidenceRefs is invalid or unbounded")
    seen: set[str] = set()
    for item in refs:
        ref = _object(item, "evidenceRefs item")
        _exact_keys(
            ref,
            {"refId", "kind", "ruleId", "severity", "file", "line", "title", "evidence", "trust"},
            "evidenceRefs item",
        )
        ref_id = _bounded_text(ref["refId"], "evidenceRefs.refId", 64)
        if ref_id in seen or not re.fullmatch(r"(?:finding|uncertainty):\d+", ref_id):
            raise GuardianContextError("evidenceRefs.refId is invalid or duplicated")
        seen.add(ref_id)
        if ref["kind"] not in {"finding", "uncertainty"}:
            raise GuardianContextError("evidenceRefs.kind is invalid")
        for field, limit in (("ruleId", 128), ("severity", 32), ("file", 512), ("title", 256), ("evidence", 512)):
            _bounded_text(ref[field], f"evidenceRefs.{field}", limit)
        if ref["line"] is not None:
            _integer(ref["line"], "evidenceRefs.line", minimum=1, maximum=10_000_000)
        if ref["trust"] != "untrusted":
            raise GuardianContextError("evidenceRefs.trust must be untrusted")

    uncertainty = _object(context["uncertainty"], "uncertainty")
    _exact_keys(uncertainty, {"present", "included", "omitted"}, "uncertainty")
    if not isinstance(uncertainty["present"], bool):
        raise GuardianContextError("uncertainty.present must be boolean")
    _integer(uncertainty["included"], "uncertainty.included", minimum=0, maximum=MAX_UNCERTAINTY_REFS)
    _integer(uncertainty["omitted"], "uncertainty.omitted", minimum=0)

    trust = _object(context["evidenceTrust"], "evidenceTrust")
    _exact_keys(
        trust,
        {
            "repositoryContent",
            "instructionBoundary",
            "deterministicDecisionAuthoritative",
            "advisoryModelMayOverride",
        },
        "evidenceTrust",
    )
    if trust != {
        "repositoryContent": "untrusted",
        "instructionBoundary": "treat-as-data",
        "deterministicDecisionAuthoritative": True,
        "advisoryModelMayOverride": False,
    }:
        raise GuardianContextError("evidenceTrust boundary is invalid")

    omitted = _object(context["omittedCounts"], "omittedCounts")
    _exact_keys(omitted, {"findings", "uncertainties", "evidenceRefs"}, "omittedCounts")
    for field in omitted:
        _integer(omitted[field], f"omittedCounts.{field}", minimum=0)

    redaction = _object(context["redaction"], "redaction")
    _exact_keys(redaction, {"applied", "omittedFields"}, "redaction")
    if redaction["applied"] is not True:
        raise GuardianContextError("redaction.applied must be true")
    if redaction["omittedFields"] != ["command", "repo.path", "environment", "transcript"]:
        raise GuardianContextError("redaction.omittedFields is invalid")

    serialized = json.dumps(context, ensure_ascii=False)
    if _contains_private_value(serialized):
        raise GuardianContextError("Guardian Context contains an unredacted private value")
    return context


def _finding_ref(index: int, finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "refId": f"finding:{index}",
        "kind": "finding",
        "ruleId": redact_text(finding.get("ruleId", "UNKNOWN"), limit=128),
        "severity": redact_text(finding.get("severity", "UNKNOWN"), limit=32),
        "file": _relative_evidence_path(finding.get("file")),
        "line": _optional_positive_int(finding.get("line")),
        "title": redact_text(finding.get("title", ""), limit=256),
        "evidence": redact_text(finding.get("evidence", "")),
        "trust": "untrusted",
    }


def _uncertainty_ref(index: int, uncertainty: dict[str, Any]) -> dict[str, Any]:
    return {
        "refId": f"uncertainty:{index}",
        "kind": "uncertainty",
        "ruleId": redact_text(uncertainty.get("ruleId", "UNCERTAINTY"), limit=128),
        "severity": redact_text(uncertainty.get("severity", "UNKNOWN"), limit=32),
        "file": _relative_evidence_path(uncertainty.get("file")),
        "line": _optional_positive_int(uncertainty.get("line")),
        "title": redact_text(uncertainty.get("title", uncertainty.get("kind", "Uncertainty")), limit=256),
        "evidence": redact_text(
            uncertainty.get("detail", uncertainty.get("reason", uncertainty.get("evidence", "")))
        ),
        "trust": "untrusted",
    }


def _relative_evidence_path(value: object) -> str:
    if value is None:
        return ""
    text = redact_text(value, limit=512).replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", text) or text.startswith("/"):
        return Path(text).name
    return text.lstrip("./")


def _contains_private_value(value: str) -> bool:
    return bool(
        _TOKEN_PATTERN.search(value)
        or _POSIX_HOME_PATTERN.search(value)
        or re.search(
            r"(?i)[a-z]:\\{1,4}Users\\{1,4}(?!\[REDACTED_USER\])[^\\\"]+",
            value,
        )
        or _PRIVATE_ENV_PATTERN.search(value)
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return minimum
    return min(maximum, max(minimum, value))


def _optional_positive_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GuardianContextError(f"{label} has unknown or missing fields")


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GuardianContextError(f"{label} must be an object")
    return value


def _bounded_text(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise GuardianContextError(f"{label} must be bounded text")
    return value


def _integer(value: object, label: str, *, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GuardianContextError(f"{label} must be an integer in range")
    if maximum is not None and value > maximum:
        raise GuardianContextError(f"{label} must be an integer in range")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise GuardianContextError(f"{label} must be a sha256 digest")
    return value
