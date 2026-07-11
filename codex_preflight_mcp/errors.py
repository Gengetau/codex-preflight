from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class McpErrorCode(StrEnum):
    CWD_REQUIRED = "MCP_CWD_REQUIRED"
    CWD_EMPTY = "MCP_CWD_EMPTY"
    CWD_URL_NOT_ALLOWED = "MCP_CWD_URL_NOT_ALLOWED"
    CWD_FILE_NOT_DIRECTORY = "MCP_CWD_FILE_NOT_DIRECTORY"
    CWD_NOT_FOUND = "MCP_CWD_NOT_FOUND"
    CWD_PERMISSION_DENIED = "MCP_CWD_PERMISSION_DENIED"
    CWD_INVALID = "MCP_CWD_INVALID"
    COMMAND_REQUIRED = "MCP_COMMAND_REQUIRED"
    FORMAT_UNSUPPORTED = "MCP_FORMAT_UNSUPPORTED"
    ARGUMENT_UNSUPPORTED = "MCP_ARGUMENT_UNSUPPORTED"
    CASE_NOT_FOUND = "MCP_CASE_NOT_FOUND"
    REMOTE_DISABLED = "MCP_REMOTE_DISABLED"
    REMOTE_URL_INVALID = "MCP_REMOTE_URL_INVALID"
    REMOTE_HOST_NOT_ALLOWED = "MCP_REMOTE_HOST_NOT_ALLOWED"
    REMOTE_ADDRESS_NOT_ALLOWED = "MCP_REMOTE_ADDRESS_NOT_ALLOWED"
    REMOTE_REF_INVALID = "MCP_REMOTE_REF_INVALID"
    REMOTE_CONFIRMATION_REQUIRED = "MCP_REMOTE_CONFIRMATION_REQUIRED"
    REMOTE_CONFIRMATION_INVALID = "MCP_REMOTE_CONFIRMATION_INVALID"
    REMOTE_CONFIRMATION_EXPIRED = "MCP_REMOTE_CONFIRMATION_EXPIRED"
    REMOTE_CONFIRMATION_REPLAYED = "MCP_REMOTE_CONFIRMATION_REPLAYED"
    REMOTE_REF_NOT_FOUND = "MCP_REMOTE_REF_NOT_FOUND"
    REMOTE_REDIRECT_NOT_ALLOWED = "MCP_REMOTE_REDIRECT_NOT_ALLOWED"
    REMOTE_AUTH_NOT_ALLOWED = "MCP_REMOTE_AUTH_NOT_ALLOWED"
    REMOTE_TIMEOUT = "MCP_REMOTE_TIMEOUT"
    REMOTE_CANCELLED = "MCP_REMOTE_CANCELLED"
    REMOTE_LIMIT_EXCEEDED = "MCP_REMOTE_LIMIT_EXCEEDED"
    REMOTE_TREE_UNSAFE = "MCP_REMOTE_TREE_UNSAFE"
    REMOTE_ACQUISITION_FAILED = "MCP_REMOTE_ACQUISITION_FAILED"
    REMOTE_SCAN_FAILED = "MCP_REMOTE_SCAN_FAILED"
    REMOTE_CACHE_FAILED = "MCP_REMOTE_CACHE_FAILED"
    REMOTE_CLEANUP_FAILED = "MCP_REMOTE_CLEANUP_FAILED"
    INTERNAL_ERROR = "MCP_INTERNAL_ERROR"


@dataclass(frozen=True)
class McpErrorDetail:
    code: McpErrorCode
    message: str
    remediation: str
    retryable: bool
    field: str | None = None
    safety_boundary: str | None = None
    context: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        detail = {
            "code": self.code.value,
            "message": self.message,
            "remediation": self.remediation,
            "retryable": self.retryable,
            "field": self.field,
            "safetyBoundary": self.safety_boundary,
        }
        if self.context is not None:
            detail["context"] = self.context
        return detail


class McpToolError(ValueError):
    """Expected MCP failure serialized into a stable machine-readable message."""

    def __init__(self, detail: McpErrorDetail) -> None:
        self.detail = detail
        super().__init__(json.dumps({"error": detail.to_dict()}, separators=(",", ":"), sort_keys=True))

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.detail.to_dict()}
