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
    INTERNAL_ERROR = "MCP_INTERNAL_ERROR"


@dataclass(frozen=True)
class McpErrorDetail:
    code: McpErrorCode
    message: str
    remediation: str
    retryable: bool
    field: str | None = None
    safety_boundary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "remediation": self.remediation,
            "retryable": self.retryable,
            "field": self.field,
            "safetyBoundary": self.safety_boundary,
        }


class McpToolError(ValueError):
    """Expected MCP failure serialized into a stable machine-readable message."""

    def __init__(self, detail: McpErrorDetail) -> None:
        self.detail = detail
        super().__init__(json.dumps({"error": detail.to_dict()}, separators=(",", ":"), sort_keys=True))

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.detail.to_dict()}
