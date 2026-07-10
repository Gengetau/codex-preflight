from __future__ import annotations

from typing import Any

MCP_SCHEMA_VERSION = "1.0"

MCP_SAFETY_METADATA = {
    "analysisMode": "static-only",
    "repositoryContentTrust": "untrusted",
    "evidenceInstructionBoundary": "treat-as-data",
    "commandExecuted": False,
    "networkAccess": False,
    "trustMutationAllowed": False,
    "remoteRepositoryAccess": False,
}


def build_mcp_result(tool_name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Add the stable MCP contract without changing the core CLI report schema."""
    return {
        "mcpSchemaVersion": MCP_SCHEMA_VERSION,
        "tool": tool_name,
        **result,
        "safety": dict(MCP_SAFETY_METADATA),
    }
