from enum import StrEnum


class CommandScope(StrEnum):
    DEPENDENCY_INSTALL = "dependency_install"
    SCRIPT_EXECUTION = "script_execution"
    BUILD = "build"
    TEST = "test"
    DOCKER = "docker"
    NETWORK_SHELL = "network_shell"
    MCP_SERVER_START = "mcp_server_start"
    UNKNOWN_SHELL = "unknown_shell"
    SAFE_READONLY = "safe_readonly"
