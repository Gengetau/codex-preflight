from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity


class McpConfigRule:
    rule_ids = (
        "MCP_SHELL_COMMAND",
        "MCP_BROAD_FILESYSTEM_ACCESS",
        "MCP_SECRET_ENV_EXPOSURE",
        "MCP_REMOTE_EXEC_ARGUMENTS",
    )

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        _ = root
        normalized = relative_path.as_posix()
        if relative_path.name not in {".mcp.json", "mcp.json"} and not normalized.startswith(".mcp/"):
            return []
        lowered = text.lower()
        findings: list[Finding] = []
        if any(f'"command": "{cmd}"' in lowered for cmd in ("bash", "sh", "powershell", "python", "node")):
            findings.append(self._finding("MCP_SHELL_COMMAND", Severity.HIGH, normalized, text, "command"))
        if any(pattern in lowered for pattern in ("c:\\", '"/"', "/users/", "/home/")):
            findings.append(
                self._finding("MCP_BROAD_FILESYSTEM_ACCESS", Severity.HIGH, normalized, text, "filesystem")
            )
        if any(token in lowered for token in ("api_key", "token", "secret")):
            findings.append(self._finding("MCP_SECRET_ENV_EXPOSURE", Severity.CRITICAL, normalized, text, "env"))
        if any(pattern in lowered for pattern in ("curl", "wget", "rm -rf", "base64")):
            findings.append(
                self._finding("MCP_REMOTE_EXEC_ARGUMENTS", Severity.HIGH, normalized, text, "args")
            )
        return findings

    @staticmethod
    def _finding(rule_id: str, severity: Severity, file: str, text: str, needle: str) -> Finding:
        return Finding(
            rule_id=rule_id,
            severity=severity,
            title="Risky MCP configuration detected",
            file=file,
            line=line_number(text, needle),
            evidence=needle,
            why_it_matters="MCP server commands can expose tools, files, or secrets to agents.",
            recommendation="Inspect MCP config statically before starting any server.",
        )
