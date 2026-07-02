import json
from typing import Any


def render_markdown_report(report_json: str | dict[str, Any]) -> str:
    report = json.loads(report_json) if isinstance(report_json, str) else report_json
    lines = [
        "# Codex Preflight Report",
        "",
        f"Decision: {report['decision']}",
        f"Risk score: {report['riskScore']}",
        f"Command: `{report['command']}`",
        f"Command scope: `{report['commandScope']}`",
        "",
        "## Recommendation",
        "",
        report["agentInstruction"],
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity, count in report["summary"].items():
        lines.append(f"| {severity.upper()} | {count} |")
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No findings.")
    for finding in report["findings"]:
        lines.extend(
            [
                f"### {finding['ruleId']}",
                "",
                f"- Severity: {finding['severity']}",
                f"- File: `{finding['file']}:{finding['line']}`",
                f"- Evidence: `{finding['evidence']}`",
                f"- Why it matters: {finding['whyItMatters']}",
                f"- Recommendation: {finding['recommendation']}",
                "",
            ]
        )
    lines.extend(
        [
            "## Cache",
            "",
            f"- Used scan cache: {report['cache']['usedScanCache']}",
            f"- Used trust cache: {report['cache']['usedTrustCache']}",
            f"- Cache reason: {report['cache']['cacheReason']}",
        ]
    )
    return "\n".join(lines) + "\n"
