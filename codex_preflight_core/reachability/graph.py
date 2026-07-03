from dataclasses import asdict, dataclass, field
from pathlib import Path

from codex_preflight_core.scanner.finding import Finding, Severity


@dataclass(frozen=True)
class ExecutionNode:
    id: str
    type: str
    label: str
    file: Path | None = None
    line: int | None = None
    command: str | None = None
    language: str | None = None

    def to_report(self) -> dict[str, object]:
        data = asdict(self)
        data["file"] = self.file.as_posix() if self.file else None
        return data


@dataclass(frozen=True)
class ExecutionEdge:
    from_id: str
    to_id: str
    reason: str

    def to_report(self) -> dict[str, object]:
        return {"from": self.from_id, "to": self.to_id, "reason": self.reason}


@dataclass(frozen=True)
class Capability:
    rule_id: str
    severity: Severity
    file: Path
    line: int
    capability: str
    evidence: str
    recommendation: str

    def to_report(self) -> dict[str, object]:
        return {
            "ruleId": self.rule_id,
            "severity": self.severity.value,
            "file": self.file.as_posix(),
            "line": self.line,
            "capability": self.capability,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }

    def to_finding(self) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Reachable execution capability detected",
            file=self.file.as_posix(),
            line=self.line,
            evidence=self.evidence,
            why_it_matters=f"The planned command can reach {self.capability}.",
            recommendation=self.recommendation,
        )


@dataclass(frozen=True)
class Uncertainty:
    rule_id: str
    severity: Severity
    reason: str
    recommendation: str
    file: Path | None = None

    def to_report(self) -> dict[str, object]:
        return {
            "ruleId": self.rule_id,
            "severity": self.severity.value,
            "file": self.file.as_posix() if self.file else None,
            "reason": self.reason,
            "recommendation": self.recommendation,
        }

    def to_finding(self) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Reachability uncertainty detected",
            file=self.file.as_posix() if self.file else "",
            line=0,
            evidence=self.reason,
            why_it_matters="Unknown execution paths are not safe for automatic execution.",
            recommendation=self.recommendation,
        )


@dataclass
class ExecutionGraph:
    entry_command: str
    nodes: list[ExecutionNode] = field(default_factory=list)
    edges: list[ExecutionEdge] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)
    uncertainties: list[Uncertainty] = field(default_factory=list)

    def to_report(self) -> dict[str, object]:
        return {
            "entryCommand": self.entry_command,
            "nodes": [node.to_report() for node in self.nodes],
            "edges": [edge.to_report() for edge in self.edges],
            "capabilities": [capability.to_report() for capability in self.capabilities],
            "uncertainties": [uncertainty.to_report() for uncertainty in self.uncertainties],
        }

    def to_findings(self) -> list[Finding]:
        return [item.to_finding() for item in self.capabilities] + [
            item.to_finding() for item in self.uncertainties
        ]
