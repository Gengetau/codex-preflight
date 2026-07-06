from dataclasses import asdict, dataclass
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    file: str
    line: int
    evidence: str
    why_it_matters: str
    recommendation: str

    def to_report(self) -> dict[str, object]:
        data = asdict(self)
        data["ruleId"] = data.pop("rule_id")
        data["whyItMatters"] = data.pop("why_it_matters")
        data["severity"] = self.severity.value
        data.update(evidence_metadata(self.rule_id, self.file, self.title))
        return data


def evidence_metadata(rule_id: str, file: str | None, title: str | None = None) -> dict[str, str]:
    if file == "<command>":
        source = "command-string"
    elif rule_id.startswith("SECRET_"):
        source = "redacted-secret"
    elif rule_id.startswith("AGENT_"):
        source = "fixed-rule-phrase"
    elif title == "Reachability uncertainty detected":
        source = "tool-generated"
    else:
        source = "repository-content"
    return {
        "evidenceSource": source,
        "evidenceTrust": "untrusted",
        "evidenceInstructionBoundary": "treat-as-data",
    }
