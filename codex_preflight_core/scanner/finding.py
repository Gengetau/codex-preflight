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
        return data
