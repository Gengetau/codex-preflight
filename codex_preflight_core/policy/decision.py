from dataclasses import dataclass
from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    ASK_USER = "ASK_USER"
    BLOCK = "BLOCK"


EXIT_CODES = {
    Decision.ALLOW: 0,
    Decision.WARN: 10,
    Decision.ASK_USER: 20,
    Decision.BLOCK: 30,
}


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    risk_score: int
    reason: str
    agent_instruction: str
