from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from codex_preflight_core.preflight import run_preflight

DEFAULT_CORPUS_ROOT = Path(__file__).resolve().parents[1] / "case_corpus"


@dataclass(frozen=True)
class CorpusCase:
    id: str
    title: str
    category: str
    command: str
    expected_decision: str
    expected_rules: list[str]
    description: str
    safety_note: str
    path: Path


def load_cases(root: Path = DEFAULT_CORPUS_ROOT) -> list[CorpusCase]:
    cases = [load_case(path.parent) for path in sorted(root.glob("*/case.yml"))]
    return sorted(cases, key=lambda case: case.id)


def load_case(path: Path) -> CorpusCase:
    data = yaml.safe_load((path / "case.yml").read_text(encoding="utf-8"))
    return CorpusCase(
        id=str(data["id"]),
        title=str(data["title"]),
        category=str(data["category"]),
        command=str(data["command"]),
        expected_decision=str(data["expectedDecision"]),
        expected_rules=list(data["expectedRules"]),
        description=str(data["description"]),
        safety_note=str(data["safetyNote"]),
        path=path,
    )


def scan_corpus(case_id: str | None = None, root: Path = DEFAULT_CORPUS_ROOT) -> dict[str, Any]:
    cases = load_cases(root)
    if case_id:
        cases = [case for case in cases if case.id == case_id]
        if not cases:
            raise ValueError(f"Unknown corpus case: {case_id}")
    results = [_scan_case(case) for case in cases]
    return {
        "passed": all(result["passed"] for result in results),
        "cases": results,
    }


def render_corpus_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Codex Preflight Corpus Scan",
        "",
        "| Case | Actual | Expected | Result |",
        "| --- | --- | --- | --- |",
    ]
    for case in result["cases"]:
        status = "pass" if case["passed"] else "fail"
        lines.append(
            f"| {case['id']} | {case['actualDecision']} | {case['expectedDecision']} | {status} |"
        )
    return "\n".join(lines) + "\n"


def _scan_case(case: CorpusCase) -> dict[str, Any]:
    report = run_preflight(case.path, case.command, use_cache=False)
    actual_rules = [finding["ruleId"] for finding in report["findings"]]
    passed = report["decision"] == case.expected_decision and actual_rules == case.expected_rules
    return {
        "id": case.id,
        "title": case.title,
        "category": case.category,
        "command": case.command,
        "expectedDecision": case.expected_decision,
        "actualDecision": report["decision"],
        "expectedRules": case.expected_rules,
        "actualRules": actual_rules,
        "passed": passed,
    }
