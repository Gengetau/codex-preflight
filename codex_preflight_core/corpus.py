from collections import defaultdict
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
        "groups": _group_results(results),
    }


def render_corpus_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Codex Preflight Corpus Scan",
        "",
        f"Overall result: {'pass' if result['passed'] else 'fail'}",
        "",
    ]
    for group in result.get("groups", _group_results(result["cases"])):
        lines.extend(
            [
                f"## Category: {group['category']}",
                "",
                "| Case | Negative control | Expected | Actual | Expected rules | Actual rules | Result |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for case in group["cases"]:
            status = "pass" if case["passed"] else "fail"
            expected_rules = ", ".join(case["expectedRules"]) or "none"
            actual_rules = ", ".join(case["actualRules"]) or "none"
            lines.append(
                "| {id} | {negative} | {expected} | {actual} | {expected_rules} | {actual_rules} | {status} |".format(
                    id=case["id"],
                    negative="yes" if case["negativeControl"] else "no",
                    expected=case["expectedDecision"],
                    actual=case["actualDecision"],
                    expected_rules=expected_rules,
                    actual_rules=actual_rules,
                    status=status,
                )
            )
        lines.append("")
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
        "negativeControl": case.expected_decision == "ALLOW" and not case.expected_rules,
        "passed": passed,
    }


def _group_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        grouped[str(result["category"])].append(result)
    return [
        {
            "category": category,
            "passed": all(case["passed"] for case in grouped[category]),
            "negativeControls": sum(1 for case in grouped[category] if case["negativeControl"]),
            "cases": sorted(grouped[category], key=lambda case: case["id"]),
        }
        for category in sorted(grouped)
    ]
