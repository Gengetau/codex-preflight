from pathlib import Path

import pytest

from codex_preflight_core.command.classifier import CommandClassification, classify_command
from codex_preflight_core.command.scope import CommandScope
from codex_preflight_core.policy.engine import evaluate_policy
from codex_preflight_core.policy.explanation import build_policy_explanation
from codex_preflight_core.preflight import run_preflight
from codex_preflight_core.report.markdown_renderer import render_markdown_report
from codex_preflight_core.scanner.finding import Finding, Severity


def finding(rule_id: str, severity: Severity, file: str = "fixture.txt") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="Synthetic finding",
        file=file,
        line=1,
        evidence="untrusted evidence",
        why_it_matters="Exercises policy explanation.",
        recommendation="Review the finding.",
    )


@pytest.mark.parametrize("scope", list(CommandScope))
def test_policy_explanation_records_every_command_scope(scope: CommandScope) -> None:
    findings = [finding("RUST_CARGO_ALIAS", Severity.LOW)]
    classification = CommandClassification("synthetic", scope, "Synthetic scope.")
    policy = evaluate_policy(findings, classification)

    explanation = build_policy_explanation(findings, classification, policy)

    assert explanation["finalDecision"] == "WARN"
    assert explanation["commandScope"] == scope.value
    assert explanation["selectedBy"] == {
        "type": "policy_matrix",
        "decision": "WARN",
        "ruleId": "RUST_CARGO_ALIAS",
    }
    assert explanation["ruleContributions"] == [
        {
            "ruleId": "RUST_CARGO_ALIAS",
            "findingCount": 1,
            "riskScore": 3,
            "matrixMatched": True,
            "minimumDecision": "WARN",
            "hardBlock": False,
            "rationale": "Cargo aliases can hide additional subcommands.",
            "affectedFinalGate": True,
            "reportOnly": False,
        }
    ]


def test_policy_explanation_distinguishes_score_and_report_only_contributions() -> None:
    findings = [
        finding("UNMAPPED_HIGH", Severity.HIGH, "high.txt"),
        finding("UNMAPPED_INFO", Severity.INFO, "info.txt"),
    ]
    classification = classify_command("pytest")
    policy = evaluate_policy(findings, classification)

    explanation = build_policy_explanation(findings, classification, policy)

    assert explanation["selectedBy"] == {
        "type": "risk_score",
        "decision": "ASK_USER",
        "ruleId": None,
    }
    assert explanation["commandContribution"] == {
        "riskScore": 25,
        "minimumDecision": "ASK_USER",
        "affectedFinalGate": True,
    }
    contributions = {item["ruleId"]: item for item in explanation["ruleContributions"]}
    assert contributions["UNMAPPED_HIGH"]["affectedFinalGate"] is True
    assert contributions["UNMAPPED_HIGH"]["reportOnly"] is False
    assert contributions["UNMAPPED_INFO"]["affectedFinalGate"] is False
    assert contributions["UNMAPPED_INFO"]["reportOnly"] is True


def test_policy_explanation_selects_hard_block_rule_deterministically() -> None:
    findings = [
        finding("SECRET_PRIVATE_KEY", Severity.CRITICAL, "key.pem"),
        finding("COMMAND_REMOTE_SHELL_PIPE", Severity.CRITICAL, "<command>"),
    ]
    classification = classify_command("bash setup.sh")
    policy = evaluate_policy(findings, classification)

    explanation = build_policy_explanation(findings, classification, policy)

    assert explanation["selectedBy"] == {
        "type": "hard_block_rule",
        "decision": "BLOCK",
        "ruleId": "COMMAND_REMOTE_SHELL_PIPE",
    }
    assert [item["ruleId"] for item in explanation["ruleContributions"]] == [
        "COMMAND_REMOTE_SHELL_PIPE",
        "SECRET_PRIVATE_KEY",
    ]


def test_json_and_markdown_reports_explain_policy_without_changing_existing_fields(tmp_path: Path) -> None:
    (tmp_path / ".cargo").mkdir()
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    (tmp_path / ".cargo" / "config.toml").write_text(
        '[source.crates-io]\nreplace-with = "mirror"\n'
        '[source.mirror]\nregistry = "https://example.com/index"\n'
        '[alias]\nci = "test --all"\n',
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "cargo build", use_cache=False)
    markdown = render_markdown_report(report)

    assert report["decision"] == "WARN"
    assert report["commandScope"] == "build"
    assert report["policyExplanation"]["finalDecision"] == "WARN"
    assert [item["ruleId"] for item in report["policyExplanation"]["ruleContributions"]] == [
        "RUST_CARGO_ALIAS",
        "RUST_CARGO_SOURCE_REPLACEMENT",
    ]
    assert "## Policy Explanation" in markdown
    assert "RUST_CARGO_ALIAS" in markdown
    assert "policy_matrix" in markdown
