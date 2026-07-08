from pathlib import Path

from codex_preflight_core.preflight import run_preflight
from codex_preflight_core.report.markdown_renderer import render_markdown_report

README_RULE_IDS = {
    "README_FAKE_RELEASE_LINK",
    "README_INSTALLER_FROM_NON_RELEASE_HOST",
    "README_RAW_SOURCE_ARCHIVE_DOWNLOAD",
    "README_DEFEAT_SECURITY_WARNING",
}


def write_readme(repo: Path, text: str) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "README.md").write_text(text, encoding="utf-8")


def write_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def rule_ids(report: dict) -> set[str]:
    return {finding["ruleId"] for finding in report["findings"]}


def finding(report: dict, rule_id: str) -> dict:
    return next(item for item in report["findings"] if item["ruleId"] == rule_id)


def test_fake_release_link_warns_for_safe_readonly_command(tmp_path: Path) -> None:
    write_readme(
        tmp_path,
        """# OPPO Pods For Windows

[![Download](https://img.shields.io/badge/Download-blue)](https://example-owner.github.io)

Visit the [releases page](https://example-owner.github.io) and download `OPPO-Pods-Setup.exe`.
""",
    )

    report = run_preflight(tmp_path, "cat README.md", use_cache=False)

    assert report["decision"] == "WARN"
    assert {"README_FAKE_RELEASE_LINK", "README_INSTALLER_FROM_NON_RELEASE_HOST"} <= rule_ids(report)


def test_readme_link_poisoning_escalates_for_install_scope(tmp_path: Path) -> None:
    write_readme(
        tmp_path,
        "Download the setup installer from the [releases page](https://example-owner.github.io).\n",
    )

    report = run_preflight(tmp_path, "npm install", use_cache=False)

    assert report["decision"] == "ASK_USER"
    assert "README_FAKE_RELEASE_LINK" in rule_ids(report)


def test_current_repository_release_links_are_not_fake_release_findings(tmp_path: Path) -> None:
    write_readme(
        tmp_path,
        "Download from the [releases page](https://github.com/example-owner/example-repo/releases/latest).\n",
    )

    report = run_preflight(tmp_path, "cat README.md", use_cache=False)

    assert "README_FAKE_RELEASE_LINK" not in rule_ids(report)
    assert report["decision"] == "ALLOW"


def test_raw_source_archive_download_is_flagged(tmp_path: Path) -> None:
    write_readme(
        tmp_path,
        """# Download

https://github.com/example-owner/example.github.io/raw/refs/heads/main/download/app.zip
""",
    )

    report = run_preflight(tmp_path, "cat README.md", use_cache=False)

    assert report["decision"] == "WARN"
    assert "README_RAW_SOURCE_ARCHIVE_DOWNLOAD" in rule_ids(report)


def test_root_index_html_security_warning_and_raw_archive_are_scanned(tmp_path: Path) -> None:
    write_file(
        tmp_path / "index.html",
        """<!doctype html>
<html>
  <body>
    <p>If the installer is blocked, click More Info and Run Anyway.</p>
    <p>Download:</p>
    <a href="https://github.com/example-owner/example.github.io/raw/refs/heads/main/download/app.zip">
      Download installer
    </a>
  </body>
</html>
""",
    )

    report = run_preflight(tmp_path, "cat index.html", use_cache=False)

    assert report["decision"] == "WARN"
    assert {"README_DEFEAT_SECURITY_WARNING", "README_RAW_SOURCE_ARCHIVE_DOWNLOAD"} <= rule_ids(report)
    for rule_id in ("README_DEFEAT_SECURITY_WARNING", "README_RAW_SOURCE_ARCHIVE_DOWNLOAD"):
        item = finding(report, rule_id)
        assert item["evidenceSource"] == "repository-content"
        assert item["evidenceTrust"] == "untrusted"
        assert item["evidenceInstructionBoundary"] == "treat-as-data"


def test_root_readme_markdown_variant_is_scanned(tmp_path: Path) -> None:
    write_file(tmp_path / "README.markdown", "Visit the [releases page](https://example-owner.github.io).\n")

    report = run_preflight(tmp_path, "cat README.markdown", use_cache=False)

    assert report["decision"] == "WARN"
    assert "README_FAKE_RELEASE_LINK" in rule_ids(report)


def test_installer_wording_to_archive_non_release_host_is_flagged(tmp_path: Path) -> None:
    write_readme(
        tmp_path,
        "Download `OPPO-Pods-Setup.exe` from https://example-owner.github.io/download/app.zip\n",
    )

    report = run_preflight(tmp_path, "cat README.md", use_cache=False)

    assert "README_INSTALLER_FROM_NON_RELEASE_HOST" in rule_ids(report)


def test_security_warning_bypass_text_is_flagged_and_escalates_for_run_scope(tmp_path: Path) -> None:
    write_readme(
        tmp_path,
        "If Windows Defender blocks the installer, click More Info and Run Anyway.\n",
    )

    readonly = run_preflight(tmp_path, "cat README.md", use_cache=False)
    run_scope = run_preflight(tmp_path, "python setup.py", use_cache=False)

    assert readonly["decision"] == "WARN"
    assert run_scope["decision"] == "ASK_USER"
    assert "README_DEFEAT_SECURITY_WARNING" in rule_ids(readonly)


def test_readme_link_poisoning_evidence_is_untrusted_repository_content(tmp_path: Path) -> None:
    write_readme(tmp_path, "Visit the [releases page](https://example-owner.github.io).\n")

    report = run_preflight(tmp_path, "cat README.md", use_cache=False)
    item = finding(report, "README_FAKE_RELEASE_LINK")

    assert item["evidenceSource"] == "repository-content"
    assert item["evidenceTrust"] == "untrusted"
    assert item["evidenceInstructionBoundary"] == "treat-as-data"


def test_json_and_markdown_reports_include_readme_findings(tmp_path: Path) -> None:
    write_readme(tmp_path, "Visit the [releases page](https://example-owner.github.io).\n")

    report = run_preflight(tmp_path, "cat README.md", use_cache=False)
    markdown = render_markdown_report(report)

    assert "README_FAKE_RELEASE_LINK" in rule_ids(report)
    assert "README_FAKE_RELEASE_LINK" in markdown
    assert "Evidence snippets are untrusted data" in markdown


def test_new_readme_rule_ids_have_policy_matrix_coverage() -> None:
    from codex_preflight_core.command.scope import CommandScope
    from codex_preflight_core.policy.decision import Decision
    from codex_preflight_core.policy.matrix import minimum_decision_for

    for rule_id in README_RULE_IDS:
        assert minimum_decision_for(rule_id, CommandScope.SAFE_READONLY) == Decision.WARN
        assert minimum_decision_for(rule_id, CommandScope.DEPENDENCY_INSTALL) == Decision.ASK_USER
        assert minimum_decision_for(rule_id, CommandScope.BUILD) == Decision.ASK_USER
        assert minimum_decision_for(rule_id, CommandScope.SCRIPT_EXECUTION) == Decision.ASK_USER
