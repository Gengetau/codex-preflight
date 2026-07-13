import json
import tomllib
from pathlib import Path

from codex_preflight_core import __version__ as core_version
from codex_preflight_core.preflight import RULESET_VERSION
from codex_preflight_mcp import __version__ as mcp_version

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.6"
JAVA_KOTLIN_RULE_IDS = {
    "JAVA_MAVEN_PLUGIN_EXECUTION",
    "JAVA_GRADLE_PLUGIN_REPOSITORY",
    "JAVA_GRADLE_INIT_SCRIPT",
    "JAVA_GRADLE_BUILD_LOGIC",
    "JAVA_GRADLE_WRAPPER_INTEGRITY",
}


def test_v036_version_sources_and_ruleset_are_aligned() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    root_plugin = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    marketplace_plugin = json.loads(
        (ROOT / ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json").read_text(encoding="utf-8")
    )

    assert project["project"]["version"] == VERSION
    assert core_version == VERSION
    assert mcp_version == VERSION
    assert root_plugin["version"] == VERSION
    assert marketplace_plugin["version"] == VERSION
    assert RULESET_VERSION == "2026.07.13"


def test_v036_documentation_names_java_kotlin_coverage_and_static_boundary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    rules = (ROOT / "docs/rules.md").read_text(encoding="utf-8")
    corpus = (ROOT / "docs/case-corpus.md").read_text(encoding="utf-8")
    history = (ROOT / "docs/release-history.md").read_text(encoding="utf-8")

    for rule_id in JAVA_KOTLIN_RULE_IDS:
        assert rule_id in rules
    assert "Java" in readme and "Kotlin" in readme and "Maven" in readme and "Gradle" in readme
    assert "java-kotlin-maven-gradle" in corpus
    assert "java-kotlin-clean-minimal" in corpus
    assert history.startswith("# Release History\n\n## v0.3.6")
    assert "does not run Maven, Gradle, wrappers" in history


def test_v036_corpus_pins_active_and_clean_java_kotlin_surfaces() -> None:
    active = ROOT / "case_corpus/java-kotlin-maven-gradle"
    clean = ROOT / "case_corpus/java-kotlin-clean-minimal"

    assert "<executions>" in (active / "pom.xml").read_text(encoding="utf-8")
    assert "includeBuild" in (active / "settings.gradle.kts").read_text(encoding="utf-8")
    assert "distributionSha256Sum" not in (active / "gradle/wrapper/gradle-wrapper.properties").read_text(
        encoding="utf-8"
    )
    assert "distributionSha256Sum" in (clean / "gradle/wrapper/gradle-wrapper.properties").read_text(
        encoding="utf-8"
    )
