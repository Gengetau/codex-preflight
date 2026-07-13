import json
import tomllib
from pathlib import Path

from codex_preflight_core import __version__ as core_version
from codex_preflight_core.command.classifier import classify_command
from codex_preflight_core.command.scope import CommandScope
from codex_preflight_core.preflight import RULESET_VERSION, run_preflight
from codex_preflight_core.repo.collector import collect_critical_files
from codex_preflight_mcp import __version__ as mcp_version

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.7"
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
    assert RULESET_VERSION == "2026.07.13.2"


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
    assert "## v0.3.6" in history
    assert "does not run Maven, Gradle, wrappers" in history


def test_v036_corpus_pins_active_and_clean_java_kotlin_surfaces() -> None:
    active = ROOT / "case_corpus/java-kotlin-maven-gradle"
    clean = ROOT / "case_corpus/java-kotlin-clean-minimal"

    case = (active / "case.yml").read_text(encoding="utf-8")
    assert 'mvn -f "dir/my pom.xml" test' in case
    assert './gradlew -I "config/my init.gradle" build' in case
    assert "<executions>" in (active / "dir/my pom.xml").read_text(encoding="utf-8")
    assert "beforeSettings" in (active / "config/my init.gradle").read_text(encoding="utf-8")
    report = run_preflight(
        active,
        'mvn -f "dir/my pom.xml" test && ./gradlew -I "config/my init.gradle" build',
        use_cache=False,
    )
    graph_files = {node["file"] for node in report["executionGraph"]["nodes"] if node["file"]}
    capability_files = {capability["file"] for capability in report["executionGraph"]["capabilities"]}
    assert report["decision"] == "WARN"
    assert {"dir/my pom.xml", "config/my init.gradle"} <= graph_files
    assert {"dir/my pom.xml", "config/my init.gradle"} <= capability_files
    assert "includeBuild" in (active / "settings.gradle.kts").read_text(encoding="utf-8")
    assert "distributionSha256Sum" not in (active / "gradle/wrapper/gradle-wrapper.properties").read_text(
        encoding="utf-8"
    )
    assert "distributionSha256Sum" in (clean / "gradle/wrapper/gradle-wrapper.properties").read_text(
        encoding="utf-8"
    )


def test_v036_release_gate_pins_gradle_project_and_settings_scope(tmp_path: Path) -> None:
    (tmp_path / "sub" / "buildSrc").mkdir(parents=True)
    (tmp_path / "other").mkdir()
    (tmp_path / "sub" / "custom-settings.gradle").write_text(
        "pluginManagement { repositories { gradlePluginPortal() } }\n", encoding="utf-8"
    )
    (tmp_path / "sub" / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    (tmp_path / "sub" / "buildSrc" / "build.gradle").write_text(
        "plugins { id 'groovy' }\n", encoding="utf-8"
    )
    (tmp_path / "other" / "settings.gradle").write_text(
        "pluginManagement { repositories { mavenCentral() } }\n", encoding="utf-8"
    )
    command = "gradle -p sub -c custom-settings.gradle test"

    report = run_preflight(tmp_path, command, use_cache=False)
    files = {node["file"] for node in report["executionGraph"]["nodes"] if node["file"]}
    capabilities = {item["file"] for item in report["executionGraph"]["capabilities"]}

    assert classify_command(command).scope == CommandScope.TEST
    assert report["decision"] == "WARN"
    assert Path("sub/custom-settings.gradle") in collect_critical_files(tmp_path, command=command)
    assert "JAVA_GRADLE_PLUGIN_REPOSITORY" in {
        finding["ruleId"] for finding in report["findings"]
    }
    assert files == {
        "sub/build.gradle",
        "sub/buildSrc/build.gradle",
        "sub/custom-settings.gradle",
    }
    assert capabilities == {"sub/buildSrc/build.gradle", "sub/custom-settings.gradle"}
