from pathlib import Path

from codex_preflight_core.preflight import run_preflight


def rule_ids(report: dict) -> list[str]:
    return [finding["ruleId"] for finding in report["findings"]]


def capability_ids(report: dict) -> list[str]:
    return [capability["ruleId"] for capability in report["executionGraph"]["capabilities"]]


def graph_files(report: dict) -> set[str]:
    return {node["file"] for node in report["executionGraph"]["nodes"] if node["file"]}


def test_maven_build_reaches_plugin_execution_metadata(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
        "<modelVersion>4.0.0</modelVersion>"
        "<groupId>example</groupId><artifactId>demo</artifactId><version>1</version>"
        "<build><plugins><plugin>"
        "<groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId>"
        "<executions><execution><goals><goal>exec</goal></goals></execution></executions>"
        "</plugin></plugins></build></project>",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "./mvnw package", use_cache=False)

    assert report["decision"] == "WARN"
    assert rule_ids(report) == ["JAVA_MAVEN_PLUGIN_EXECUTION"]
    assert capability_ids(report) == ["JAVA_MAVEN_PLUGIN_EXECUTION"]
    assert "pom.xml" in graph_files(report)


def test_gradle_build_reaches_plugin_init_build_logic_and_wrapper_metadata(tmp_path: Path) -> None:
    (tmp_path / "buildSrc").mkdir()
    (tmp_path / "gradle" / "wrapper").mkdir(parents=True)
    (tmp_path / "build.gradle.kts").write_text('plugins { java }\n', encoding="utf-8")
    (tmp_path / "buildSrc" / "build.gradle.kts").write_text('plugins { `kotlin-dsl` }\n', encoding="utf-8")
    (tmp_path / "settings.gradle.kts").write_text(
        "pluginManagement { repositories { gradlePluginPortal() } }\n"
        'includeBuild("build-logic")\n',
        encoding="utf-8",
    )
    (tmp_path / "init.gradle.kts").write_text("beforeSettings { }\n", encoding="utf-8")
    (tmp_path / "gradlew").write_text("#!/bin/sh\n# inert fixture\n", encoding="utf-8")
    (tmp_path / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
        "distributionUrl=http\\://example.invalid/gradle.zip\n",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "./gradlew build", use_cache=False)

    expected = {
        "JAVA_GRADLE_PLUGIN_REPOSITORY",
        "JAVA_GRADLE_INIT_SCRIPT",
        "JAVA_GRADLE_BUILD_LOGIC",
        "JAVA_GRADLE_WRAPPER_INTEGRITY",
    }
    assert report["decision"] == "WARN"
    assert expected <= set(rule_ids(report))
    assert expected <= set(capability_ids(report))
    assert {
        "build.gradle.kts",
        "buildSrc/build.gradle.kts",
        "settings.gradle.kts",
        "init.gradle.kts",
        "gradlew",
        "gradle/wrapper/gradle-wrapper.properties",
    } <= graph_files(report)


def test_clean_maven_and_gradle_metadata_allows_gradle_test(tmp_path: Path) -> None:
    (tmp_path / "gradle" / "wrapper").mkdir(parents=True)
    (tmp_path / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion>"
        "<groupId>example</groupId><artifactId>clean</artifactId><version>1</version></project>",
        encoding="utf-8",
    )
    (tmp_path / "build.gradle.kts").write_text('plugins { java }\n', encoding="utf-8")
    (tmp_path / "settings.gradle.kts").write_text('rootProject.name = "clean"\n', encoding="utf-8")
    (tmp_path / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.10-bin.zip\n"
        f"distributionSha256Sum={'a' * 64}\n",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, ".\\gradlew.bat test", use_cache=False)

    assert report["decision"] == "ALLOW"
    assert rule_ids(report) == []
    assert capability_ids(report) == []


def test_gradle_comment_and_string_indicators_remain_clean(tmp_path: Path) -> None:
    (tmp_path / "settings.gradle.kts").write_text(
        "// pluginManagement { repositories { maven() } }\n"
        "/* includedBuild(\"disabled\") */\n"
        'val sample = "pluginManagement { repositories { gradlePluginPortal() } }"\n',
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "gradle test", use_cache=False)

    assert report["decision"] == "ALLOW"
    assert rule_ids(report) == []
    assert capability_ids(report) == []


def test_gradle_common_plugin_repository_and_no_parentheses_included_build_are_detected(tmp_path: Path) -> None:
    (tmp_path / "settings.gradle").write_text(
        "pluginManagement { repositories { mavenCentral() } }\n"
        'includeBuild "build-logic"\n',
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "gradle build", use_cache=False)

    assert report["decision"] == "WARN"
    assert rule_ids(report) == ["JAVA_GRADLE_PLUGIN_REPOSITORY", "JAVA_GRADLE_BUILD_LOGIC"]
    assert capability_ids(report) == ["JAVA_GRADLE_PLUGIN_REPOSITORY", "JAVA_GRADLE_BUILD_LOGIC"]


def test_maven_plugin_management_without_active_plugin_execution_remains_clean(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><build><pluginManagement><plugins><plugin>"
        "<artifactId>exec-maven-plugin</artifactId>"
        "<executions><execution><goals><goal>exec</goal></goals></execution></executions>"
        "</plugin></plugins></pluginManagement></build></project>",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "mvn package", use_cache=False)

    assert report["decision"] == "ALLOW"
    assert rule_ids(report) == []
    assert capability_ids(report) == []


def test_malformed_pom_is_ignored_safely(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project><plugin><executions>", encoding="utf-8")

    report = run_preflight(tmp_path, "mvn test", use_cache=False)

    assert report["decision"] == "ALLOW"
    assert rule_ids(report) == []
    assert capability_ids(report) == []
