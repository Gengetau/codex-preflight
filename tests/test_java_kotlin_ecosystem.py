from pathlib import Path

import pytest

from codex_preflight_core.command.classifier import classify_command
from codex_preflight_core.command.java import parse_java_invocation, split_command_words
from codex_preflight_core.command.scope import CommandScope
from codex_preflight_core.preflight import run_preflight
from codex_preflight_core.repo.collector import collect_critical_files
from codex_preflight_core.repo.fingerprint import compute_critical_fingerprint


def rule_ids(report: dict) -> list[str]:
    return [finding["ruleId"] for finding in report["findings"]]


def capability_ids(report: dict) -> list[str]:
    return [capability["ruleId"] for capability in report["executionGraph"]["capabilities"]]


def graph_files(report: dict) -> set[str]:
    return {node["file"] for node in report["executionGraph"]["nodes"] if node["file"]}


def capability_files(report: dict) -> set[str]:
    return {capability["file"] for capability in report["executionGraph"]["capabilities"]}


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

    report = run_preflight(tmp_path, "./gradlew -I init.gradle.kts build", use_cache=False)

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


def test_gradle_dependency_repository_outside_empty_plugin_management_remains_clean(tmp_path: Path) -> None:
    (tmp_path / "settings.gradle.kts").write_text(
        "pluginManagement { }\n"
        "dependencyResolutionManagement {\n"
        "  repositories { mavenCentral() }\n"
        "}\n",
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


@pytest.mark.parametrize(
    "command",
    ["mvn -f alternate.xml test", "mvn --file alternate.xml test", "mvn --file=alternate.xml test"],
)
def test_maven_alternate_pom_is_collected_scanned_and_reachable(tmp_path: Path, command: str) -> None:
    (tmp_path / "alternate.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><build><plugins><plugin>"
        "<artifactId>exec-maven-plugin</artifactId><executions><execution>"
        "<goals><goal>exec</goal></goals></execution></executions>"
        "</plugin></plugins></build></project>",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, command, use_cache=False)

    assert Path("alternate.xml") in collect_critical_files(tmp_path, command=command)
    assert rule_ids(report) == ["JAVA_MAVEN_PLUGIN_EXECUTION"]
    assert capability_ids(report) == ["JAVA_MAVEN_PLUGIN_EXECUTION"]
    assert graph_files(report) == {"alternate.xml"}


@pytest.mark.parametrize(
    "command",
    [
        "gradle -I config/bootstrap.gradle test",
        "gradle --init-script config/bootstrap.gradle test",
        "gradle --init-script=config/bootstrap.gradle test",
    ],
)
def test_gradle_arbitrary_init_script_is_collected_scanned_and_reachable(
    tmp_path: Path, command: str
) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "bootstrap.gradle").write_text("beforeSettings { }\n", encoding="utf-8")
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert Path("config/bootstrap.gradle") in collect_critical_files(tmp_path, command=command)
    assert rule_ids(report) == ["JAVA_GRADLE_INIT_SCRIPT"]
    assert capability_ids(report) == ["JAVA_GRADLE_INIT_SCRIPT"]
    assert "config/bootstrap.gradle" in graph_files(report)


def test_system_gradle_does_not_reach_repository_init_or_wrapper_files(tmp_path: Path) -> None:
    (tmp_path / "gradle" / "wrapper").mkdir(parents=True)
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    (tmp_path / "init.gradle").write_text("beforeSettings { }\n", encoding="utf-8")
    (tmp_path / "gradlew").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
        "distributionUrl=http\\://example.invalid/gradle.zip\n", encoding="utf-8"
    )

    report = run_preflight(tmp_path, "gradle test", use_cache=False)

    assert graph_files(report) == {"build.gradle"}
    assert capability_files(report) == set()


@pytest.mark.parametrize(
    ("command", "wrapper_name"),
    [("./gradlew test", "gradlew"), (".\\gradlew.bat test", "gradlew.bat")],
)
def test_gradle_wrapper_reaches_only_invoked_wrapper_metadata_not_root_init(
    tmp_path: Path, command: str, wrapper_name: str
) -> None:
    (tmp_path / "gradle" / "wrapper").mkdir(parents=True)
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    (tmp_path / "init.gradle").write_text("beforeSettings { }\n", encoding="utf-8")
    (tmp_path / wrapper_name).write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
        "distributionUrl=http\\://example.invalid/gradle.zip\n", encoding="utf-8"
    )

    report = run_preflight(tmp_path, command, use_cache=False)

    assert {"build.gradle", wrapper_name, "gradle/wrapper/gradle-wrapper.properties"} <= graph_files(report)
    assert "init.gradle" not in graph_files(report)
    assert capability_files(report) == {"gradle/wrapper/gradle-wrapper.properties"}


def test_explicit_gradle_init_reaches_only_the_selected_init_script(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    (tmp_path / "init.gradle").write_text("beforeSettings { }\n", encoding="utf-8")
    (tmp_path / "config" / "bootstrap.gradle").write_text("beforeSettings { }\n", encoding="utf-8")

    report = run_preflight(tmp_path, "gradle -I config/bootstrap.gradle test", use_cache=False)

    assert "config/bootstrap.gradle" in graph_files(report)
    assert "init.gradle" not in graph_files(report)
    assert capability_files(report) == {"config/bootstrap.gradle"}


@pytest.mark.parametrize(
    "command",
    ['mvn -f "dir/my pom.xml" test', 'mvn --file="dir/my pom.xml" test'],
)
def test_quoted_maven_pom_is_classified_collected_scanned_fingerprinted_and_reachable(
    tmp_path: Path, command: str
) -> None:
    target = tmp_path / "dir" / "my pom.xml"
    target.parent.mkdir()
    target.write_text(
        "<project><modelVersion>4.0.0</modelVersion><build><plugins><plugin>"
        "<artifactId>exec-maven-plugin</artifactId><executions><execution>"
        "<goals><goal>exec</goal></goals></execution></executions>"
        "</plugin></plugins></build></project>",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, command, use_cache=False)
    before = compute_critical_fingerprint(tmp_path, command=command)
    target.write_text(target.read_text(encoding="utf-8") + "\n<!-- fingerprint change -->\n", encoding="utf-8")

    invocation = parse_java_invocation(split_command_words(command))
    assert invocation is not None and invocation.maven_files == ("dir/my pom.xml",)
    assert classify_command(command).scope == CommandScope.TEST
    assert report["decision"] == "WARN"
    assert Path("dir/my pom.xml") in collect_critical_files(tmp_path, command=command)
    assert "JAVA_MAVEN_PLUGIN_EXECUTION" in rule_ids(report)
    assert graph_files(report) == {"dir/my pom.xml"}
    assert capability_files(report) == {"dir/my pom.xml"}
    assert compute_critical_fingerprint(tmp_path, command=command) != before


@pytest.mark.parametrize(
    "command",
    [
        'gradle -I "config/my init.gradle" test',
        'gradle --init-script="config/my init.gradle" test',
    ],
)
def test_quoted_gradle_init_is_classified_collected_scanned_fingerprinted_and_reachable(
    tmp_path: Path, command: str
) -> None:
    target = tmp_path / "config" / "my init.gradle"
    target.parent.mkdir()
    target.write_text("beforeSettings { }\n", encoding="utf-8")
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")

    report = run_preflight(tmp_path, command, use_cache=False)
    before = compute_critical_fingerprint(tmp_path, command=command)
    target.write_text("beforeSettings { println('changed') }\n", encoding="utf-8")

    invocation = parse_java_invocation(split_command_words(command))
    assert invocation is not None and invocation.gradle_init_scripts == ("config/my init.gradle",)
    assert classify_command(command).scope == CommandScope.TEST
    assert report["decision"] == "WARN"
    assert Path("config/my init.gradle") in collect_critical_files(tmp_path, command=command)
    assert "JAVA_GRADLE_INIT_SCRIPT" in rule_ids(report)
    assert {"build.gradle", "config/my init.gradle"} <= graph_files(report)
    assert capability_files(report) == {"config/my init.gradle"}
    assert compute_critical_fingerprint(tmp_path, command=command) != before


@pytest.mark.parametrize(
    ("command", "target_name"),
    [
        ("gradle -c config/custom.gradle test", "config/custom.gradle"),
        ("gradle --settings-file=config/custom.gradle test", "config/custom.gradle"),
        ('gradle -c "config/custom settings.gradle" test', "config/custom settings.gradle"),
    ],
)
def test_gradle_settings_file_is_classified_collected_scanned_fingerprinted_and_reachable(
    tmp_path: Path, command: str, target_name: str
) -> None:
    target = tmp_path / target_name
    target.parent.mkdir(exist_ok=True)
    target.write_text(
        "pluginManagement { repositories { gradlePluginPortal() } }\n",
        encoding="utf-8",
    )
    (target.parent / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    (tmp_path / "settings.gradle").write_text("rootProject.name = 'default'\n", encoding="utf-8")

    report = run_preflight(tmp_path, command, use_cache=False)
    before = compute_critical_fingerprint(tmp_path, command=command)
    target.write_text(target.read_text(encoding="utf-8") + "// changed\n", encoding="utf-8")

    invocation = parse_java_invocation(split_command_words(command))
    assert invocation is not None and invocation.gradle_settings_files == (target_name,)
    assert classify_command(command).scope == CommandScope.TEST
    assert report["decision"] == "WARN"
    assert Path(target_name) in collect_critical_files(tmp_path, command=command)
    assert "JAVA_GRADLE_PLUGIN_REPOSITORY" in rule_ids(report)
    assert target_name in graph_files(report)
    assert "settings.gradle" not in graph_files(report)
    assert capability_files(report) == {target_name}
    assert compute_critical_fingerprint(tmp_path, command=command) != before


@pytest.mark.parametrize("command", ["gradle -p sub test", "gradle --project-dir=sub test"])
def test_gradle_project_dir_limits_reachability_to_selected_project(
    tmp_path: Path, command: str
) -> None:
    (tmp_path / "sub" / "buildSrc").mkdir(parents=True)
    (tmp_path / "other").mkdir()
    (tmp_path / "sub" / "settings.gradle").write_text(
        "pluginManagement { repositories { gradlePluginPortal() } }\n", encoding="utf-8"
    )
    (tmp_path / "sub" / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    (tmp_path / "sub" / "buildSrc" / "build.gradle").write_text(
        "plugins { id 'groovy' }\n", encoding="utf-8"
    )
    (tmp_path / "other" / "settings.gradle").write_text(
        "pluginManagement { repositories { mavenCentral() } }\n", encoding="utf-8"
    )
    (tmp_path / "other" / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")

    report = run_preflight(tmp_path, command, use_cache=False)
    invocation = parse_java_invocation(split_command_words(command))

    assert invocation is not None and invocation.gradle_project_dir == "sub"
    assert classify_command(command).scope == CommandScope.TEST
    assert report["decision"] == "WARN"
    assert {
        Path("sub/settings.gradle"),
        Path("sub/build.gradle"),
        Path("sub/buildSrc/build.gradle"),
    } <= set(collect_critical_files(tmp_path, command=command))
    assert {"JAVA_GRADLE_PLUGIN_REPOSITORY", "JAVA_GRADLE_BUILD_LOGIC"} <= set(rule_ids(report))
    assert graph_files(report) == {
        "sub/settings.gradle",
        "sub/build.gradle",
        "sub/buildSrc/build.gradle",
    }
    assert capability_files(report) == {"sub/settings.gradle", "sub/buildSrc/build.gradle"}
    assert not any(path.startswith("other/") for path in graph_files(report))


def test_gradle_project_dir_is_the_base_for_custom_settings_file(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "custom-settings.gradle").write_text(
        "pluginManagement { repositories { gradlePluginPortal() } }\n", encoding="utf-8"
    )
    (tmp_path / "sub" / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    (tmp_path / "custom-settings.gradle").write_text(
        "pluginManagement { repositories { mavenCentral() } }\n", encoding="utf-8"
    )
    command = "gradle -p sub -c custom-settings.gradle test"

    report = run_preflight(tmp_path, command, use_cache=False)

    assert classify_command(command).scope == CommandScope.TEST
    assert report["decision"] == "WARN"
    assert Path("sub/custom-settings.gradle") in collect_critical_files(tmp_path, command=command)
    assert Path("custom-settings.gradle") not in collect_critical_files(tmp_path, command=command)
    assert "JAVA_GRADLE_PLUGIN_REPOSITORY" in rule_ids(report)
    assert graph_files(report) == {"sub/build.gradle", "sub/custom-settings.gradle"}
    assert capability_files(report) == {"sub/custom-settings.gradle"}


@pytest.mark.parametrize(
    "command",
    [
        "gradle -p ../outside-gradle test",
        "gradle -c ../outside-settings.gradle test",
        "gradle -I ../outside-init.gradle test",
    ],
)
def test_gradle_scoped_paths_outside_repository_are_rejected(tmp_path: Path, command: str) -> None:
    outside_project = tmp_path.parent / "outside-gradle"
    outside_project.mkdir(exist_ok=True)
    (outside_project / "settings.gradle").write_text(
        "pluginManagement { repositories { gradlePluginPortal() } }\n", encoding="utf-8"
    )
    (tmp_path.parent / "outside-settings.gradle").write_text(
        "pluginManagement { repositories { gradlePluginPortal() } }\n", encoding="utf-8"
    )
    (tmp_path.parent / "outside-init.gradle").write_text("beforeSettings { }\n", encoding="utf-8")

    report = run_preflight(tmp_path, command, use_cache=False)

    assert classify_command(command).scope == CommandScope.TEST
    assert report["decision"] == "ALLOW"
    assert rule_ids(report) == []
    assert collect_critical_files(tmp_path, command=command) == []
    assert graph_files(report) == set()
    assert capability_files(report) == set()


def test_gradle_scoped_symlink_targets_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real-settings.gradle"
    real.write_text(
        "pluginManagement { repositories { gradlePluginPortal() } }\n", encoding="utf-8"
    )
    linked = tmp_path / "linked-settings.gradle"
    try:
        linked.symlink_to(real)
    except OSError:
        pytest.skip("File symlinks are unavailable in this environment")
    command = "gradle -c linked-settings.gradle test"

    report = run_preflight(tmp_path, command, use_cache=False)

    assert classify_command(command).scope == CommandScope.TEST
    assert report["decision"] == "ALLOW"
    assert Path("linked-settings.gradle") not in collect_critical_files(tmp_path, command=command)
    assert rule_ids(report) == []
    assert graph_files(report) == set()
    assert capability_files(report) == set()
