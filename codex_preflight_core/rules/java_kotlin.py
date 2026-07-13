import re
import xml.etree.ElementTree as ET
from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity

JAVA_KOTLIN_RULE_IDS = (
    "JAVA_MAVEN_PLUGIN_EXECUTION",
    "JAVA_GRADLE_PLUGIN_REPOSITORY",
    "JAVA_GRADLE_INIT_SCRIPT",
    "JAVA_GRADLE_BUILD_LOGIC",
    "JAVA_GRADLE_WRAPPER_INTEGRITY",
)

_GRADLE_FILES = {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}
_INIT_FILES = {"init.gradle", "init.gradle.kts"}
_PLUGIN_MANAGEMENT = re.compile(r"\bpluginManagement\s*\{")
_REPOSITORIES = re.compile(r"\brepositories\s*\{")
_PLUGIN_REPOSITORY = re.compile(r"\b(?:maven|ivy|gradlePluginPortal|mavenCentral|google)\s*(?:\{|\()")
_INCLUDED_BUILD = re.compile(r"\bincludeBuild(?:\s*\(|[ \t]+(?=\r?$))", re.MULTILINE)


class JavaKotlinEcosystemRule:
    rule_ids = JAVA_KOTLIN_RULE_IDS

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        del root
        if relative_path.name == "pom.xml":
            return _scan_pom(relative_path, text)
        if relative_path.name in _GRADLE_FILES:
            return _scan_gradle_file(relative_path, text)
        if relative_path.name in _INIT_FILES:
            return [_init_script_finding(relative_path)]
        if relative_path.name == "gradle-wrapper.properties":
            return _scan_wrapper_properties(relative_path, text)
        return []


def _scan_pom(relative_path: Path, text: str) -> list[Finding]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    for plugin in _executed_maven_plugins(root):
        executions = next((child for child in plugin if _local_name(child.tag) == "executions"), None)
        if executions is None or not any(_local_name(child.tag) == "execution" for child in executions):
            continue
        group_id = _child_text(plugin, "groupId") or "org.apache.maven.plugins"
        artifact_id = _child_text(plugin, "artifactId") or "unknown-plugin"
        goals = [
            (goal.text or "").strip()
            for goal in plugin.iter()
            if _local_name(goal.tag) == "goal" and (goal.text or "").strip()
        ]
        evidence = f"{group_id}:{artifact_id}"
        if goals:
            evidence = f"{evidence} goals={','.join(goals)}"
        return [
            _finding(
                "JAVA_MAVEN_PLUGIN_EXECUTION",
                relative_path,
                line_number(text, artifact_id),
                evidence,
                "Maven plugin execution configured",
                "Maven lifecycle phases can execute repository-selected plugin goals.",
                "Review Maven plugin executions before running Maven build or test commands.",
            )
        ]
    return []


def _executed_maven_plugins(root: ET.Element) -> list[ET.Element]:
    plugins: list[ET.Element] = []
    for build in (element for element in root.iter() if _local_name(element.tag) == "build"):
        for collection in (child for child in build if _local_name(child.tag) == "plugins"):
            plugins.extend(child for child in collection if _local_name(child.tag) == "plugin")
    return plugins


def _scan_gradle_file(relative_path: Path, text: str) -> list[Finding]:
    code = _mask_gradle_comments_and_strings(text)
    findings: list[Finding] = []
    if (
        relative_path.name in {"settings.gradle", "settings.gradle.kts"}
        and _PLUGIN_MANAGEMENT.search(code)
        and _REPOSITORIES.search(code)
        and _PLUGIN_REPOSITORY.search(code)
    ):
        findings.append(
            _finding(
                "JAVA_GRADLE_PLUGIN_REPOSITORY",
                relative_path,
                line_number(text, "pluginManagement"),
                "pluginManagement repositories",
                "Gradle plugin repository configuration detected",
                "Plugin repositories control where Gradle resolves executable build plugins.",
                "Review Gradle plugin repositories before running Gradle commands.",
            )
        )
    is_build_src = "buildSrc" in relative_path.parts
    if is_build_src or _INCLUDED_BUILD.search(code):
        evidence = "buildSrc build logic" if is_build_src else "includeBuild(...)"
        findings.append(
            _finding(
                "JAVA_GRADLE_BUILD_LOGIC",
                relative_path,
                1 if is_build_src else line_number(text, "includeBuild"),
                evidence,
                "Gradle included or buildSrc logic detected",
                "Gradle build logic can compile and execute repository-controlled code during configuration.",
                "Inspect included Gradle build logic before running Gradle commands.",
            )
        )
    return findings


def _init_script_finding(relative_path: Path) -> Finding:
    return _finding(
        "JAVA_GRADLE_INIT_SCRIPT",
        relative_path,
        1,
        relative_path.as_posix(),
        "Gradle init script detected",
        "Gradle init scripts can alter repositories, plugins, and task behavior before a build runs.",
        "Inspect Gradle init scripts before running Gradle commands.",
    )


def _scan_wrapper_properties(relative_path: Path, text: str) -> list[Finding]:
    properties = _properties(text)
    distribution_url = properties.get("distributionUrl")
    if not distribution_url:
        return []
    checksum = properties.get("distributionSha256Sum", "")
    secure_url = distribution_url.lower().startswith("https\\://") or distribution_url.lower().startswith("https://")
    valid_checksum = bool(re.fullmatch(r"[0-9a-fA-F]{64}", checksum))
    if secure_url and valid_checksum:
        return []
    reasons: list[str] = []
    if not secure_url:
        reasons.append("distributionUrl is not HTTPS")
    if not valid_checksum:
        reasons.append("distributionSha256Sum is missing or invalid")
    return [
        _finding(
            "JAVA_GRADLE_WRAPPER_INTEGRITY",
            relative_path,
            line_number(text, "distributionUrl"),
            "; ".join(reasons),
            "Gradle wrapper integrity indicator requires review",
            "An unpinned or insecure Gradle distribution weakens wrapper provenance guarantees.",
            "Use an HTTPS Gradle distribution URL and pin its 64-character SHA-256 checksum.",
        )
    ]


def _properties(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _mask_gradle_comments_and_strings(text: str) -> str:
    masked: list[str] = []
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            masked.append("\n" if char == "\n" else " ")
            line_comment = char != "\n"
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                masked.extend("  ")
                block_comment = False
                index += 2
            else:
                masked.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            masked.append("\n" if char == "\n" else " ")
            index += 1
            continue
        if char == "/" and next_char == "/":
            masked.extend("  ")
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            masked.extend("  ")
            block_comment = True
            index += 2
            continue
        if char in {"'", '"'}:
            quote = char
            masked.append(" ")
            index += 1
            continue
        masked.append(char)
        index += 1
    return "".join(masked)


def _child_text(element: ET.Element, name: str) -> str | None:
    child = next((item for item in element if _local_name(item.tag) == name), None)
    value = (child.text or "").strip() if child is not None else ""
    return value or None


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _finding(
    rule_id: str,
    relative_path: Path,
    line: int,
    evidence: str,
    title: str,
    why_it_matters: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.LOW,
        title=title,
        file=relative_path.as_posix(),
        line=line,
        evidence=evidence[:160],
        why_it_matters=why_it_matters,
        recommendation=recommendation,
    )
