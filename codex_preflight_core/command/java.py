from collections.abc import Sequence
from dataclasses import dataclass

MAVEN_VALUE_OPTIONS = {
    "-f",
    "--file",
    "-s",
    "--settings",
    "-gs",
    "--global-settings",
    "-t",
    "--toolchains",
    "-P",
    "--activate-profiles",
    "-T",
    "--threads",
    "-pl",
    "--projects",
    "-rf",
    "--resume-from",
}

GRADLE_VALUE_OPTIONS = {
    "-p",
    "--project-dir",
    "-c",
    "--settings-file",
    "-I",
    "--init-script",
    "-g",
    "--gradle-user-home",
    "--project-cache-dir",
    "--include-build",
    "--max-workers",
    "--priority",
    "--warning-mode",
    "--console",
    "--configuration-cache-problems",
    "--dependency-verification",
    "--write-verification-metadata",
}


@dataclass(frozen=True)
class JavaInvocation:
    kind: str
    executable: str
    task: str
    maven_files: tuple[str, ...] = ()
    gradle_init_scripts: tuple[str, ...] = ()
    gradle_project_dir: str | None = None
    gradle_settings_files: tuple[str, ...] = ()
    uses_gradle_wrapper: bool = False


def split_command_words(command: str) -> list[str]:
    words: list[str] = []
    current: list[str] = []
    quote: str | None = None
    word_started = False
    for char in command:
        if quote is not None:
            if char == quote:
                quote = None
            else:
                current.append(char)
            word_started = True
            continue
        if char in {"'", '"'}:
            quote = char
            word_started = True
            continue
        if char.isspace():
            if word_started:
                words.append("".join(current))
                current.clear()
                word_started = False
            continue
        current.append(char)
        word_started = True
    if word_started:
        words.append("".join(current))
    return words


def parse_java_invocation(parts: Sequence[str]) -> JavaInvocation | None:
    if not parts:
        return None
    cleaned = list(parts)
    executable = cleaned[0]
    basename = executable.lower().replace("\\", "/").rsplit("/", 1)[-1]
    arguments = cleaned[1:]
    if basename in {"mvn", "mvnw", "mvnw.cmd"}:
        return JavaInvocation(
            kind="maven",
            executable=executable,
            task=_first_task(arguments, MAVEN_VALUE_OPTIONS, "package").lower(),
            maven_files=_option_values(arguments, {"-f", "--file"}),
        )
    if basename in {"gradle", "gradlew", "gradlew.bat"}:
        return JavaInvocation(
            kind="gradle",
            executable=executable,
            task=_first_task(arguments, GRADLE_VALUE_OPTIONS, "build").lower(),
            gradle_init_scripts=_option_values(arguments, {"-I", "--init-script"}),
            gradle_project_dir=_last_option_value(arguments, {"-p", "--project-dir"}),
            gradle_settings_files=_option_values(arguments, {"-c", "--settings-file"}),
            uses_gradle_wrapper=basename in {"gradlew", "gradlew.bat"},
        )
    return None


def _first_task(parts: Sequence[str], value_options: set[str], default: str) -> str:
    index = 0
    while index < len(parts):
        part = parts[index]
        if part == "--":
            return parts[index + 1] if index + 1 < len(parts) else default
        option_name = part.split("=", 1)[0]
        if option_name in value_options:
            index += 1 if "=" in part else 2
            continue
        if part.startswith("-"):
            index += 1
            continue
        return part
    return default


def _option_values(parts: Sequence[str], option_names: set[str]) -> tuple[str, ...]:
    values: list[str] = []
    index = 0
    while index < len(parts):
        part = parts[index]
        option_name, separator, inline_value = part.partition("=")
        if option_name not in option_names:
            index += 1
            continue
        if separator:
            if inline_value:
                values.append(inline_value)
            index += 1
            continue
        if index + 1 < len(parts):
            values.append(parts[index + 1])
        index += 2
    return tuple(values)


def _last_option_value(parts: Sequence[str], option_names: set[str]) -> str | None:
    values = _option_values(parts, option_names)
    return values[-1] if values else None
