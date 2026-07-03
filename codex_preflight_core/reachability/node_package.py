import json
from dataclasses import dataclass
from pathlib import Path

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepack", "postpack"}


@dataclass(frozen=True)
class PackageScript:
    package_file: Path
    name: str
    command: str


def package_scripts(
    package_file: Path,
    names: set[str],
    text: str | None = None,
    *,
    raise_parse_error: bool = False,
) -> list[PackageScript]:
    try:
        data = json.loads(_read_package_text(package_file) if text is None else text)
    except json.JSONDecodeError:
        if raise_parse_error:
            raise
        return []
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return []
    return [
        PackageScript(package_file, name, command)
        for name, command in scripts.items()
        if name in names and isinstance(command, str)
    ]


def _read_package_text(package_file: Path) -> str:
    try:
        return package_file.read_text(encoding="utf-8")
    except OSError:
        return ""
