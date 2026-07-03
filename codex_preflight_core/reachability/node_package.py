import json
from dataclasses import dataclass
from pathlib import Path

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepack", "postpack"}


@dataclass(frozen=True)
class PackageScript:
    package_file: Path
    name: str
    command: str


def package_scripts(package_file: Path, names: set[str]) -> list[PackageScript]:
    try:
        data = json.loads(package_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return []
    relative = Path(package_file.name) if not package_file.is_absolute() else package_file
    return [
        PackageScript(relative, name, command)
        for name, command in scripts.items()
        if name in names and isinstance(command, str)
    ]
