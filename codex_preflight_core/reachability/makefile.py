from pathlib import Path


def make_targets(relative_path: Path, text: str) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    current: str | None = None
    commands: list[str] = []
    for line in text.splitlines():
        if line and not line.startswith(("\t", " ")) and ":" in line:
            if current and commands:
                targets.append((current, "\n".join(commands)))
            current = line.split(":", 1)[0].strip()
            commands = []
        elif current and line.startswith(("\t", " ")):
            commands.append(line.strip())
    if current and commands:
        targets.append((current, "\n".join(commands)))
    _ = relative_path
    return targets
