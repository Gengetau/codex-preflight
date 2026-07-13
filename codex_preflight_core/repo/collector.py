import os
import stat
from collections.abc import Callable
from pathlib import Path

from codex_preflight_core.command.classifier import split_shell_segments
from codex_preflight_core.command.java import parse_java_invocation, split_command_words
from codex_preflight_core.repo.safe_path import (
    SafeDirectoryHandle,
    SafePathError,
    local_absolute_path,
    open_directory_handle_nofollow,
    verify_regular_file_nofollow,
)

CRITICAL_BASENAMES = {
    ".env",
    "package.json",
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "poetry.lock",
    "uv.lock",
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "gems.locked",
    "Rakefile",
    "extconf.rb",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "init.gradle",
    "init.gradle.kts",
    "gradlew",
    "gradlew.bat",
    "gradle-wrapper.properties",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "compose.yml",
    "compose.yaml",
    "AGENTS.md",
    "CLAUDE.md",
    ".mcp.json",
    "mcp.json",
    "README.md",
}
ROOT_DOCUMENTATION_BASENAMES = {
    "README",
    "README.md",
    "README.markdown",
    "index.html",
    "index.htm",
}
DOCUMENTATION_PREFIXES = ("docs/", "documentation/")
DOCUMENTATION_SUFFIXES = (".md", ".markdown", ".html", ".htm")
CRITICAL_PREFIXES = (
    ".github/workflows/",
    ".cursor/rules",
    "scripts/",
    "bin/",
    "tools/",
    ".mcp/",
    ".cargo/",
    "gradle/",
    "buildSrc/",
)
SKIP_DIRS = {".git", "node_modules", "vendor", "target", "dist", "build", "__pycache__", ".venv", "venv"}
COMMAND_TARGET_TOOLS = {"bash", "sh", "python", "node", "powershell", "pwsh"}
FIXTURE_MARKER = ".codex-preflight-fixtures"


class CriticalFileCollectionError(OSError):
    pass


class CriticalFileCollectionLimitError(CriticalFileCollectionError):
    pass


def is_critical_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/")
    basename = Path(normalized).name
    return (
        basename in CRITICAL_BASENAMES
        or normalized in ROOT_DOCUMENTATION_BASENAMES
        or _is_bounded_documentation_surface(normalized)
        or normalized.endswith(".go")
        or normalized.endswith(".gemspec")
        or any(normalized.startswith(prefix) for prefix in CRITICAL_PREFIXES)
    )


def _is_bounded_documentation_surface(normalized: str) -> bool:
    return normalized.startswith(DOCUMENTATION_PREFIXES) and normalized.lower().endswith(DOCUMENTATION_SUFFIXES)


def collect_critical_files(
    root: Path,
    command: str | None = None,
    *,
    budget_check: Callable[[], None] | None = None,
    reject_unsafe: bool = False,
    max_files: int | None = None,
) -> list[Path]:
    if max_files is not None and (type(max_files) is not int or max_files < 0):
        raise ValueError("max_files must be a non-negative integer")
    if reject_unsafe:
        return _collect_critical_files_strict(
            root,
            command,
            budget_check=budget_check,
            max_files=max_files,
        )
    _check_budget(budget_check)
    root = root.resolve()
    _check_budget(budget_check)
    collected: set[Path] = set()
    pending = [root]
    while pending:
        _check_budget(budget_check)
        current_path = pending.pop()
        try:
            iterator = os.scandir(current_path)
        except OSError as error:
            if reject_unsafe:
                raise CriticalFileCollectionError("A repository directory is unavailable.") from error
            continue
        with iterator:
            while True:
                _check_budget(budget_check)
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                except OSError as error:
                    if reject_unsafe:
                        raise CriticalFileCollectionError("A repository entry is unavailable.") from error
                    break
                _check_budget(budget_check)
                path = Path(entry.path)
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as error:
                    if reject_unsafe:
                        raise CriticalFileCollectionError("A repository entry is unavailable.") from error
                    continue
                reparse = entry.is_symlink() or _is_reparse(info)
                if reject_unsafe and reparse:
                    raise CriticalFileCollectionError("A repository entry is unsafe.")
                if stat.S_ISDIR(info.st_mode):
                    if entry.name in SKIP_DIRS or reparse:
                        continue
                    if _has_fixture_marker(path, reject_unsafe=reject_unsafe):
                        continue
                    pending.append(path)
                    _check_budget(budget_check)
                    continue

                relative = path.relative_to(root).as_posix()
                if is_critical_path(relative):
                    if not _is_safe_file(root, path, reject_unsafe=reject_unsafe):
                        if reject_unsafe:
                            raise CriticalFileCollectionError("A critical file is unsafe.")
                        continue
                    _add_collected(collected, Path(relative), max_files=max_files)
                _check_budget(budget_check)
    for target in _command_target_files(
        root,
        command,
        budget_check=budget_check,
        reject_unsafe=reject_unsafe,
    ):
        _check_budget(budget_check)
        _add_collected(collected, target, max_files=max_files)
    _check_budget(budget_check)
    return sorted(collected, key=lambda item: item.as_posix())


def _collect_critical_files_strict(
    root: Path,
    command: str | None,
    *,
    budget_check: Callable[[], None] | None,
    max_files: int | None,
) -> list[Path]:
    _check_budget(budget_check)
    try:
        root = local_absolute_path(root)
    except SafePathError as error:
        raise CriticalFileCollectionError("The repository root is unsafe.") from error
    collected: set[Path] = set()
    try:
        with open_directory_handle_nofollow(root) as root_directory:
            pending: list[tuple[Path, SafeDirectoryHandle]] = [(Path(), root_directory)]
            try:
                while pending:
                    _check_budget(budget_check)
                    relative_directory, directory = pending.pop()
                    local_files: list[Path] = []
                    local_directories: list[tuple[Path, SafeDirectoryHandle]] = []
                    marker = False
                    try:
                        with directory.entries() as iterator:
                            for entry in iterator:
                                _check_budget(budget_check)
                                if entry.reparse or stat.S_ISLNK(entry.mode):
                                    raise CriticalFileCollectionError("A repository entry is unsafe.")
                                relative = relative_directory / entry.name
                                if entry.name == FIXTURE_MARKER and relative_directory != Path():
                                    marker = True
                                    continue
                                if stat.S_ISDIR(entry.mode):
                                    if entry.name not in SKIP_DIRS:
                                        local_directories.append((relative, directory.open_child(entry)))
                                    continue
                                if stat.S_ISREG(entry.mode) and is_critical_path(relative.as_posix()):
                                    try:
                                        verify_regular_file_nofollow(root / relative)
                                    except (OSError, SafePathError) as error:
                                        raise CriticalFileCollectionError("A critical file is unsafe.") from error
                                    local_files.append(relative)
                                _check_budget(budget_check)
                        if marker:
                            continue
                        for relative in local_files:
                            _add_collected(collected, relative, max_files=max_files)
                        pending.extend(local_directories)
                        local_directories.clear()
                        _check_budget(budget_check)
                    finally:
                        directory.close()
                        for _relative, child in local_directories:
                            child.close()
            finally:
                for _relative, directory in pending:
                    directory.close()
    except CriticalFileCollectionError:
        raise
    except (FileNotFoundError, SafePathError) as error:
        raise CriticalFileCollectionError("A repository directory is unavailable.") from error
    for target in _command_target_files(
        root,
        command,
        budget_check=budget_check,
        reject_unsafe=True,
    ):
        _check_budget(budget_check)
        _add_collected(collected, target, max_files=max_files)
    _check_budget(budget_check)
    return sorted(collected, key=lambda item: item.as_posix())


def _is_safe_file(root: Path, path: Path, *, reject_unsafe: bool) -> bool:
    if not reject_unsafe:
        if not path.is_file():
            return False
        if path.is_symlink():
            try:
                path.resolve().relative_to(root)
            except (OSError, ValueError):
                return False
        return True
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not _is_reparse(info)
        and info.st_nlink == 1
    )


def _has_fixture_marker(path: Path, *, reject_unsafe: bool) -> bool:
    marker = path / FIXTURE_MARKER
    try:
        info = marker.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        if reject_unsafe:
            raise CriticalFileCollectionError("A fixture marker is unavailable.") from error
        return False
    if reject_unsafe and (stat.S_ISLNK(info.st_mode) or _is_reparse(info)):
        raise CriticalFileCollectionError("A fixture marker is unsafe.")
    return True


def _command_target_files(
    root: Path,
    command: str | None,
    *,
    budget_check: Callable[[], None] | None = None,
    reject_unsafe: bool = False,
) -> list[Path]:
    _check_budget(budget_check)
    if not command:
        return []
    targets: set[Path] = set()
    for segment in split_shell_segments(command):
        _check_budget(budget_check)
        targets.update(
            _command_target_files_for_segment(
                root,
                segment,
                budget_check=budget_check,
                reject_unsafe=reject_unsafe,
            )
        )
    _check_budget(budget_check)
    return sorted(targets, key=lambda item: item.as_posix())


def _command_target_files_for_segment(
    root: Path,
    command: str,
    *,
    budget_check: Callable[[], None] | None = None,
    reject_unsafe: bool = False,
) -> list[Path]:
    _check_budget(budget_check)
    parts = split_command_words(command)
    _check_budget(budget_check)
    invocation = parse_java_invocation(parts)
    if invocation is not None:
        base = root
        if invocation.kind == "gradle" and invocation.gradle_project_dir is not None:
            project_dir = resolve_command_target_directory(
                root,
                invocation.gradle_project_dir,
                reject_unsafe=reject_unsafe,
            )
            if project_dir is None:
                return []
            base = root / project_dir
        raw_targets = invocation.maven_files
        if invocation.kind == "gradle":
            raw_targets = (*invocation.gradle_init_scripts, *invocation.gradle_settings_files)
        targets: list[Path] = []
        for raw_target in raw_targets:
            target = resolve_command_target_file(
                root,
                raw_target,
                base=base,
                budget_check=budget_check,
                reject_unsafe=reject_unsafe,
            )
            if target is not None:
                targets.append(target)
        return targets
    if len(parts) < 2 or parts[0].lower() not in COMMAND_TARGET_TOOLS:
        return []
    target = resolve_command_target_file(
        root,
        parts[1],
        budget_check=budget_check,
        reject_unsafe=reject_unsafe,
    )
    return [target] if target is not None else []


def resolve_command_target_file(
    root: Path,
    raw_target: str,
    *,
    base: Path | None = None,
    budget_check: Callable[[], None] | None = None,
    reject_unsafe: bool = False,
) -> Path | None:
    root = root.resolve()
    base = root if base is None else base
    try:
        base.resolve().relative_to(root)
    except (OSError, ValueError):
        return None
    target = Path(raw_target.replace("\\", "/"))
    if target.is_absolute():
        return None
    lexical_path = base / target
    if reject_unsafe:
        if _has_unsafe_lexical_component(root, lexical_path):
            raise CriticalFileCollectionError("A command target file is unsafe.")
        try:
            path = local_absolute_path(lexical_path)
            relative = path.relative_to(root)
            verify_regular_file_nofollow(path)
        except FileNotFoundError:
            return None
        except ValueError:
            return None
        except SafePathError as error:
            raise CriticalFileCollectionError("A command target file is unsafe.") from error
        return Path(relative.as_posix())

    try:
        path = lexical_path.resolve()
    except OSError:
        return None
    _check_budget(budget_check)
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    if _has_unsafe_lexical_component(root, lexical_path):
        return None
    if _is_safe_file(root, path, reject_unsafe=False):
        return Path(relative.as_posix())
    return None


def resolve_command_target_directory(
    root: Path,
    raw_target: str,
    *,
    base: Path | None = None,
    reject_unsafe: bool = False,
) -> Path | None:
    root = root.resolve()
    base = root if base is None else base
    target = Path(raw_target.replace("\\", "/"))
    if target.is_absolute():
        return None
    lexical_path = base / target
    try:
        path = local_absolute_path(lexical_path) if reject_unsafe else lexical_path.resolve()
        relative = path.relative_to(root)
    except (OSError, SafePathError, ValueError):
        return None
    if _has_unsafe_lexical_component(root, lexical_path):
        if reject_unsafe:
            raise CriticalFileCollectionError("A command target directory is unsafe.")
        return None
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        return None
    if reject_unsafe:
        try:
            with open_directory_handle_nofollow(path):
                pass
        except (OSError, SafePathError) as error:
            raise CriticalFileCollectionError("A command target directory is unsafe.") from error
    return Path(relative.as_posix())


def _has_unsafe_lexical_component(root: Path, lexical_path: Path) -> bool:
    try:
        relative = Path(os.path.relpath(lexical_path, root))
    except ValueError:
        return True
    if relative.parts and relative.parts[0] == "..":
        return True
    current = root
    for part in relative.parts:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            return True
    return False


def _check_budget(check: Callable[[], None] | None) -> None:
    if check is not None:
        check()


def _add_collected(collected: set[Path], path: Path, *, max_files: int | None) -> None:
    collected.add(path)
    if max_files is not None and len(collected) > max_files:
        raise CriticalFileCollectionLimitError("The critical-file limit was exceeded.")


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
