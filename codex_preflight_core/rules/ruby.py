import re
from collections.abc import Iterator
from pathlib import Path

from codex_preflight_core.scanner.finding import Finding, Severity

RUBY_RULE_IDS = (
    "RUBY_BUNDLER_GIT_SOURCE",
    "RUBY_BUNDLER_LOCAL_PATH_SOURCE",
    "RUBY_GEMSPEC_EXTENSION",
    "RUBY_INSTALL_HOOK",
    "RUBY_NATIVE_EXTENSION",
    "RUBY_RAKE_COMMAND_EXEC",
)

_GIT_SOURCE = re.compile(r"(?:\bgit\s*:|\bgithub\s*:|^\s*git\s*\()")
_LOCAL_PATH_SOURCE = re.compile(r"(?:\bpath\s*:|^\s*path\s*\()")
_GIT_BLOCK_SOURCE = re.compile(r"^\s*git\s+['\"]")
_LOCAL_PATH_BLOCK_SOURCE = re.compile(r"^\s*path\s+['\"]")
_GEMSPEC_EXTENSION = re.compile(r"\.extensions?\s*(?:=|<<)")
_INSTALL_HOOK = re.compile(r"\bGem\.(?:pre|post)_(?:install|uninstall)\b")
_RAKE_COMMAND = re.compile(r"(?:^\s*(?:sh|ruby)\s+|\b(?:system|exec|spawn)\s*\(|`[^`]+`)")
_RAKE_COMMAND_NO_PARENS = re.compile(
    r"(?:^\s*|[;=]\s*|\b(?:if|unless|while|until)\s+|\bKernel\.)(?:system|exec|spawn)\s+['\"]"
)


class RubyEcosystemRule:
    rule_ids = RUBY_RULE_IDS

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        del root
        if relative_path.name in {"Gemfile", "Gemfile.lock", "gems.locked"}:
            return _scan_bundler_file(relative_path, text)
        if relative_path.suffix == ".gemspec":
            return _scan_gemspec(relative_path, text)
        if relative_path.name == "Rakefile":
            return _scan_rakefile(relative_path, text)
        if relative_path.name == "extconf.rb":
            return [_native_extension(relative_path, text)]
        return []


def _scan_bundler_file(relative_path: Path, text: str) -> list[Finding]:
    active = list(_active_lines(text))
    if relative_path.name in {"Gemfile.lock", "gems.locked"}:
        git_line = next(((number, line) for number, line in active if line.strip() == "GIT"), None)
        path_line = next(((number, line) for number, line in active if line.strip() == "PATH"), None)
    else:
        git_line = next(
            (
                (number, line)
                for number, line in active
                if _GIT_SOURCE.search(_mask_strings(line))
                or _GIT_BLOCK_SOURCE.search(_mask_string_contents(line))
            ),
            None,
        )
        path_line = next(
            (
                (number, line)
                for number, line in active
                if _LOCAL_PATH_SOURCE.search(_mask_strings(line))
                or _LOCAL_PATH_BLOCK_SOURCE.search(_mask_string_contents(line))
            ),
            None,
        )
    findings: list[Finding] = []
    if git_line:
        findings.append(_source_finding("RUBY_BUNDLER_GIT_SOURCE", relative_path, git_line, "git"))
    if path_line:
        findings.append(_source_finding("RUBY_BUNDLER_LOCAL_PATH_SOURCE", relative_path, path_line, "local path"))
    return findings


def _source_finding(
    rule_id: str,
    relative_path: Path,
    matched: tuple[int, str],
    source_kind: str,
) -> Finding:
    line, evidence = matched
    return Finding(
        rule_id=rule_id,
        severity=Severity.LOW,
        title=f"Bundler {source_kind} gem source detected",
        file=relative_path.as_posix(),
        line=line,
        evidence=evidence.strip()[:160],
        why_it_matters=f"Bundler {source_kind} sources change dependency provenance and resolution.",
        recommendation=f"Review the Bundler {source_kind} source before running Bundler or Rake commands.",
    )


def _scan_gemspec(relative_path: Path, text: str) -> list[Finding]:
    active = list(_active_lines(text))
    findings: list[Finding] = []
    extension = next(
        ((number, line) for number, line in active if _GEMSPEC_EXTENSION.search(_mask_strings(line))),
        None,
    )
    if extension:
        findings.append(
            _finding(
                "RUBY_GEMSPEC_EXTENSION",
                relative_path,
                extension,
                "Ruby gemspec declares native extensions",
                "Gemspec extensions can execute extconf and compiler toolchains during installation.",
                "Review declared gem extensions before installing or building the gem.",
            )
        )
    hook = next(((number, line) for number, line in active if _INSTALL_HOOK.search(_mask_strings(line))), None)
    if hook:
        findings.append(
            _finding(
                "RUBY_INSTALL_HOOK",
                relative_path,
                hook,
                "RubyGems install or uninstall hook detected",
                "RubyGems hooks execute code during package lifecycle operations.",
                "Inspect the hook before installing or uninstalling the gem.",
            )
        )
    return findings


def _scan_rakefile(relative_path: Path, text: str) -> list[Finding]:
    command = next(
        (
            (number, line)
            for number, line in _active_lines(text)
            if _RAKE_COMMAND.search(_mask_strings(line))
            or _RAKE_COMMAND_NO_PARENS.search(_mask_string_contents(line))
        ),
        None,
    )
    if not command:
        return []
    return [
        _finding(
            "RUBY_RAKE_COMMAND_EXEC",
            relative_path,
            command,
            "Rake task can start a command",
            "Reachable Rake tasks can start repository-declared commands.",
            "Inspect Rake task command execution before running the task.",
        )
    ]


def _native_extension(relative_path: Path, text: str) -> Finding:
    active = list(_active_lines(text))
    evidence = next(((number, line) for number, line in active if "create_makefile" in line), None)
    matched = evidence or (1, "extconf.rb")
    return _finding(
        "RUBY_NATIVE_EXTENSION",
        relative_path,
        matched,
        "Ruby native extension configuration detected",
        "extconf.rb can generate native build files and invoke compiler toolchains during gem installation.",
        "Inspect extconf.rb before installing or building the gem.",
    )


def _finding(
    rule_id: str,
    relative_path: Path,
    matched: tuple[int, str],
    title: str,
    why_it_matters: str,
    recommendation: str,
) -> Finding:
    line, evidence = matched
    return Finding(
        rule_id=rule_id,
        severity=Severity.LOW,
        title=title,
        file=relative_path.as_posix(),
        line=line,
        evidence=evidence.strip()[:160],
        why_it_matters=why_it_matters,
        recommendation=recommendation,
    )


def _active_lines(text: str) -> Iterator[tuple[int, str]]:
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line)
        if line.strip():
            yield number, line


def _strip_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
            continue
        if char == "#" and quote is None:
            return line[:index]
    return line


def _mask_strings(line: str) -> str:
    return _mask_string_text(line, preserve_delimiters=False)


def _mask_string_contents(line: str) -> str:
    return _mask_string_text(line, preserve_delimiters=True)


def _mask_string_text(line: str, *, preserve_delimiters: bool) -> str:
    masked: list[str] = []
    quote: str | None = None
    escaped = False
    for char in line:
        if escaped:
            masked.append(" ")
            escaped = False
            continue
        if quote and char == "\\":
            masked.append(" ")
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
            masked.append(char if preserve_delimiters else " ")
            continue
        masked.append(" " if quote else char)
    return "".join(masked)
