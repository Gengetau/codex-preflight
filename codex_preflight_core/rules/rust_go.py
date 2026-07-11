import re
import tomllib
from pathlib import Path

from codex_preflight_core.rules.base import line_number
from codex_preflight_core.scanner.finding import Finding, Severity

RUST_GO_RULE_IDS = (
    "RUST_BUILD_SCRIPT",
    "RUST_CARGO_SOURCE_REPLACEMENT",
    "RUST_CARGO_ALIAS",
    "RUST_CARGO_GIT_SOURCE",
    "GO_GENERATE_DIRECTIVE",
    "GO_TESTMAIN",
    "GO_CGO_USAGE",
    "GO_MODULE_REPLACE",
    "GO_LOCAL_MODULE_REPLACE",
)

_GO_GENERATE = re.compile(r"^\s*//go:generate\s+(.+)$", re.MULTILINE)
_GO_TESTMAIN = re.compile(r"\bfunc\s+TestMain\s*\(", re.MULTILINE)
_GO_CGO_IMPORT = re.compile(r'^\s*import\s+"C"\s*$', re.MULTILINE)
_GO_REPLACE_BLOCK = re.compile(r"(?ms)^\s*replace\s*\((.*?)^\s*\)")
_GO_REPLACE_LINE = re.compile(r"^\s*replace\s+(.+?)\s+=>\s+(.+?)(?:\s+v[^\s]+)?\s*$", re.MULTILINE)


class RustGoEcosystemRule:
    rule_ids = RUST_GO_RULE_IDS

    def scan(self, root: Path, relative_path: Path, text: str) -> list[Finding]:
        del root
        normalized = relative_path.as_posix()
        if relative_path.name == "Cargo.toml":
            return _scan_cargo_toml(relative_path, text)
        if relative_path.name == "Cargo.lock":
            return _scan_cargo_lock(relative_path, text)
        if normalized == ".cargo/config.toml":
            return _scan_cargo_config(relative_path, text)
        if relative_path.name == "build.rs":
            return [_rust_build_script(relative_path, text, "Rust build script file")]
        if relative_path.name == "go.mod":
            return _scan_go_mod(relative_path, text)
        if relative_path.suffix == ".go":
            return _scan_go_source(relative_path, text)
        return []


def _scan_cargo_toml(relative_path: Path, text: str) -> list[Finding]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    package = data.get("package", {})
    if not isinstance(package, dict):
        return []
    build_script = package.get("build")
    if isinstance(build_script, str):
        return [_rust_build_script(relative_path, text, f'package.build = "{build_script}"')]
    return []


def _scan_cargo_lock(relative_path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        if "source =" in line and "git+" in line:
            findings.append(
                Finding(
                    rule_id="RUST_CARGO_GIT_SOURCE",
                    severity=Severity.LOW,
                    title="Cargo lock references a git dependency source",
                    file=relative_path.as_posix(),
                    line=line_number(text, "git+"),
                    evidence=line.strip()[:160],
                    why_it_matters="Git dependency sources can change review and provenance expectations.",
                    recommendation="Review git-sourced Cargo dependencies before running Cargo commands.",
                )
            )
            break
    return findings


def _scan_cargo_config(relative_path: Path, text: str) -> list[Finding]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    findings: list[Finding] = []
    source_config = data.get("source", {})
    if isinstance(source_config, dict):
        for name, value in source_config.items():
            if not isinstance(value, dict):
                continue
            evidence = _first_present(value, "replace-with", "registry", "local-registry", "directory")
            if evidence:
                findings.append(
                    Finding(
                        rule_id="RUST_CARGO_SOURCE_REPLACEMENT",
                    severity=Severity.LOW,
                        title="Cargo source replacement or custom registry detected",
                        file=relative_path.as_posix(),
                        line=line_number(text, str(evidence)),
                        evidence=f"source.{name}: {evidence}",
                        why_it_matters=(
                            "Cargo source replacement can redirect dependency resolution to alternate registries "
                            "or local mirrors."
                        ),
                        recommendation="Review Cargo source replacement before running Cargo build or test commands.",
                    )
                )
    aliases = data.get("alias", {})
    if isinstance(aliases, dict):
        for name, command in aliases.items():
            if isinstance(command, str):
                findings.append(
                    Finding(
                        rule_id="RUST_CARGO_ALIAS",
                        severity=Severity.LOW,
                        title="Cargo alias command detected",
                        file=relative_path.as_posix(),
                        line=line_number(text, str(name)),
                        evidence=f"{name}: {command}",
                        why_it_matters="Cargo aliases can hide additional subcommands behind familiar names.",
                        recommendation="Review Cargo aliases before running Cargo commands in this repository.",
                    )
                )
    return findings


def _first_present(data: dict[object, object], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str):
            return f"{key}={value}"
    return None


def _rust_build_script(relative_path: Path, text: str, evidence: str) -> Finding:
    return Finding(
        rule_id="RUST_BUILD_SCRIPT",
        severity=Severity.LOW,
        title="Rust build script detected",
        file=relative_path.as_posix(),
        line=line_number(text, "build") if relative_path.name == "Cargo.toml" else 1,
        evidence=evidence,
        why_it_matters="Cargo build scripts run during Cargo build and test workflows.",
        recommendation="Inspect build.rs behavior before running Cargo build or test commands.",
    )


def _scan_go_mod(relative_path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for module, target in _go_replacements(text):
        target_rule = "GO_LOCAL_MODULE_REPLACE" if _looks_local_go_replacement(target) else "GO_MODULE_REPLACE"
        findings.append(
            Finding(
                rule_id=target_rule,
                severity=Severity.LOW,
                title="Go module replacement detected",
                file=relative_path.as_posix(),
                line=line_number(text, "replace"),
                evidence=f"{module} => {target}",
                why_it_matters="Go replace directives change dependency resolution for build and test commands.",
                recommendation="Review Go replace directives before running Go commands in this repository.",
            )
        )
    return findings


def _go_replacements(text: str) -> list[tuple[str, str]]:
    candidates = [text]
    candidates.extend(match.group(1) for match in _GO_REPLACE_BLOCK.finditer(text))
    replacements: list[tuple[str, str]] = []
    for candidate in candidates:
        for match in _GO_REPLACE_LINE.finditer(candidate):
            replacements.append((match.group(1).strip(), match.group(2).strip()))
    return replacements


def _looks_local_go_replacement(target: str) -> bool:
    return target.startswith(("./", "../", "/", ".\\", "..\\")) or "\\" in target


def _scan_go_source(relative_path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _GO_GENERATE.finditer(text):
        findings.append(
            Finding(
                rule_id="GO_GENERATE_DIRECTIVE",
                severity=Severity.LOW,
                title="Go generate directive detected",
                file=relative_path.as_posix(),
                line=line_number(text, match.group(0).strip()),
                evidence=match.group(0).strip()[:160],
                why_it_matters="go generate executes repository-declared generator commands.",
                recommendation="Review generator directives before running go generate.",
            )
        )
    if _GO_TESTMAIN.search(text):
        findings.append(
            Finding(
                rule_id="GO_TESTMAIN",
                severity=Severity.LOW,
                title="Go TestMain hook detected",
                file=relative_path.as_posix(),
                line=line_number(text, "TestMain"),
                evidence="func TestMain(",
                why_it_matters="TestMain can run setup and teardown code around go test.",
                recommendation="Inspect TestMain before running Go tests.",
            )
        )
    if _GO_CGO_IMPORT.search(text):
        findings.append(
            Finding(
                rule_id="GO_CGO_USAGE",
                severity=Severity.LOW,
                title="Go cgo usage detected",
                file=relative_path.as_posix(),
                line=line_number(text, 'import "C"'),
                evidence='import "C"',
                why_it_matters="cgo can invoke native compiler and linker behavior during Go builds and tests.",
                recommendation="Review cgo usage before running Go build or test commands.",
            )
        )
    return findings
