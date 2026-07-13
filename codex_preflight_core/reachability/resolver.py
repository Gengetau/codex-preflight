import json
import os
from pathlib import Path

import codex_preflight_core.reachability.command_parser as command_parser
import codex_preflight_core.reachability.docker as docker
import codex_preflight_core.reachability.node_package as node_package
import codex_preflight_core.reachability.nodejs as nodejs
import codex_preflight_core.reachability.python as python
import codex_preflight_core.reachability.shell as shell
import codex_preflight_core.reachability.uncertainty as uncertainty
from codex_preflight_core.command.classifier import CommandClassification, split_shell_segments
from codex_preflight_core.command.scope import CommandScope
from codex_preflight_core.reachability.graph import Capability, ExecutionEdge, ExecutionGraph, ExecutionNode
from codex_preflight_core.repo.collector import FIXTURE_MARKER, SKIP_DIRS
from codex_preflight_core.rules.base import Rule
from codex_preflight_core.rules.ruby import RubyEcosystemRule
from codex_preflight_core.rules.rust_go import RustGoEcosystemRule
from codex_preflight_core.scanner.finding import Severity
from codex_preflight_core.scanner.safe_reader import MAX_FILE_SIZE, read_text_safely

MAX_CHAIN_DEPTH = 5
MAX_NODES = 100
REACHABILITY_MAX_FILE_SIZE = MAX_FILE_SIZE


def build_execution_graph(root: Path, command: str, classification: CommandClassification) -> ExecutionGraph:
    resolver = ReachabilityResolver(root.resolve(), command, classification)
    return resolver.build()


class ReachabilityResolver:
    def __init__(self, root: Path, command: str, classification: CommandClassification) -> None:
        self.root = root
        self.command = command
        self.classification = classification
        self.graph = ExecutionGraph(entry_command=command)
        self.visited_files: set[Path] = set()
        self.node_budget_exhausted = False

    def build(self) -> ExecutionGraph:
        entry = self._add_node("command", self.command, command=self.command)
        scope = self.classification.scope
        if scope == CommandScope.DEPENDENCY_INSTALL:
            self._resolve_dependency_install(entry)
        elif scope == CommandScope.SCRIPT_EXECUTION:
            for segment in split_shell_segments(self.command):
                self._resolve_command_references(segment, entry, Path("."), 0, "command target")
        elif scope == CommandScope.DOCKER:
            self._resolve_docker(entry)
        elif scope in {CommandScope.BUILD, CommandScope.TEST}:
            self._resolve_build(entry)
        elif scope in {CommandScope.UNKNOWN_SHELL, CommandScope.MCP_SERVER_START}:
            for segment in split_shell_segments(self.command):
                self._resolve_command_references(segment, entry, Path("."), 0, "command target")
        return self.graph

    def _resolve_dependency_install(self, parent: ExecutionNode) -> None:
        for package_file in self._walk_files({"package.json"}):
            for name, command in self._package_scripts(package_file, node_package.LIFECYCLE_SCRIPTS):
                label = f"{package_file.as_posix()} scripts.{name}"
                if not self._has_node_budget(package_file, label):
                    return
                node = self._add_node(
                    "package-script",
                    label,
                    file=package_file,
                    command=command,
                    language="node-package",
                )
                self._add_edge(parent, node, "dependency install lifecycle")
                if shell.local_references(command):
                    self._add_capability(
                        "SCRIPT_INDIRECT_EXECUTION",
                        Severity.MEDIUM,
                        package_file,
                        f"{name}: {command}",
                        "package lifecycle script",
                        "Inspect lifecycle script indirection before running dependency installation.",
                    )
                self._resolve_command_references(
                    command,
                    node,
                    package_file.parent,
                    0,
                    "lifecycle script invokes local script",
                )
        if _is_bundle_install(self.command):
            self._resolve_ruby(parent, include_bundle=True, include_rake=False, include_extensions=True)

    def _resolve_build(self, parent: ExecutionNode) -> None:
        for segment in split_shell_segments(self.command):
            parts = [part.strip("\"'") for part in shell.split_words(segment)]
            script_name = _package_script_name(parts)
            ruby_mode = _ruby_command_mode(parts)
            if ruby_mode:
                include_bundle, include_rake = ruby_mode
                self._resolve_ruby(
                    parent,
                    include_bundle=include_bundle,
                    include_rake=include_rake,
                    include_extensions=False,
                )
            elif script_name:
                for package_file in self._walk_files({"package.json"}):
                    for name, command in self._package_scripts(package_file, {script_name}):
                        label = f"{package_file.as_posix()} scripts.{name}"
                        if not self._has_node_budget(package_file, label):
                            return
                        node = self._add_node(
                            "package-script",
                            label,
                            file=package_file,
                            command=command,
                        )
                        self._add_edge(parent, node, "package run script")
                        self._resolve_command_references(
                            command,
                            node,
                            package_file.parent,
                            0,
                            "package script invokes local script",
                        )
            elif parts and parts[0].lower() == "make":
                for makefile in self._walk_files({"Makefile"}):
                    if not self._has_node_budget(makefile, makefile.as_posix()):
                        return
                    node = self._add_node("makefile", makefile.as_posix(), file=makefile, language="make")
                    self._add_edge(parent, node, "make command reads Makefile")
                    self._scan_file(makefile, node, 0)
            elif parts and parts[0].lower() == "cargo":
                self._resolve_cargo(parent)
            elif parts and parts[0].lower() == "go":
                self._resolve_go(parent)

    def _resolve_cargo(self, parent: ExecutionNode) -> None:
        cargo_files = [*self._walk_files({"Cargo.toml", "Cargo.lock", "build.rs"}), *self._walk_files({"config.toml"})]
        for relative in sorted(set(cargo_files), key=lambda item: item.as_posix()):
            if relative.name == "config.toml" and relative.as_posix() != ".cargo/config.toml":
                continue
            if not self._has_node_budget(relative, relative.as_posix()):
                return
            node = self._add_node("file", relative.as_posix(), file=relative, language="rust")
            self._add_edge(parent, node, "cargo command reads Rust project metadata")
            self._add_rule_capabilities(relative)

    def _resolve_go(self, parent: ExecutionNode) -> None:
        go_files = [*self._walk_files({"go.mod", "go.sum"}), *self._walk_suffix(".go")]
        for relative in sorted(set(go_files), key=lambda item: item.as_posix()):
            if not self._has_node_budget(relative, relative.as_posix()):
                return
            node = self._add_node("file", relative.as_posix(), file=relative, language="go")
            self._add_edge(parent, node, "go command reads Go project metadata and source")
            self._add_rule_capabilities(relative)

    def _resolve_ruby(
        self,
        parent: ExecutionNode,
        *,
        include_bundle: bool,
        include_rake: bool,
        include_extensions: bool,
    ) -> None:
        ruby_files: list[Path] = []
        if include_bundle:
            ruby_files.extend(self._walk_files({"Gemfile", "Gemfile.lock", "gems.locked"}))
            ruby_files.extend(self._walk_suffix(".gemspec"))
        if include_rake:
            ruby_files.extend(self._walk_files({"Rakefile"}))
        if include_extensions:
            ruby_files.extend(self._walk_files({"extconf.rb"}))
        for relative in sorted(set(ruby_files), key=lambda item: item.as_posix()):
            if not self._has_node_budget(relative, relative.as_posix()):
                return
            node = self._add_node("file", relative.as_posix(), file=relative, language="ruby")
            self._add_edge(parent, node, "Ruby command reads Bundler or Rake project metadata")
            self._add_rule_capabilities(relative, RubyEcosystemRule())

    def _add_rule_capabilities(self, relative: Path, rule: Rule | None = None) -> None:
        text = self._read(relative)
        if text is None:
            self.graph.uncertainties.append(uncertainty.parse_uncertain("Could not read ecosystem file.", relative))
            return
        scanner = rule or RustGoEcosystemRule()
        for finding in scanner.scan(self.root, relative, text):
            self.graph.capabilities.append(
                Capability(
                    rule_id=finding.rule_id,
                    severity=finding.severity,
                    file=Path(finding.file),
                    line=finding.line,
                    capability=finding.title,
                    evidence=finding.evidence,
                    recommendation=finding.recommendation,
                )
            )

    def _resolve_docker(self, parent: ExecutionNode) -> None:
        lowered = self.command.lower()
        names = {"Dockerfile"} if "build" in lowered else docker.COMPOSE_NAMES | {"Dockerfile"}
        for relative in self._walk_files(names):
            if relative.name == "Dockerfile" or relative.name in docker.COMPOSE_NAMES:
                if not self._has_node_budget(relative, relative.as_posix()):
                    return
                node = self._add_node("file", relative.as_posix(), file=relative, language="docker")
                self._add_edge(parent, node, "docker command reads configuration")
                text = self._read(relative)
                if text is None:
                    continue
                self.graph.capabilities.extend(docker.docker_capabilities(relative, text))
                if relative.name in docker.COMPOSE_NAMES:
                    for reference in docker.referenced_dockerfiles(text):
                        self._follow_target(reference, node, relative.parent, 0, "compose build references Dockerfile")

    def _resolve_command_references(
        self,
        command: str,
        parent: ExecutionNode,
        base_dir: Path,
        depth: int,
        reason: str,
    ) -> None:
        parsed = command_parser.parse_reachable_command(command)
        found_static_reference = bool(
            parsed.local_paths or parsed.nested_commands or parsed.package_scripts or parsed.python_modules
        )
        for parsed_uncertainty in parsed.uncertainties:
            self.graph.uncertainties.append(self._parsed_uncertainty(parsed_uncertainty, parent.file))
        for nested in parsed.nested_commands:
            for segment in split_shell_segments(nested):
                self._resolve_command_references(segment, parent, base_dir, depth, reason)
        for script_name in parsed.package_scripts:
            self._resolve_package_script(script_name, parent, base_dir, depth, reason)
        for module_name in parsed.python_modules:
            self._follow_python_module(module_name, parent, base_dir, depth, reason)
        for reference in parsed.local_paths:
            self._follow_target(reference.target, parent, base_dir, depth, reason if reason else reference.reason)
        if not found_static_reference and not parsed.uncertainties and self._looks_dynamic(command):
            self.graph.uncertainties.append(uncertainty.dynamic_command(command, parent.file))
        elif (
            not found_static_reference
            and not parsed.uncertainties
            and self._looks_like_unknown_local_command(command)
        ):
            self.graph.uncertainties.append(uncertainty.unknown_interpreter(command, parent.file))

    def _resolve_package_script(
        self,
        script_name: str,
        parent: ExecutionNode,
        base_dir: Path,
        depth: int,
        reason: str,
    ) -> None:
        package_files = [base_dir / "package.json"] if (self.root / base_dir / "package.json").is_file() else []
        package_files.extend(
            package_file for package_file in self._walk_files({"package.json"}) if package_file not in package_files
        )
        for package_file in package_files:
            for name, command in self._package_scripts(package_file, {script_name}):
                label = f"{package_file.as_posix()} scripts.{name}"
                if not self._has_node_budget(package_file, label):
                    return
                node = self._add_node("package-script", label, file=package_file, command=command)
                self._add_edge(parent, node, reason if reason else "package script command")
                self._resolve_command_references(
                    command,
                    node,
                    package_file.parent,
                    depth,
                    "package script invokes local script",
                )

    def _follow_python_module(
        self,
        module_name: str,
        parent: ExecutionNode,
        base_dir: Path,
        depth: int,
        reason: str,
    ) -> None:
        module_path = Path(module_name.replace(".", "/"))
        candidates = [module_path.with_suffix(".py"), module_path / "__main__.py"]
        for candidate in candidates:
            raw = self._resolve_candidate(base_dir, candidate, None)
            if raw.is_file():
                self._follow_target(candidate.as_posix(), parent, base_dir, depth, reason or "python -m module target")
                return
        self.graph.uncertainties.append(uncertainty.missing_target(module_name, parent.file))

    def _follow_target(
        self,
        target: str,
        parent: ExecutionNode,
        base_dir: Path,
        depth: int,
        reason: str,
        fallback_dir: Path | None = None,
    ) -> None:
        if depth >= MAX_CHAIN_DEPTH:
            self.graph.uncertainties.append(uncertainty.chain_depth_exceeded(parent.file))
            return
        if not self._has_node_budget(parent.file, target):
            return
        target_path = Path(target.strip("\"'"))
        if target_path.is_absolute():
            self.graph.uncertainties.append(uncertainty.outside_repo(target, parent.file))
            return
        raw_path = self._resolve_candidate(base_dir, target_path, fallback_dir)
        if raw_path.is_symlink():
            self.graph.uncertainties.append(
                uncertainty.parse_uncertain(f"Reachable target is a symlink and was not read: {target}", parent.file)
            )
            return
        resolved = raw_path.resolve()
        try:
            relative = resolved.relative_to(self.root)
        except ValueError:
            self.graph.uncertainties.append(uncertainty.outside_repo(target, parent.file))
            return
        if not resolved.is_file():
            self.graph.uncertainties.append(uncertainty.missing_target(target, parent.file))
            return
        if not self._has_node_budget(parent.file, relative.as_posix()):
            return
        node = self._add_node("file", relative.as_posix(), file=relative, language=_language_for(relative))
        self._add_edge(parent, node, reason)
        self._scan_file(relative, node, depth + 1)

    def _scan_file(self, relative: Path, node: ExecutionNode, depth: int) -> None:
        if relative in self.visited_files:
            return
        self.visited_files.add(relative)
        text = self._read(relative)
        if text is None:
            self.graph.uncertainties.append(uncertainty.parse_uncertain("Could not read reachable file.", relative))
            return
        self.graph.capabilities.extend(_capabilities_for(relative, text))
        if relative.suffix.lower() in nodejs.NODE_MODULE_EXTENSIONS:
            if nodejs.has_dynamic_module_reference(text):
                self.graph.uncertainties.append(uncertainty.dynamic_module_reference(relative))
            for reference in nodejs.local_module_references(text):
                self._follow_node_module_target(reference.target, node, relative.parent, depth, reference.reason)
        for line in text.splitlines():
            for reference in shell.local_references(line):
                self._follow_target(
                    reference.target,
                    node,
                    Path("."),
                    depth,
                    reference.reason,
                    fallback_dir=relative.parent,
                )

    def _follow_node_module_target(
        self,
        target: str,
        parent: ExecutionNode,
        base_dir: Path,
        depth: int,
        reason: str,
    ) -> None:
        target_path = Path(target.strip("\"'"))
        if target_path.is_absolute():
            self.graph.uncertainties.append(uncertainty.outside_repo(target, parent.file))
            return
        for candidate in _node_module_candidates(target_path):
            raw = self._resolve_candidate(base_dir, candidate, None)
            resolved = raw.resolve()
            try:
                resolved.relative_to(self.root)
            except ValueError:
                self.graph.uncertainties.append(uncertainty.outside_repo(target, parent.file))
                return
            if resolved.is_file():
                self._follow_target(candidate.as_posix(), parent, base_dir, depth, reason)
                return
        self.graph.uncertainties.append(uncertainty.missing_target(target, parent.file))

    def _walk_files(self, basenames: set[str]) -> list[Path]:
        found: list[Path] = []
        for current, dirs, files in os.walk(self.root):
            current_path = Path(current)
            dirs[:] = [
                directory
                for directory in dirs
                if directory not in SKIP_DIRS and not (current_path / directory / FIXTURE_MARKER).exists()
            ]
            for filename in files:
                if filename in basenames:
                    found.append((current_path / filename).relative_to(self.root))
        return sorted(found, key=lambda item: item.as_posix())

    def _walk_suffix(self, suffix: str) -> list[Path]:
        found: list[Path] = []
        for current, dirs, files in os.walk(self.root):
            current_path = Path(current)
            dirs[:] = [
                directory
                for directory in dirs
                if directory not in SKIP_DIRS and not (current_path / directory / FIXTURE_MARKER).exists()
            ]
            for filename in files:
                if filename.endswith(suffix):
                    found.append((current_path / filename).relative_to(self.root))
        return sorted(found, key=lambda item: item.as_posix())

    def _package_scripts(self, relative: Path, names: set[str]) -> list[tuple[str, str]]:
        text = self._read(relative)
        if text is None:
            self.graph.uncertainties.append(uncertainty.parse_uncertain("Could not read package.json.", relative))
            return []
        try:
            scripts = node_package.package_scripts(relative, names, text, raise_parse_error=True)
        except json.JSONDecodeError:
            self.graph.uncertainties.append(uncertainty.parse_uncertain("Could not parse package.json.", relative))
            return []
        return [(script.name, script.command) for script in scripts]

    def _read(self, relative: Path) -> str | None:
        return read_text_safely(self.root, relative, max_size=REACHABILITY_MAX_FILE_SIZE).text

    def _has_node_budget(self, file: Path | None, pending_label: str) -> bool:
        if len(self.graph.nodes) < MAX_NODES:
            return True
        if not self.node_budget_exhausted:
            self.node_budget_exhausted = True
            self.graph.uncertainties.append(
                uncertainty.node_budget_exceeded(
                    max_nodes=MAX_NODES,
                    current_nodes=len(self.graph.nodes),
                    pending_label=pending_label,
                    file=file,
                )
            )
        return False

    def _add_node(
        self,
        node_type: str,
        label: str,
        *,
        file: Path | None = None,
        command: str | None = None,
        language: str | None = None,
    ) -> ExecutionNode:
        node = ExecutionNode(
            id=f"n{len(self.graph.nodes) + 1}",
            type=node_type,
            label=label,
            file=file,
            command=command,
            language=language,
        )
        self.graph.nodes.append(node)
        return node

    def _add_edge(self, source: ExecutionNode, target: ExecutionNode, reason: str) -> None:
        self.graph.edges.append(ExecutionEdge(from_id=source.id, to_id=target.id, reason=reason))

    def _add_capability(
        self,
        rule_id: str,
        severity: Severity,
        file: Path,
        evidence: str,
        capability: str,
        recommendation: str,
    ) -> None:
        self.graph.capabilities.append(
            Capability(
                rule_id=rule_id,
                severity=severity,
                file=file,
                line=1,
                capability=capability,
                evidence=evidence[:160],
                recommendation=recommendation,
            )
        )

    def _looks_dynamic(self, command: str) -> bool:
        return "$(" in command or "`" in command or "${" in command

    def _looks_like_unknown_local_command(self, command: str) -> bool:
        parts = [part.strip("\"'") for part in shell.split_words(command)]
        if len(parts) < 2 or "://" in parts[1]:
            return False
        return "/" in parts[1] or "\\" in parts[1] or Path(parts[1]).suffix

    def _parsed_uncertainty(
        self,
        parsed_uncertainty: command_parser.CommandUncertainty,
        file: Path | None,
    ):
        if parsed_uncertainty.rule_id == "SCRIPT_TARGET_OUTSIDE_REPO":
            return uncertainty.outside_repo(parsed_uncertainty.reason, file)
        if parsed_uncertainty.rule_id == "SCRIPT_EXTERNAL_PACKAGE_EXECUTION":
            return uncertainty.external_package_execution(parsed_uncertainty.reason, file)
        if parsed_uncertainty.rule_id == "SCRIPT_TASK_RUNNER_UNRESOLVED":
            return uncertainty.task_runner_unresolved(parsed_uncertainty.reason, file)
        return uncertainty.parse_uncertain(parsed_uncertainty.reason, file)

    def _resolve_candidate(self, base_dir: Path, target_path: Path, fallback_dir: Path | None) -> Path:
        first = self.root / base_dir / target_path
        if first.is_file() or fallback_dir is None:
            return first
        fallback = self.root / fallback_dir / target_path
        return fallback if fallback.is_file() else first


def _capabilities_for(relative: Path, text: str) -> list[Capability]:
    suffix = relative.suffix.lower()
    if suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx"}:
        return nodejs.node_capabilities(relative, text)
    if suffix == ".py":
        return python.python_capabilities(relative, text)
    if suffix in shell.SHELL_EXTENSIONS:
        return shell.shell_capabilities(relative, text)
    if relative.name == "Dockerfile" or relative.name in docker.COMPOSE_NAMES:
        return docker.docker_capabilities(relative, text)
    return shell.shell_capabilities(relative, text)


def _package_script_name(parts: list[str]) -> str | None:
    if len(parts) >= 3 and parts[0].lower() in {"npm", "pnpm", "yarn"} and parts[1].lower() == "run":
        return parts[2]
    if len(parts) >= 2 and parts[0].lower() in {"npm", "pnpm", "yarn"} and parts[1].lower() in {
        "test",
        "start",
        "build",
    }:
        return parts[1]
    return None


def _is_bundle_install(command: str) -> bool:
    for segment in split_shell_segments(command):
        parts = [part.strip("\"'").lower() for part in shell.split_words(segment)]
        if len(parts) >= 2 and parts[0] in {"bundle", "bundler"} and parts[1] == "install":
            return True
    return False


def _ruby_command_mode(parts: list[str]) -> tuple[bool, bool] | None:
    lowered = [part.lower() for part in parts]
    if lowered and lowered[0] == "rake":
        return False, True
    if len(lowered) >= 3 and lowered[0] in {"bundle", "bundler"} and lowered[1:3] == ["exec", "rake"]:
        return True, True
    return None


def _node_module_candidates(target_path: Path) -> list[Path]:
    if target_path.suffix:
        return [target_path]
    return [
        *(target_path.with_suffix(extension) for extension in nodejs.NODE_MODULE_EXTENSIONS),
        *(target_path / f"index{extension}" for extension in nodejs.NODE_MODULE_EXTENSIONS),
    ]


def _language_for(relative: Path) -> str | None:
    suffix = relative.suffix.lower()
    if suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx"}:
        return "nodejs"
    if suffix == ".go":
        return "go"
    if relative.name in {"Cargo.toml", "Cargo.lock", "build.rs"} or relative.as_posix() == ".cargo/config.toml":
        return "rust"
    if relative.name in {"Gemfile", "Gemfile.lock", "gems.locked", "Rakefile", "extconf.rb"}:
        return "ruby"
    if relative.suffix == ".gemspec":
        return "ruby"
    if suffix == ".py":
        return "python"
    if suffix in shell.SHELL_EXTENSIONS:
        return "shell"
    if relative.name == "Dockerfile" or relative.name in docker.COMPOSE_NAMES:
        return "docker"
    return None
