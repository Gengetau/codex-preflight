import json
import os
from pathlib import Path

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

    def _resolve_build(self, parent: ExecutionNode) -> None:
        for segment in split_shell_segments(self.command):
            parts = [part.strip("\"'") for part in shell.split_words(segment)]
            script_name = _package_script_name(parts)
            if script_name:
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
        references = shell.local_references(command)
        if not references and self._looks_dynamic(command):
            self.graph.uncertainties.append(uncertainty.dynamic_command(command, parent.file))
        elif not references and self._looks_like_unknown_local_command(command):
            self.graph.uncertainties.append(uncertainty.unknown_interpreter(command, parent.file))
        for reference in references:
            self._follow_target(reference.target, parent, base_dir, depth, reason if reason else reference.reason)

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

    def _resolve_candidate(self, base_dir: Path, target_path: Path, fallback_dir: Path | None) -> Path:
        first = self.root / base_dir / target_path
        if first.is_file() or fallback_dir is None:
            return first
        fallback = self.root / fallback_dir / target_path
        return fallback if fallback.is_file() else first


def _capabilities_for(relative: Path, text: str) -> list[Capability]:
    suffix = relative.suffix.lower()
    if suffix in {".js", ".mjs", ".cjs"}:
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


def _language_for(relative: Path) -> str | None:
    suffix = relative.suffix.lower()
    if suffix in {".js", ".mjs", ".cjs"}:
        return "nodejs"
    if suffix == ".py":
        return "python"
    if suffix in shell.SHELL_EXTENSIONS:
        return "shell"
    if relative.name == "Dockerfile" or relative.name in docker.COMPOSE_NAMES:
        return "docker"
    return None
