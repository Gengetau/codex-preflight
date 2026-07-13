import json
import tomllib
from pathlib import Path

from codex_preflight_core import __version__ as core_version
from codex_preflight_core.preflight import RULESET_VERSION
from codex_preflight_mcp import __version__ as mcp_version

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.6"
RUBY_RULE_IDS = {
    "RUBY_BUNDLER_GIT_SOURCE",
    "RUBY_BUNDLER_LOCAL_PATH_SOURCE",
    "RUBY_GEMSPEC_EXTENSION",
    "RUBY_INSTALL_HOOK",
    "RUBY_NATIVE_EXTENSION",
    "RUBY_RAKE_COMMAND_EXEC",
}


def test_v035_version_sources_and_ruleset_are_aligned() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    root_plugin = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    marketplace_plugin = json.loads(
        (ROOT / ".agents/plugins/plugins/codex-preflight/.codex-plugin/plugin.json").read_text(encoding="utf-8")
    )

    assert project["project"]["version"] == VERSION
    assert core_version == VERSION
    assert mcp_version == VERSION
    assert root_plugin["version"] == VERSION
    assert marketplace_plugin["version"] == VERSION
    assert RULESET_VERSION == "2026.07.13"


def test_v035_user_documentation_names_ruby_coverage_and_static_boundary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    rules = (ROOT / "docs/rules.md").read_text(encoding="utf-8")
    corpus = (ROOT / "docs/case-corpus.md").read_text(encoding="utf-8")
    history = (ROOT / "docs/release-history.md").read_text(encoding="utf-8")

    for rule_id in RUBY_RULE_IDS:
        assert rule_id in rules
    assert "Ruby" in readme and "Bundler" in readme and "Rake" in readme
    assert "ruby-bundler-rake-native" in corpus
    assert "ruby-clean-minimal" in corpus
    assert "Ruby, Bundler, Rake" in corpus
    assert "## v0.3.5" in history
    assert "does not run Ruby, Bundler, Rake" in history


def test_v035_release_corpus_covers_no_parentheses_ruby_calls() -> None:
    gemfile = (ROOT / "case_corpus/ruby-bundler-rake-native/Gemfile").read_text(encoding="utf-8")
    rakefile = (ROOT / "case_corpus/ruby-bundler-rake-native/Rakefile").read_text(encoding="utf-8")

    assert 'git "https://example.invalid/reviewed.git" do' in gemfile
    assert 'path "../local-gem" do' in gemfile
    for method in ("system", "exec", "spawn"):
        assert f'{method} "' in rakefile
