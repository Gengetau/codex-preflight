from pathlib import Path

from codex_preflight_core.preflight import run_preflight


def rule_ids(report: dict) -> list[str]:
    return [finding["ruleId"] for finding in report["findings"]]


def capability_ids(report: dict) -> list[str]:
    return [capability["ruleId"] for capability in report["executionGraph"]["capabilities"]]


def graph_files(report: dict) -> set[str]:
    return {node["file"] for node in report["executionGraph"]["nodes"] if node["file"]}


def test_bundle_exec_rake_reaches_warning_oriented_ruby_surfaces(tmp_path: Path) -> None:
    (tmp_path / "ext" / "demo").mkdir(parents=True)
    (tmp_path / "Gemfile").write_text(
        'source "https://rubygems.org"\n'
        'gem "reviewed", git: "https://example.invalid/reviewed.git", branch: "main"\n',
        encoding="utf-8",
    )
    (tmp_path / "Gemfile.lock").write_text(
        "PATH\n  remote: ../local-gem\n  specs:\n    local-gem (1.0.0)\n",
        encoding="utf-8",
    )
    (tmp_path / "Rakefile").write_text(
        'task :install do\n  sh "ruby ext/demo/extconf.rb"\nend\n',
        encoding="utf-8",
    )
    (tmp_path / "demo.gemspec").write_text(
        "Gem::Specification.new do |spec|\n"
        '  spec.name = "demo"\n'
        '  spec.extensions = ["ext/demo/extconf.rb"]\n'
        "end\n"
        "Gem.post_install { |_installer| true }\n",
        encoding="utf-8",
    )
    (tmp_path / "ext" / "demo" / "extconf.rb").write_text(
        'require "mkmf"\ncreate_makefile("demo/native")\n',
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "bundle exec rake install", use_cache=False)

    assert report["decision"] == "WARN"
    assert rule_ids(report) == [
        "RUBY_BUNDLER_GIT_SOURCE",
        "RUBY_BUNDLER_LOCAL_PATH_SOURCE",
        "RUBY_RAKE_COMMAND_EXEC",
        "RUBY_GEMSPEC_EXTENSION",
        "RUBY_INSTALL_HOOK",
        "RUBY_NATIVE_EXTENSION",
    ]
    assert {
        "RUBY_BUNDLER_GIT_SOURCE",
        "RUBY_BUNDLER_LOCAL_PATH_SOURCE",
        "RUBY_RAKE_COMMAND_EXEC",
        "RUBY_GEMSPEC_EXTENSION",
        "RUBY_INSTALL_HOOK",
    } <= set(capability_ids(report))
    assert "RUBY_NATIVE_EXTENSION" not in capability_ids(report)
    assert {"Gemfile", "Gemfile.lock", "Rakefile", "demo.gemspec"} <= graph_files(report)
    assert "ext/demo/extconf.rb" not in graph_files(report)


def test_bundle_install_reaches_custom_bundler_lockfile(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\n', encoding="utf-8")
    (tmp_path / "gems.locked").write_text(
        "GIT\n  remote: https://example.invalid/locked.git\n  revision: abc123\n",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "bundle install", use_cache=False)

    assert report["decision"] == "WARN"
    assert rule_ids(report) == ["RUBY_BUNDLER_GIT_SOURCE"]
    assert capability_ids(report) == ["RUBY_BUNDLER_GIT_SOURCE"]
    assert {"Gemfile", "gems.locked"} <= graph_files(report)


def test_bundle_install_reaches_gemspec_and_native_extension_configuration(tmp_path: Path) -> None:
    (tmp_path / "ext" / "demo").mkdir(parents=True)
    (tmp_path / "Gemfile").write_text('gemspec\n', encoding="utf-8")
    (tmp_path / "demo.gemspec").write_text(
        'Gem::Specification.new { |spec| spec.extensions = ["ext/demo/extconf.rb"] }\n',
        encoding="utf-8",
    )
    (tmp_path / "ext" / "demo" / "extconf.rb").write_text(
        'require "mkmf"\ncreate_makefile("demo/native")\n',
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "bundle install", use_cache=False)

    assert report["decision"] == "WARN"
    assert rule_ids(report) == ["RUBY_GEMSPEC_EXTENSION", "RUBY_NATIVE_EXTENSION"]
    assert capability_ids(report) == ["RUBY_GEMSPEC_EXTENSION", "RUBY_NATIVE_EXTENSION"]
    assert {"Gemfile", "demo.gemspec", "ext/demo/extconf.rb"} <= graph_files(report)


def test_clean_ruby_project_allows_rake_test(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text(
        'source "https://rubygems.org"\ngem "rake", "~> 13.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "Gemfile.lock").write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.2.1)\n",
        encoding="utf-8",
    )
    (tmp_path / "Rakefile").write_text('task :test do\n  puts "static fixture"\nend\n', encoding="utf-8")
    (tmp_path / "demo.gemspec").write_text(
        'Gem::Specification.new { |spec| spec.name = "demo" }\n',
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "rake test", use_cache=False)

    assert report["decision"] == "ALLOW"
    assert rule_ids(report) == []
    assert capability_ids(report) == []
    assert "Rakefile" in graph_files(report)


def test_commented_ruby_indicators_remain_clean(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text(
        '# gem "disabled", path: "../disabled"\n# git "https://example.invalid/disabled.git" do\n',
        encoding="utf-8",
    )
    (tmp_path / "Rakefile").write_text('# task :install do\n#   system("disabled")\n# end\n', encoding="utf-8")
    (tmp_path / "demo.gemspec").write_text(
        '# spec.extensions = ["ext/demo/extconf.rb"]\n# Gem.pre_install { true }\n',
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "bundle exec rake install", use_cache=False)

    assert report["decision"] == "ALLOW"
    assert rule_ids(report) == []
    assert capability_ids(report) == []


def test_ruby_indicator_words_inside_strings_remain_clean(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text('gem "path: not-a-source"\n', encoding="utf-8")
    (tmp_path / "Rakefile").write_text(
        'task :test do\n  puts "system(\\"not called\\")"\nend\n',
        encoding="utf-8",
    )
    (tmp_path / "demo.gemspec").write_text(
        'Gem::Specification.new { |spec| spec.summary = "Gem.post_install and spec.extensions =" }\n',
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "bundle exec rake test", use_cache=False)

    assert report["decision"] == "ALLOW"
    assert rule_ids(report) == []
    assert capability_ids(report) == []
