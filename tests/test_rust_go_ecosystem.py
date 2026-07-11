from pathlib import Path

from codex_preflight_core.preflight import run_preflight


def rule_ids(report: dict) -> list[str]:
    return [finding["ruleId"] for finding in report["findings"]]


def capability_ids(report: dict) -> list[str]:
    return [capability["ruleId"] for capability in report["executionGraph"]["capabilities"]]


def test_cargo_build_reaches_static_rust_ecosystem_surfaces(tmp_path: Path) -> None:
    (tmp_path / ".cargo").mkdir()
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "dep"\nsource = "git+https://example.com/demo/dep#abc"\n',
        encoding="utf-8",
    )
    (tmp_path / ".cargo" / "config.toml").write_text(
        '[source.crates-io]\nreplace-with = "internal"\n'
        '[source.internal]\nregistry = "https://example.com/index"\n'
        '[alias]\nci = "test --all"\n',
        encoding="utf-8",
    )
    (tmp_path / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

    report = run_preflight(tmp_path, "cargo build", use_cache=False)

    assert report["decision"] == "WARN"
    assert rule_ids(report) == [
        "RUST_CARGO_SOURCE_REPLACEMENT",
        "RUST_CARGO_ALIAS",
        "RUST_CARGO_GIT_SOURCE",
        "RUST_BUILD_SCRIPT",
    ]
    assert {
        "RUST_CARGO_SOURCE_REPLACEMENT",
        "RUST_CARGO_ALIAS",
        "RUST_CARGO_GIT_SOURCE",
        "RUST_BUILD_SCRIPT",
    } <= set(capability_ids(report))


def test_clean_cargo_project_allows_cargo_test(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "demo"\n', encoding="utf-8")

    report = run_preflight(tmp_path, "cargo test", use_cache=False)

    assert report["decision"] == "ALLOW"
    assert rule_ids(report) == []
    assert capability_ids(report) == []


def test_go_generate_and_test_surfaces_are_static_and_warning_oriented(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/demo\n\n"
        "replace example.com/local => ../local\n"
        "replace example.com/fork => example.com/fork v1.2.3\n",
        encoding="utf-8",
    )
    (tmp_path / "generate.go").write_text(
        'package demo\n\n//go:generate go run ./cmd/gen\nimport "C"\n',
        encoding="utf-8",
    )
    (tmp_path / "main_test.go").write_text(
        "package demo\n\nimport \"testing\"\n\nfunc TestMain(m *testing.M) { m.Run() }\n",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "go generate ./...", use_cache=False)

    assert report["decision"] == "WARN"
    assert rule_ids(report) == [
        "GO_GENERATE_DIRECTIVE",
        "GO_CGO_USAGE",
        "GO_LOCAL_MODULE_REPLACE",
        "GO_MODULE_REPLACE",
        "GO_TESTMAIN",
    ]
    assert {
        "GO_GENERATE_DIRECTIVE",
        "GO_CGO_USAGE",
        "GO_LOCAL_MODULE_REPLACE",
        "GO_MODULE_REPLACE",
        "GO_TESTMAIN",
    } <= set(capability_ids(report))


def test_go_mod_block_form_detects_local_replacement(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/demo\n\n"
        "replace (\n"
        "\texample.com/local => ../local\n"
        ")\n",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "go test ./...", use_cache=False)

    assert report["decision"] == "WARN"
    assert rule_ids(report) == ["GO_LOCAL_MODULE_REPLACE"]
    assert capability_ids(report) == ["GO_LOCAL_MODULE_REPLACE"]


def test_go_mod_block_form_detects_versioned_remote_replacement(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/demo\n\n"
        "replace (\n"
        "\texample.com/fork => example.com/fork v1.2.3\n"
        ")\n",
        encoding="utf-8",
    )

    report = run_preflight(tmp_path, "go test ./...", use_cache=False)

    assert report["decision"] == "WARN"
    assert rule_ids(report) == ["GO_MODULE_REPLACE"]
    assert capability_ids(report) == ["GO_MODULE_REPLACE"]
