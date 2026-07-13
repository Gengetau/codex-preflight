from codex_preflight_core.command.java import parse_java_invocation, split_command_words


def test_split_command_words_groups_quotes_without_consuming_windows_path_separators() -> None:
    assert split_command_words(
        'gradle -I "config\\my init.gradle" -c="config\\custom settings.gradle" test'
    ) == [
        "gradle",
        "-I",
        "config\\my init.gradle",
        "-c=config\\custom settings.gradle",
        "test",
    ]


def test_gradle_invocation_preserves_project_settings_and_init_values() -> None:
    invocation = parse_java_invocation(
        split_command_words(
            'gradle --project-dir="sub project" --settings-file="config/my settings.gradle" '
            '--init-script="config/my init.gradle" test'
        )
    )

    assert invocation is not None
    assert invocation.task == "test"
    assert invocation.gradle_project_dir == "sub project"
    assert invocation.gradle_settings_files == ("config/my settings.gradle",)
    assert invocation.gradle_init_scripts == ("config/my init.gradle",)
