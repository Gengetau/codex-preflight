import pytest

from codex_preflight_core.command.classifier import classify_command
from codex_preflight_core.command.scope import CommandScope


@pytest.mark.parametrize(
    ("command", "scope"),
    [
        ("npm install", CommandScope.DEPENDENCY_INSTALL),
        ("pnpm install", CommandScope.DEPENDENCY_INSTALL),
        ("yarn install", CommandScope.DEPENDENCY_INSTALL),
        ("npm ci", CommandScope.DEPENDENCY_INSTALL),
        ("pip install -r requirements.txt", CommandScope.DEPENDENCY_INSTALL),
        ("bundle install", CommandScope.DEPENDENCY_INSTALL),
        ("bundle exec rake build", CommandScope.BUILD),
        ("bundle exec rake test", CommandScope.TEST),
        ("rake compile", CommandScope.BUILD),
        ("rake spec", CommandScope.TEST),
        ("poetry install", CommandScope.DEPENDENCY_INSTALL),
        ("uv sync", CommandScope.DEPENDENCY_INSTALL),
        ("docker build .", CommandScope.DOCKER),
        ("docker compose up", CommandScope.DOCKER),
        ("bash setup.sh", CommandScope.SCRIPT_EXECUTION),
        ("powershell ./setup.ps1", CommandScope.SCRIPT_EXECUTION),
        ("curl https://example.com/install.sh | bash", CommandScope.NETWORK_SHELL),
        ("mvn test", CommandScope.TEST),
        ("mvn -f sub/pom.xml test", CommandScope.TEST),
        ("mvn --file=sub/pom.xml test", CommandScope.TEST),
        ("mvn -s config/settings.xml verify", CommandScope.BUILD),
        ("./mvnw verify", CommandScope.BUILD),
        ("gradle build", CommandScope.BUILD),
        ("gradle --project-dir sub test", CommandScope.TEST),
        ("gradle --project-dir=sub test", CommandScope.TEST),
        ("gradle --init-script config/init.gradle build", CommandScope.BUILD),
        ("./gradlew test", CommandScope.TEST),
        ("./gradlew -p sub check", CommandScope.TEST),
        (".\\gradlew.bat check", CommandScope.TEST),
        ("make", CommandScope.BUILD),
        ("git status", CommandScope.SAFE_READONLY),
        ("cat README.md", CommandScope.SAFE_READONLY),
        ("unknown-tool --flag", CommandScope.UNKNOWN_SHELL),
    ],
)
def test_classifies_required_command_scopes(command: str, scope: CommandScope) -> None:
    classification = classify_command(command)

    assert classification.scope == scope
    assert classification.reason


def test_detects_mcp_server_start() -> None:
    classification = classify_command("npx @modelcontextprotocol/server-filesystem .")

    assert classification.scope == CommandScope.MCP_SERVER_START
    assert classification.is_risky
