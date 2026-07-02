# Rules

V1 statically inspects package lifecycle scripts, shell patterns, secrets, GitHub Actions, MCP
configs, agent instructions, Docker files, and Makefiles.

Rule IDs are stable because Codex summaries and golden tests depend on them. High-risk examples
include `NODE_LIFECYCLE_REMOTE_EXEC`, `SHELL_CURL_PIPE_BASH`, `SECRET_OPENAI_KEY`,
`GHA_PULL_REQUEST_TARGET`, `MCP_SHELL_COMMAND`, `AGENT_SECRET_EXFILTRATION_REQUEST`, and
`DOCKER_PRIVILEGED_CONTAINER`.
