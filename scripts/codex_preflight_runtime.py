from __future__ import annotations

import sys
from collections.abc import Callable

RuntimeMain = Callable[[], int | None]


def _resolve_role(role: str) -> RuntimeMain:
    if role == "mcp":
        from codex_preflight_mcp.server import main

        return main
    if role == "hook":
        from codex_preflight_guardian.pre_tool_use import main

        return main
    raise ValueError(f"unsupported runtime role: {role}")


def main() -> int:
    if len(sys.argv) < 2:
        print("missing runtime role", file=sys.stderr)
        return 2

    role = sys.argv[1]
    sys.argv = [sys.argv[0], *sys.argv[2:]]
    try:
        role_main = _resolve_role(role)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2

    result = role_main()
    return int(result) if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
