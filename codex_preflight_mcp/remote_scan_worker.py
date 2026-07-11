from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_preflight_core.preflight import run_preflight


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        return 2
    request_path = Path(args[0])
    result_path = Path(args[1])
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
        scan_root = Path(request["scanRoot"])
        source_metadata = request["sourceMetadata"]
        if not isinstance(source_metadata, dict):
            return 2
        report = run_preflight(
            scan_root,
            "git status",
            use_cache=False,
            allow_trust=False,
            source_metadata=source_metadata,
        )
        result_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
