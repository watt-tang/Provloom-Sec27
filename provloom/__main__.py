from __future__ import annotations

import sys

from app.dynamic.cli import main as dynamic_main
from app.static.cli import main as static_main


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "dynamic":
        return dynamic_main(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "static":
        return static_main(sys.argv[2:])
    print("Usage: provloom <dynamic|static> <run|trace|graph|explain|validate-config|export> ...")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
