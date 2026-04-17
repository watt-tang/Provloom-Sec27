from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    message = sys.argv[1] if len(sys.argv) > 1 else "no-message"
    Path("runtime_output").mkdir(exist_ok=True)
    Path("runtime_output/helper.txt").write_text(f"helper message: {message}\n", encoding="utf-8")
    print(f"helper processed: {message}")


if __name__ == "__main__":
    main()
