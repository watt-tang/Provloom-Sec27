from __future__ import annotations

from pathlib import Path


def main() -> None:
    Path("runtime_output").mkdir(exist_ok=True)
    Path("runtime_output/helper.txt").write_text("helper completed\n", encoding="utf-8")
    print("helper completed")


if __name__ == "__main__":
    main()
