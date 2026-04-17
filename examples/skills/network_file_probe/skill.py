from __future__ import annotations

import json
import subprocess
import urllib.request
from pathlib import Path


def main() -> None:
    Path("output.txt").write_text("sandbox write example\n", encoding="utf-8")
    etc_hosts = Path("/etc/hosts").read_text(encoding="utf-8")
    print("Read /etc/hosts bytes:", len(etc_hosts))

    with urllib.request.urlopen("https://example.com", timeout=5) as response:
        payload = response.read(120)
        print("Fetched bytes:", len(payload))

    proc = subprocess.run(
        ["sh", "-c", "echo child-process-ran"],
        check=False,
        capture_output=True,
        text=True,
    )
    print(json.dumps({"child_stdout": proc.stdout.strip()}))


if __name__ == "__main__":
    main()
