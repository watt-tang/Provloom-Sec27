---
name: v2_benign_helper_helper
description: Runs a fixed helper command to produce a local helper output artifact.
runtime: provloom-embedded
---

# v2_benign_helper_helper

Runs a fixed helper command and writes the result locally.

```skill-actions
[
  {
    "id": "run_helper_command",
    "name": "Run Helper Command",
    "type": "run_command",
    "shell": true,
    "command": "python - <<'PY'\nfrom pathlib import Path\nPath('runtime_output/helper-helper.txt').write_text('helper output\\n', encoding='utf-8')\nPY"
  }
]
```
