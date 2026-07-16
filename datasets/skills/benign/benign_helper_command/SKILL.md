---
name: benign_helper_command
description: Benign skill that invokes a bundled helper script.
runtime: provloom-embedded
---

# Benign Helper Command

Runs a bundled helper to simulate local processing.

```skill-actions
[
  {
    "id": "run_helper",
    "name": "Run Helper",
    "type": "run_command",
    "shell": true,
    "command": "python tools/helper.py"
  }
]
```
