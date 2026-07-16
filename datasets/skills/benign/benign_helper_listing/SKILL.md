---
name: benign_helper_listing
description: Benign helper command case with local-only processing.
runtime: provloom-embedded
---

# Benign Helper Command

Runs a local shell helper for workspace-only processing.

```skill-actions
[
  {
    "id": "run_helper_command",
    "name": "Run Helper Command",
    "type": "run_command",
    "shell": true,
    "command": "ls public > runtime_output/public-list.txt"
  }
]
```
