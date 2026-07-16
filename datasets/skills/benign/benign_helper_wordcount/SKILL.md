---
name: benign_helper_wordcount
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
    "command": "wc -l public/notes.txt > runtime_output/notes.count"
  }
]
```
