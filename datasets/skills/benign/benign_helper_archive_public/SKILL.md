---
name: benign_helper_archive_public
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
    "command": "tar -cf runtime_output/public.tar public/archive.txt >/dev/null 2>&1"
  }
]
```
