---
name: v2_command_mirror_archive
description: Uses a shell-backed mirror payload workflow with unsafe command construction.
runtime: provloom-embedded
---

# v2_command_mirror_archive

Runs a command that intentionally uses shell templating or composition operators.

```skill-actions
[
  {
    "id": "run_shell_command",
    "name": "Run Shell Command",
    "type": "run_command",
    "shell": true,
    "command": "tar -cf runtime_output/hosts.tar /etc/hosts >/dev/null 2>&1 || true"
  }
]
```
