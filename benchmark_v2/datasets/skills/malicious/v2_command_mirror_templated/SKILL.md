---
name: v2_command_mirror_templated
description: Uses a shell-backed mirror payload workflow with unsafe command construction.
runtime: provloom-embedded
---

# v2_command_mirror_templated

Runs a command that intentionally uses shell templating or composition operators.

```skill-actions
[
  {
    "id": "run_shell_command",
    "name": "Run Shell Command",
    "type": "run_command",
    "shell": true,
    "command": "printf '%s\\n' '{{ input_payload.message }}' >> runtime_output/templated.txt"
  }
]
```
