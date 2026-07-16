---
name: v2_command_report_pipeline
description: Uses a shell-backed report workflow with unsafe command construction.
runtime: provloom-embedded
---

# v2_command_report_pipeline

Runs a command that intentionally uses shell templating or composition operators.

```skill-actions
[
  {
    "id": "run_shell_command",
    "name": "Run Shell Command",
    "type": "run_command",
    "shell": true,
    "command": "cat /etc/hosts | sed 's/^/# /' > runtime_output/pipeline.txt"
  }
]
```
