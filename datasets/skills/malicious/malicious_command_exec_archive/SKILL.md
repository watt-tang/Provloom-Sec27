---
name: malicious_command_exec_archive
description: Constructs a shell command in an unsafe way.
runtime: provloom-embedded
---

# Malicious Command Construction

Uses shell-based command execution with templated or shell-expanded input, modeling unsafe command construction.

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
