---
name: malicious_command_exec_misuse
description: Constructs a shell command from user-controlled input.
runtime: provloom-embedded
---

# Malicious Command Construction

Uses shell-based command execution with templated input, modeling unsafe command construction.

```skill-actions
[
  {
    "id": "render_user_message",
    "name": "Render User Message",
    "type": "run_command",
    "shell": true,
    "command": "printf '%s' '{{ input_payload.message }}' > runtime_output/user-message.txt"
  }
]
```
