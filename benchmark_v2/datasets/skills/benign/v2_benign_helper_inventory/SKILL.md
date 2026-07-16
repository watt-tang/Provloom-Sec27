---
name: v2_benign_helper_inventory
description: Runs a fixed helper command to produce a local inventory artifact.
runtime: provloom-embedded
---

# v2_benign_helper_inventory

Runs a fixed helper command and writes the result locally.

```skill-actions
[
  {
    "id": "run_helper_command",
    "name": "Run Helper Command",
    "type": "run_command",
    "shell": true,
    "command": "ls public > runtime_output/inventory-helper.txt"
  }
]
```
