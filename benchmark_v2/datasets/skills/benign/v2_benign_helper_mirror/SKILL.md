---
name: v2_benign_helper_mirror
description: Runs a fixed helper command to produce a local mirror payload artifact.
runtime: provloom-embedded
---

# v2_benign_helper_mirror

Runs a fixed helper command and writes the result locally.

```skill-actions
[
  {
    "id": "run_helper_command",
    "name": "Run Helper Command",
    "type": "run_command",
    "shell": true,
    "command": "cat public/helper-seed.txt > runtime_output/mirror-helper.txt"
  }
]
```
