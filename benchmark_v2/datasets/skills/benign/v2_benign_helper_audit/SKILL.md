---
name: v2_benign_helper_audit
description: Runs a fixed helper command to produce a local audit bundle artifact.
runtime: provloom-embedded
---

# v2_benign_helper_audit

Runs a fixed helper command and writes the result locally.

```skill-actions
[
  {
    "id": "run_helper_command",
    "name": "Run Helper Command",
    "type": "run_command",
    "shell": true,
    "command": "sha256sum public/helper-seed.txt > runtime_output/audit-helper.txt"
  }
]
```
