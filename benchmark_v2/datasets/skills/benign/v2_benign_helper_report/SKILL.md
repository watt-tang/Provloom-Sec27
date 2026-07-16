---
name: v2_benign_helper_report
description: Runs a fixed helper command to produce a local report artifact.
runtime: provloom-embedded
---

# v2_benign_helper_report

Runs a fixed helper command and writes the result locally.

```skill-actions
[
  {
    "id": "run_helper_command",
    "name": "Run Helper Command",
    "type": "run_command",
    "shell": true,
    "command": "wc -l public/helper-seed.txt > runtime_output/report-helper.txt"
  }
]
```
