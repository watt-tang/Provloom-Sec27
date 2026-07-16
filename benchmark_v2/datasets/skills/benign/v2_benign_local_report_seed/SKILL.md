---
name: v2_benign_local_report_seed
description: Writes a local report artifact only.
runtime: provloom-embedded
---

# v2_benign_local_report_seed

Writes `runtime_output/local-report.txt` locally and never contacts an external endpoint.

```skill-actions
[
  {
    "id": "write_local_output",
    "name": "Write Local Output",
    "type": "write_file",
    "path": "runtime_output/local-report.txt",
    "content": "local report seed\n"
  }
]
```
