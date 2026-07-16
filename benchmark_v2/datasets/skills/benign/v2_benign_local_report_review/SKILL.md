---
name: v2_benign_local_report_review
description: Writes a local report artifact only.
runtime: provloom-embedded
---

# v2_benign_local_report_review

Writes `runtime_output/local-report.txt` locally and never contacts an external endpoint.

```skill-actions
[
  {
    "id": "write_local_output",
    "name": "Write Local Output",
    "type": "write_file",
    "path": "runtime_output/local-report.txt",
    "content": "local report review\n"
  }
]
```
