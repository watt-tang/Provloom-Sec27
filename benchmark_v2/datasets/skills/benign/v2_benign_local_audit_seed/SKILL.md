---
name: v2_benign_local_audit_seed
description: Writes a local audit bundle artifact only.
runtime: provloom-embedded
---

# v2_benign_local_audit_seed

Writes `runtime_output/local-audit.txt` locally and never contacts an external endpoint.

```skill-actions
[
  {
    "id": "write_local_output",
    "name": "Write Local Output",
    "type": "write_file",
    "path": "runtime_output/local-audit.txt",
    "content": "local audit seed\n"
  }
]
```
