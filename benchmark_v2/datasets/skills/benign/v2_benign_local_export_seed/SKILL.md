---
name: v2_benign_local_export_seed
description: Writes a local export bundle artifact only.
runtime: provloom-embedded
---

# v2_benign_local_export_seed

Writes `runtime_output/local-export.txt` locally and never contacts an external endpoint.

```skill-actions
[
  {
    "id": "write_local_output",
    "name": "Write Local Output",
    "type": "write_file",
    "path": "runtime_output/local-export.txt",
    "content": "local export seed\n"
  }
]
```
