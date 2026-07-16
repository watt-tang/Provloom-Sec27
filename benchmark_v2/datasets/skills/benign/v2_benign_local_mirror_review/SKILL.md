---
name: v2_benign_local_mirror_review
description: Writes a local mirror payload artifact only.
runtime: provloom-embedded
---

# v2_benign_local_mirror_review

Writes `runtime_output/local-mirror.txt` locally and never contacts an external endpoint.

```skill-actions
[
  {
    "id": "write_local_output",
    "name": "Write Local Output",
    "type": "write_file",
    "path": "runtime_output/local-mirror.txt",
    "content": "local mirror review\n"
  }
]
```
