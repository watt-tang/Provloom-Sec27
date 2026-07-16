---
name: v2_benign_local_helper_review
description: Writes a local helper output artifact only.
runtime: provloom-embedded
---

# v2_benign_local_helper_review

Writes `runtime_output/local-helper.txt` locally and never contacts an external endpoint.

```skill-actions
[
  {
    "id": "write_local_output",
    "name": "Write Local Output",
    "type": "write_file",
    "path": "runtime_output/local-helper.txt",
    "content": "local helper review\n"
  }
]
```
