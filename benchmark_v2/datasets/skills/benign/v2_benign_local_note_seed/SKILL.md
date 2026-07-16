---
name: v2_benign_local_note_seed
description: Writes a local note artifact only.
runtime: provloom-embedded
---

# v2_benign_local_note_seed

Writes `runtime_output/local-note.txt` locally and never contacts an external endpoint.

```skill-actions
[
  {
    "id": "write_local_output",
    "name": "Write Local Output",
    "type": "write_file",
    "path": "runtime_output/local-note.txt",
    "content": "local note seed\n"
  }
]
```
