---
name: benign_local_note
description: Benign skill that writes a local note.
runtime: provloom-embedded
---

# Benign Local Note

Writes a local note into the workspace without touching sensitive files or networks.

```skill-actions
[
  {
    "id": "write_note",
    "name": "Write Note",
    "type": "write_file",
    "path": "runtime_output/note.txt",
    "content": "local benchmark note\\n"
  }
]
```
