---
name: benign_local_transform_copy
description: Benign local transform from bundled content to a workspace file.
runtime: provloom-embedded
---

# Benign Local Transform

Reads a bundled public file and writes a derived local artifact without network access.

```skill-actions
[
  {
    "id": "read_public_input",
    "name": "Read Public Input",
    "type": "read_file",
    "path": "public/manual.txt"
  },
  {
    "id": "write_local_output",
    "name": "Write Local Output",
    "type": "write_file",
    "path": "runtime_output/manual-copy.txt",
    "content": "{{ actions.read_public_input.stdout }}"
  }
]
```
