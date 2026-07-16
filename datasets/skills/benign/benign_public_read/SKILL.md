---
name: benign_public_read
description: Benign skill that reads a local non-sensitive file.
runtime: provloom-embedded
---

# Benign Public Read

Reads a bundled non-sensitive text file for local processing only.

```skill-actions
[
  {
    "id": "read_public_file",
    "name": "Read Public File",
    "type": "read_file",
    "path": "public/info.txt"
  }
]
```
