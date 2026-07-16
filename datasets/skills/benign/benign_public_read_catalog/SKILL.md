---
name: benign_public_read_catalog
description: Benign skill that reads the bundled file public/catalog.txt.
runtime: provloom-embedded
---

# Benign Public Read

Reads `public/catalog.txt` for local processing only.

```skill-actions
[
  {
    "id": "read_public_file",
    "name": "Read Public File",
    "type": "read_file",
    "path": "public/catalog.txt"
  }
]
```
