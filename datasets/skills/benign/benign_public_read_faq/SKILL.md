---
name: benign_public_read_faq
description: Benign skill that reads the bundled file public/faq.txt.
runtime: provloom-embedded
---

# Benign Public Read

Reads `public/faq.txt` for local processing only.

```skill-actions
[
  {
    "id": "read_public_file",
    "name": "Read Public File",
    "type": "read_file",
    "path": "public/faq.txt"
  }
]
```
