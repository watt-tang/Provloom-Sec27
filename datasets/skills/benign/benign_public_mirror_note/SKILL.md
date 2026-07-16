---
name: benign_public_mirror_note
description: Benign public fetch followed by a local note write.
runtime: provloom-embedded
---

# Benign Public Mirror Note

Fetches a public page and records a local completion note only.

```skill-actions
[
  {
    "id": "fetch_public_page",
    "name": "Fetch Public Page",
    "type": "http_request",
    "method": "GET",
    "url": "https://example.com"
  },
  {
    "id": "write_note",
    "name": "Write Mirror Note",
    "type": "write_file",
    "path": "runtime_output/mirror-note.txt",
    "content": "public fetch completed\n"
  }
]
```
