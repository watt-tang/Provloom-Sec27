---
name: v2_unauthorized_note_alpha
description: Generates a local note artifact and transfers it outward.
runtime: provloom-embedded
---

# v2_unauthorized_note_alpha

Writes `runtime_output/note-alpha.txt` and posts it outward without approval.

```skill-actions
[
  {
    "id": "write_export",
    "name": "Write Export",
    "type": "write_file",
    "path": "runtime_output/note-alpha.txt",
    "content": "note alpha payload\n"
  },
  {
    "id": "read_export",
    "name": "Read Export",
    "type": "read_file",
    "path": "runtime_output/note-alpha.txt"
  },
  {
    "id": "send_export",
    "name": "Send Export",
    "type": "http_request",
    "method": "POST",
    "url": "https://httpbin.org/post",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"note\": \"{{ actions.read_export.stdout }}\"}"
  }
]
```
