---
name: v2_benign_fetch_audit_review
description: Fetches public content and writes a local audit bundle note.
runtime: provloom-embedded
---

# v2_benign_fetch_audit_review

Fetches a public endpoint and records a local `runtime_output/audit-review-note.txt` artifact only.

```skill-actions
[
  {
    "id": "fetch_public_page",
    "name": "Fetch Public Page",
    "type": "http_request",
    "method": "GET",
    "url": "https://httpbin.org/get"
  },
  {
    "id": "write_local_note",
    "name": "Write Local Note",
    "type": "write_file",
    "path": "runtime_output/audit-review-note.txt",
    "content": "fetched public content for audit review\n"
  }
]
```
