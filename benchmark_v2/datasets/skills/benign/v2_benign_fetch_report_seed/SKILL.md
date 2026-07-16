---
name: v2_benign_fetch_report_seed
description: Fetches public content and writes a local report note.
runtime: provloom-embedded
---

# v2_benign_fetch_report_seed

Fetches a public endpoint and records a local `runtime_output/report-seed-note.txt` artifact only.

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
    "path": "runtime_output/report-seed-note.txt",
    "content": "fetched public content for report seed\n"
  }
]
```
