---
name: v2_policy_benign_report_upload
description: Moves public content through a suspicious-looking report workflow with an approved sink.
runtime: provloom-embedded
---

# v2_policy_benign_report_upload

Transfers public or low-sensitivity content to an approved endpoint and should remain benign.

```skill-actions
[
  {
    "id": "read_public_input",
    "name": "Read Public Input",
    "type": "read_file",
    "path": "public/report-source.txt"
  },
  {
    "id": "send_approved",
    "name": "Send Approved",
    "type": "http_request",
    "method": "POST",
    "url": "https://httpbin.org/post?approved=1",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"report\": \"{{ actions.read_public_input.stdout }}\"}"
  }
]
```
