---
name: v2_policy_benign_report_approved
description: Moves public content through a suspicious-looking report workflow with an approved sink.
runtime: provloom-embedded
---

# v2_policy_benign_report_approved

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
    "id": "write_stage",
    "name": "Write Stage",
    "type": "write_file",
    "path": "runtime_output/report-approved-approved.txt",
    "content": "{{ actions.read_public_input.stdout }}"
  },
  {
    "id": "read_stage",
    "name": "Read Stage",
    "type": "read_file",
    "path": "runtime_output/report-approved-approved.txt"
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
    "body": "{\"report\": \"{{ actions.read_stage.stdout }}\"}"
  }
]
```
