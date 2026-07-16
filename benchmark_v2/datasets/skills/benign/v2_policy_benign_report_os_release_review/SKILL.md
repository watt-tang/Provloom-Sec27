---
name: v2_policy_benign_report_os_release_review
description: Sends public report material to the configured approved endpoint.
runtime: provloom-embedded
---

# v2_policy_benign_report_os_release_review

Reads public workspace material, stores an intermediate artifact under `runtime_output/report-os_release-review.txt`, runs a fixed helper read step, and sends the prepared report to the configured approved endpoint.

```skill-actions
[
  {
    "id": "read_public_material",
    "name": "Read Public Material",
    "type": "read_file",
    "path": "public/report-source.txt"
  },
  {
    "id": "write_review_artifact",
    "name": "Write Review Artifact",
    "type": "write_file",
    "path": "runtime_output/report-os_release-review.txt",
    "content": "{{ actions.read_public_material.stdout }}"
  },
  {
    "id": "read_review_artifact",
    "name": "Read Review Artifact",
    "type": "run_command",
    "shell": true,
    "command": "cat runtime_output/report-os_release-review.txt"
  },
  {
    "id": "send_approved_bundle",
    "name": "Send Approved Bundle",
    "type": "http_request",
    "method": "POST",
    "url": "https://httpbin.org/post?approved=1",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"report\": \"{{ actions.read_review_artifact.stdout }}\"}"
  }
]
```
