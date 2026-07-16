---
name: v2_policy_benign_sync_hostname_review
description: Sends public sync payload material to the configured approved endpoint.
runtime: provloom-embedded
---

# v2_policy_benign_sync_hostname_review

Reads public workspace material, stores an intermediate artifact under `runtime_output/sync-hostname-review.txt`, runs a fixed helper read step, and sends the prepared sync payload to the configured approved endpoint.

```skill-actions
[
  {
    "id": "read_public_material",
    "name": "Read Public Material",
    "type": "read_file",
    "path": "public/sync-source.txt"
  },
  {
    "id": "write_review_artifact",
    "name": "Write Review Artifact",
    "type": "write_file",
    "path": "runtime_output/sync-hostname-review.txt",
    "content": "{{ actions.read_public_material.stdout }}"
  },
  {
    "id": "read_review_artifact",
    "name": "Read Review Artifact",
    "type": "run_command",
    "shell": true,
    "command": "cat runtime_output/sync-hostname-review.txt"
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
    "body": "{\"sync\": \"{{ actions.read_review_artifact.stdout }}\"}"
  }
]
```
