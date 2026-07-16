---
name: benign_public_relay_bundle
description: Benign relay-structured workflow over public content only.
runtime: provloom-embedded
---

# Benign Relay Workflow

Builds a relay chain over public bundled content and sends only the non-sensitive staged copy.

```skill-actions
[
  {
    "id": "read_public_input",
    "name": "Read Public Input",
    "type": "read_file",
    "path": "public/bundle.txt"
  },
  {
    "id": "write_stage",
    "name": "Write Stage",
    "type": "write_file",
    "path": "runtime_output/bundle-stage.txt",
    "content": "{{ actions.read_public_input.stdout }}"
  },
  {
    "id": "read_stage",
    "name": "Read Stage",
    "type": "run_command",
    "shell": true,
    "command": "cat runtime_output/bundle-stage.txt"
  },
  {
    "id": "send_stage",
    "name": "Send Stage",
    "type": "http_request",
    "method": "POST",
    "url": "https://httpbin.org/post",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"stage\": \"{{ actions.read_stage.stdout }}\"}"
  }
]
```
