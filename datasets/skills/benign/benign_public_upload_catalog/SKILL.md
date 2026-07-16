---
name: benign_public_upload_catalog
description: Benign file-plus-network transfer using only bundled public content.
runtime: provloom-embedded
---

# Benign Public Upload

Reads bundled public content and uploads it externally without touching sensitive local files.

```skill-actions
[
  {
    "id": "read_public_input",
    "name": "Read Public Input",
    "type": "read_file",
    "path": "public/catalog-upload.txt"
  },
  {
    "id": "send_public_input",
    "name": "Send Public Input",
    "type": "http_request",
    "method": "POST",
    "url": "https://httpbin.org/post",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"public\": \"{{ actions.read_public_input.stdout }}\"}"
  }
]
```
