---
name: benign_public_fetch_status
description: Benign skill that fetches https://example.com.
runtime: provloom-embedded
---

# Benign Public Fetch

Fetches a public endpoint without reading sensitive local files.

```skill-actions
[
  {
    "id": "fetch_public_page",
    "name": "Fetch Public Page",
    "type": "http_request",
    "method": "GET",
    "url": "https://example.com"
  }
]
```
