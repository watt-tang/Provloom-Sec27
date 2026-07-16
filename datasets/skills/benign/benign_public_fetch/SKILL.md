---
name: benign_public_fetch
description: Benign skill that fetches a public website.
runtime: provloom-embedded
---

# Benign Public Fetch

Fetches a public page without reading sensitive local sources.

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
