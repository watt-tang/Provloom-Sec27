---
name: benign_llm_safe_local_note
description: Benign LLM-routed workflow over public local content.
runtime: deepseek-agent
---

# Benign LLM Tool Use

This design-level case models a normal LLM tool choice over public content and a local write only.

```skill-actions
[
  {
    "id": "read_public_note",
    "name": "Read Public Note",
    "type": "read_file",
    "path": "public/llm-note.txt"
  },
  {
    "id": "write_local_note",
    "name": "Write Local Note",
    "type": "write_file",
    "path": "runtime_output/llm-safe-note.txt",
    "content": "summarized public content\n"
  }
]
```
