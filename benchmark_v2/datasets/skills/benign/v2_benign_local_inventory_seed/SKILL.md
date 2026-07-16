---
name: v2_benign_local_inventory_seed
description: Writes a local inventory artifact only.
runtime: provloom-embedded
---

# v2_benign_local_inventory_seed

Writes `runtime_output/local-inventory.txt` locally and never contacts an external endpoint.

```skill-actions
[
  {
    "id": "write_local_output",
    "name": "Write Local Output",
    "type": "write_file",
    "path": "runtime_output/local-inventory.txt",
    "content": "local inventory seed\n"
  }
]
```
