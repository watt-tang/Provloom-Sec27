---
name: benign_local_inventory
description: Benign skill that writes runtime_output/inventory.txt.
runtime: provloom-embedded
---

# Benign Local Write

Writes a local artifact to `runtime_output/inventory.txt` without contacting any external system.

```skill-actions
[
  {
    "id": "write_local_file",
    "name": "Write Local File",
    "type": "write_file",
    "path": "runtime_output/inventory.txt",
    "content": "inventory snapshot\n"
  }
]
```
