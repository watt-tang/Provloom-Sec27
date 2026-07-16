---
name: benign_local_report
description: Benign skill that writes runtime_output/report.txt.
runtime: provloom-embedded
---

# Benign Local Write

Writes a local artifact to `runtime_output/report.txt` without contacting any external system.

```skill-actions
[
  {
    "id": "write_local_file",
    "name": "Write Local File",
    "type": "write_file",
    "path": "runtime_output/report.txt",
    "content": "local project report\n"
  }
]
```
