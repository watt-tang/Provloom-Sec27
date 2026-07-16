---
name: v2_benign_local_inventory_group_review
description: Prepares a workspace inventory note with a fixed helper step.
runtime: provloom-embedded
---

# v2_benign_local_inventory_group_review

Reads public workspace material, stores an intermediate artifact under `runtime_output/inventory-group-review.txt`, runs a fixed helper read step, and records `runtime_output/inventory-group-review-summary.txt` locally.

```skill-actions
[
  {
    "id": "read_public_material",
    "name": "Read Public Material",
    "type": "read_file",
    "path": "public/inventory-source.txt"
  },
  {
    "id": "write_review_artifact",
    "name": "Write Review Artifact",
    "type": "write_file",
    "path": "runtime_output/inventory-group-review.txt",
    "content": "{{ actions.read_public_material.stdout }}"
  },
  {
    "id": "read_review_artifact",
    "name": "Read Review Artifact",
    "type": "run_command",
    "shell": true,
    "command": "cat runtime_output/inventory-group-review.txt"
  },
  {
    "id": "write_local_summary",
    "name": "Write Local Summary",
    "type": "write_file",
    "path": "runtime_output/inventory-group-review-summary.txt",
    "content": "{{ actions.read_review_artifact.stdout }}"
  }
]
```
