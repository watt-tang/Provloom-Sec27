#!/usr/bin/env python3
"""Manage review queue for unannotated samples."""

import csv
import json

CSV_PATH = "/root/projects/ProvLoom/docs/human_complete670.csv"
MANIFEST_PATH = "/mnt/e/humanreview/manifest.csv"
QUEUE_PATH = "/root/projects/ProvLoom/docs/review_queue.json"

def get_unannotated():
    """Get list of unannotated samples with their SKILL.md paths."""
    # Read manifest
    manifest = {}
    with open(MANIFEST_PATH, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            idx = int(row["index"])
            manifest[idx] = {
                "skill_path": row["output_file"],
                "sample_key": row["sample_key"],
                "sample_name": row["sample_name"],
            }

    # Read CSV
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    unannotated = []
    for i, row in enumerate(rows):
        if not row.get("existing_human_decision"):
            sample_num = i + 1
            if sample_num in manifest:
                unannotated.append({
                    "row_index": i,
                    "sample_num": sample_num,
                    "sample_key": manifest[sample_num]["sample_key"],
                    "sample_name": manifest[sample_num]["sample_name"],
                    "skill_path": manifest[sample_num]["skill_path"],
                })

    return unannotated

def save_queue(queue):
    """Save queue to JSON."""
    with open(QUEUE_PATH, "w", encoding="utf-8") as f:
        json.dump(queue, f, indent=2)

def load_queue():
    """Load queue from JSON."""
    with open(QUEUE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    queue = get_unannotated()
    save_queue(queue)
    print(f"Review queue: {len(queue)} unannotated samples")
    print(f"First 10:")
    for item in queue[:10]:
        print(f"  {item['sample_num']:03d}: {item['sample_key']} / {item['sample_name']}")
        print(f"    Path: {item['skill_path']}")
