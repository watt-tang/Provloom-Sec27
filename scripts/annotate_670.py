#!/usr/bin/env python3
"""Annotate 670 skill samples based on existing annotations and SKILL.md content."""

import csv
import re
import os
import sys

MANIFEST = "/mnt/e/humanreview/manifest.csv"
ANNOTATION_FILE = "/root/projects/ProvLoom/docs/670_annotation.md"
CSV_FILE = "/root/projects/ProvLoom/docs/human_complete670.csv"
SKILL_DIR = "/mnt/e/humanreview"

def parse_annotations(annotation_path):
    """Parse the 670_annotation.md file to extract annotations for samples 001-130."""
    annotations = {}
    with open(annotation_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Pattern: sample number on its own line, then annotation line
    # The format is: \nNNN\n\nannotation_csv_line
    pattern = r'\n(\d{3})\n+\s*([^\n]+)'
    for m in re.finditer(pattern, content):
        sample_num = m.group(1)
        annotation_line = m.group(2).strip()
        # Parse the CSV-like annotation: decision,behavior,chain_valid,root_cause,notes,reviewer,status
        # Notes are in quotes
        annotations[sample_num] = annotation_line

    return annotations


def parse_annotation_fields(annotation_line):
    """Parse a single annotation line into its fields."""
    # The format is: decision,behavior,chain_valid,root_cause,"notes",reviewer,status
    # We need to handle quoted strings with commas
    fields = []
    in_quotes = False
    current = ""
    for ch in annotation_line:
        if ch == '"':
            in_quotes = not in_quotes
            current += ch
        elif ch == ',' and not in_quotes:
            fields.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        fields.append(current.strip())

    if len(fields) < 7:
        return None

    decision = fields[0]
    behavior = fields[1]
    chain_valid = fields[2]
    root_cause = fields[3]
    # Notes might be quoted
    notes = fields[4]
    if notes.startswith('"') and notes.endswith('"'):
        notes = notes[1:-1]
    reviewer = fields[5]
    status = fields[6]

    return {
        "existing_human_decision": decision,
        "existing_human_gt_behavior": behavior,
        "existing_human_gt_chain_valid": chain_valid,
        "existing_human_gt_root_cause": root_cause,
        "existing_human_notes": notes,
        "existing_reviewer": reviewer,
        "existing_review_status": status,
    }


def read_manifest(manifest_path):
    """Read manifest.csv to get index-to-SKILL.md mapping."""
    mapping = {}
    with open(manifest_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            idx = int(row["index"])
            skill_path = row["output_file"]
            sample_key = row["sample_key"]
            sample_name = row["sample_name"]
            mapping[idx] = {
                "skill_path": skill_path,
                "sample_key": sample_key,
                "sample_name": sample_name,
            }
    return mapping


def read_csv(csv_path):
    """Read the existing CSV file."""
    rows = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            rows.append(row)
    return fieldnames, rows


def write_csv(csv_path, fieldnames, rows):
    """Write the updated CSV file."""
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    # Parse existing annotations
    annotations = parse_annotations(ANNOTATION_FILE)
    print(f"Parsed {len(annotations)} existing annotations")

    # Parse manifest
    manifest = read_manifest(MANIFEST)
    print(f"Parsed manifest with {len(manifest)} entries")

    # Read CSV
    fieldnames, rows = read_csv(CSV_FILE)
    print(f"Read {len(rows)} CSV rows")

    # Build mapping: CSV row index -> sample number
    # CSV row 0 = sample 001, row 1 = sample 002, etc.
    annotated_count = 0
    unannotated_count = 0
    for i, row in enumerate(rows):
        sample_num = f"{i+1:03d}"
        if sample_num in annotations:
            ann = parse_annotation_fields(annotations[sample_num])
            if ann:
                for key, val in ann.items():
                    row[key] = val
                annotated_count += 1
            else:
                print(f"Failed to parse annotation for sample {sample_num}")
                unannotated_count += 1
        else:
            unannotated_count += 1

    print(f"Annotated from existing: {annotated_count}")
    print(f"Remaining unannotated: {unannotated_count}")

    # List unannotated samples
    unannotated = []
    for i, row in enumerate(rows):
        sample_num = f"{i+1:03d}"
        if not row.get("existing_human_decision"):
            if sample_num in manifest:
                unannotated.append((sample_num, manifest[int(sample_num)]["skill_path"]))
    print(f"\nUnannotated samples ({len(unannotated)}):")
    for num, path in unannotated[:10]:
        print(f"  {num}: {path}")
    if len(unannotated) > 10:
        print(f"  ... and {len(unannotated) - 10} more")

    # Write updated CSV
    write_csv(CSV_FILE, fieldnames, rows)
    print(f"\nWrote updated CSV to {CSV_FILE}")


if __name__ == "__main__":
    main()
