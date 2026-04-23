---
name: provloom-batch-scan
description: Re-run the ProvLoom dangerous-skill batch scan and inspect its progress or recent findings. Use when Codex needs to scan the exact skill list in `artifacts/dangerous-skill-paths.txt`, write fresh outputs to `/mnt/e/log3`, back up the previous `/mnt/e/log3`, run with the standard 10-worker foreground workflow, or report scan progress/results from the latest log directory.
---

# ProvLoom Batch Scan

## Overview

Run the project's standard dangerous-skill batch scan in a repeatable way and inspect the resulting logs without re-deriving commands. Prefer the bundled scripts in `scripts/` over manually reconstructing the long `batch_scan_skills.py` invocation.

## Workflow

1. Use `scripts/rerun_scan.py` for a fresh foreground scan.
2. Use `scripts/show_progress.py` to print a one-line or JSON progress snapshot from `/mnt/e/log3/progress.json`.
3. Use `scripts/show_results.py` to inspect the latest result rows or summarize the run.

## Fresh Re-Scan

Run:

```bash
python3 .agents/skills/provloom-batch-scan/scripts/rerun_scan.py --api-key '<KEY>'
```

Behavior:

- Read the exact scan target list from `artifacts/dangerous-skill-paths.txt`.
- Scan `--skills-root /mnt/e/dangerous_skills`.
- Write a fresh run to `/mnt/e/log3`.
- If `/mnt/e/log3` already exists and is non-empty, move it to `/mnt/e/log3.rerun-backup-<YYYYMMDD-HHMMSS>` first.
- Run in foreground with `--max-workers 10`, `--analysis-mode epg_with_filtering`, `--network-policy default`, `--timeout-seconds 600`, and `--no-resume`.

Prefer passing the key via environment variable for repeated use:

```bash
export PROVLOOM_SCAN_API_KEY='<KEY>'
python3 .agents/skills/provloom-batch-scan/scripts/rerun_scan.py
```

## Progress Checks

One-line progress:

```bash
python3 .agents/skills/provloom-batch-scan/scripts/show_progress.py
```

JSON progress:

```bash
python3 .agents/skills/provloom-batch-scan/scripts/show_progress.py --json
```

The one-line output is designed for quick status pings such as:

```text
running | scanning | done 19/617 | completed 19 | skipped 0 | failed 0 | active 10
```

## Result Checks

Show the latest five result rows:

```bash
python3 .agents/skills/provloom-batch-scan/scripts/show_results.py
```

Show more rows:

```bash
python3 .agents/skills/provloom-batch-scan/scripts/show_results.py --tail 20
```

Show only aggregate stats:

```bash
python3 .agents/skills/provloom-batch-scan/scripts/show_results.py --summary
```

## Notes

- These scripts assume the repository layout from this project and should be run from any location; they resolve the repo root automatically.
- `scripts/rerun_scan.py` relies on `scripts/batch_scan_skills.py`, which now accepts `PROVLOOM_SCAN_API_KEY` as the default API key source.
- The result viewer reads `results.jsonl` directly, so it works before `summary.json` is finalized.
