#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_SKILLS_ROOT = Path("/mnt/e/dangerous_skills")
DEFAULT_LOG_DIR = Path("/mnt/e/log3")
DEFAULT_SKILL_PATHS_FILE = REPO_ROOT / "artifacts" / "dangerous-skill-paths.txt"
DEFAULT_BATCH_SCRIPT = REPO_ROOT / "scripts" / "batch_scan_skills.py"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the standard ProvLoom dangerous-skill batch scan in foreground.",
    )
    parser.add_argument("--api-key", default=os.getenv("PROVLOOM_SCAN_API_KEY", ""))
    parser.add_argument("--skills-root", default=str(DEFAULT_SKILLS_ROOT))
    parser.add_argument("--skill-paths-file", default=str(DEFAULT_SKILL_PATHS_FILE))
    parser.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR))
    parser.add_argument("--max-workers", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--analysis-mode", default="epg_with_filtering")
    parser.add_argument("--network-policy", default="default")
    parser.add_argument("--base-url", default="https://api.siliconflow.cn/v1")
    parser.add_argument("--model", default="deepseek-ai/DeepSeek-V3")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def backup_existing_log_dir(log_dir: Path) -> Path | None:
    if not log_dir.exists():
        return None
    if log_dir.is_dir() and not any(log_dir.iterdir()):
        return None
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = log_dir.with_name(f"{log_dir.name}.rerun-backup-{timestamp}")
    shutil.move(str(log_dir), str(backup_dir))
    return backup_dir


def main() -> int:
    args = parse_args()
    if not args.api_key:
        print("Missing API key. Pass --api-key or set PROVLOOM_SCAN_API_KEY.", file=sys.stderr)
        return 2

    skills_root = Path(args.skills_root).expanduser().resolve()
    skill_paths_file = Path(args.skill_paths_file).expanduser().resolve()
    log_dir = Path(args.log_dir).expanduser().resolve()
    batch_script = DEFAULT_BATCH_SCRIPT.resolve()

    if not batch_script.exists():
        print(f"Batch script not found: {batch_script}", file=sys.stderr)
        return 2
    if not skills_root.exists():
        print(f"Skills root not found: {skills_root}", file=sys.stderr)
        return 2
    if not skill_paths_file.exists():
        print(f"Skill paths file not found: {skill_paths_file}", file=sys.stderr)
        return 2

    cmd = [
        "python3",
        "-u",
        str(batch_script),
        "--skills-root",
        str(skills_root),
        "--skill-paths-file",
        str(skill_paths_file),
        "--log-dir",
        str(log_dir),
        "--max-workers",
        str(args.max_workers),
        "--analysis-mode",
        args.analysis_mode,
        "--network-policy",
        args.network_policy,
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--base-url",
        args.base_url,
        "--model",
        args.model,
        "--no-resume",
    ]

    env = os.environ.copy()
    env["PROVLOOM_SCAN_API_KEY"] = args.api_key

    if args.dry_run:
        planned_backup = None
        if log_dir.exists() and any(log_dir.iterdir()):
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            planned_backup = log_dir.with_name(f"{log_dir.name}.rerun-backup-{timestamp}")
        if planned_backup is not None:
            print(f"Would back up previous log dir to: {planned_backup}")
        print(f"Log dir: {log_dir}")
        print(f"Scanning {skill_paths_file} with {args.max_workers} workers")
        print("Dry run command:")
        print(" ".join(cmd))
        return 0

    backup_dir = backup_existing_log_dir(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    if backup_dir is not None:
        print(f"Backed up previous log dir to: {backup_dir}")
    print(f"Log dir: {log_dir}")
    print(f"Scanning {skill_paths_file} with {args.max_workers} workers")

    completed = subprocess.run(cmd, cwd=REPO_ROOT, env=env)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
