from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import random
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.baselines.verdict_mapping import MAPPINGS, normalize_prediction

BASELINES_ROOT = Path(os.environ.get("PROVLOOM_BASELINES_ROOT", PROJECT_ROOT.parent / "provloom-baselines"))
DEFAULT_ARTIFACT_ROOT = PROJECT_ROOT / "results" / "baselines"
PROVLOOM_METRICS = PROJECT_ROOT / "results" / "provbench" / "full" / "metrics.json"
PROVLOOM_SUMMARY = PROJECT_ROOT / "results" / "provbench" / "full" / "summary.json"

BASELINE_REPOS = {
    "sentry_full": ("https://github.com/getsentry/skills", BASELINES_ROOT / "sentry-skills"),
    "skillscan": ("https://github.com/NMitchem/SkillScan", BASELINES_ROOT / "skillscan"),
    "snyk_agent_scan": ("https://github.com/snyk/agent-scan", BASELINES_ROOT / "snyk-agent-scan"),
    "cisco_llm": ("https://github.com/cisco-ai-defense/skill-scanner", BASELINES_ROOT / "cisco-skill-scanner"),
    "ai_infra_guard": ("https://github.com/Tencent/AI-Infra-Guard", BASELINES_ROOT / "ai-infra-guard"),
}

BASELINE_PYTHONS = {
    "skillscan": BASELINES_ROOT / "envs" / "skillscan" / "bin" / "python",
    "snyk_agent_scan": BASELINES_ROOT / "envs" / "snyk-agent-scan" / "bin" / "python",
    "cisco_llm": BASELINES_ROOT / "envs" / "cisco-skill-scanner" / "bin" / "python",
    "ai_infra_guard": BASELINES_ROOT / "envs" / "ai-infra-guard" / "bin" / "python",
}

SMOKE_SET = [f"BV3-{i:04d}" for i in range(1, 21)]


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).resolve()
    if args.evaluate_only:
        return evaluate_only(args, output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    args.skillscan_sandbox_stage = detect_skillscan_sandbox_stage(args.baseline)
    write_versions(DEFAULT_ARTIFACT_ROOT / "baseline_versions.json")
    write_verdict_mapping(DEFAULT_ARTIFACT_ROOT / "verdict_mapping.md")

    sample_ids = select_sample_ids(args)
    if args.auto_full_output_root and args.workers != 1:
        raise SystemExit("--auto-full-output-root requires --workers 1 so rate-limit calibration is serial.")
    prior = load_prior(output_root / "summary.json") if args.resume and not args.force else {}
    rows: list[dict[str, Any]] = []
    started = time.perf_counter()
    started_at = datetime.now(timezone.utc).isoformat()

    print(f"[START] baseline={args.baseline} samples={len(sample_ids)} output={output_root}", flush=True)
    print(f"[INFO] workers={args.workers}", flush=True)
    print("[INFO] scan stage does not load ProvBench ground truth.", flush=True)
    pending: list[tuple[int, str]] = []
    for idx, sample_id in enumerate(sample_ids, 1):
        previous = load_completed_sample(output_root, sample_id) if args.resume and not args.force else None
        if not previous:
            previous = prior.get(sample_id)
        if previous and previous.get("status") == "completed":
            rows.append(previous)
            print(f"[SKIP] {idx:04d}/{len(sample_ids):04d} {sample_id} pred={previous.get('normalized_prediction')}", flush=True)
        else:
            pending.append((idx, sample_id))

    write_summary(output_root, args, rows, started, started_at)
    if args.workers == 1:
        for idx, sample_id in pending:
            print(f"[RUN]  {idx:04d}/{len(sample_ids):04d} {sample_id}", flush=True)
            row = scan_one_with_retries(args.baseline, sample_id, args)
            rows.append(row)
            write_sample(output_root, row)
            write_summary(output_root, args, rows, started, started_at)
            print(
                f"[DONE] {idx:04d}/{len(sample_ids):04d} {sample_id} status={row.get('status')} "
                f"pred={row.get('normalized_prediction')} severity={row.get('severity')} elapsed={row.get('runtime_seconds')}s",
                flush=True,
            )
            sleep_between_serial_samples(args, idx != len(sample_ids))
    else:
        pending_iter = iter(pending)
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures: dict[Any, tuple[int, int, str]] = {}
            slot_has_run: dict[int, bool] = {slot: False for slot in range(args.workers)}
            for slot in range(args.workers):
                try:
                    idx, sample_id = next(pending_iter)
                except StopIteration:
                    break
                print(f"[RUN]  {idx:04d}/{len(sample_ids):04d} {sample_id} slot={slot}", flush=True)
                futures[executor.submit(scan_one_in_slot, args.baseline, sample_id, args, slot_has_run[slot])] = (
                    slot,
                    idx,
                    sample_id,
                )
                slot_has_run[slot] = True
            while futures:
                done, _ = wait(set(futures), return_when=FIRST_COMPLETED)
                future = next(iter(done))
                slot, idx, sample_id = futures.pop(future)
                try:
                    row = future.result()
                except Exception as exc:
                    row = failed_row(type(exc).__name__, str(exc), started)
                    row.update({"sample_id": sample_id, "baseline": args.baseline, "normalized_prediction": "failed"})
                row["worker_slot"] = slot
                rows.append(row)
                rows.sort(key=lambda item: str(item.get("sample_id") or ""))
                write_sample(output_root, row)
                write_summary(output_root, args, rows, started, started_at)
                completed = len(rows)
                print(
                    f"[DONE] {completed:04d}/{len(sample_ids):04d} {sample_id} status={row.get('status')} "
                    f"pred={row.get('normalized_prediction')} severity={row.get('severity')} elapsed={row.get('runtime_seconds')}s",
                    flush=True,
                )
                try:
                    next_idx, next_sample_id = next(pending_iter)
                except StopIteration:
                    continue
                print(
                    f"[RUN]  {next_idx:04d}/{len(sample_ids):04d} {next_sample_id} slot={slot}",
                    flush=True,
                )
                futures[executor.submit(scan_one_in_slot, args.baseline, next_sample_id, args, True)] = (
                    slot,
                    next_idx,
                    next_sample_id,
                )
    write_summary(output_root, args, rows, started, started_at)
    if args.auto_full_output_root:
        return maybe_start_auto_full(args, output_root, rows)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run external malicious skill scanner baselines on ProvBench.")
    parser.add_argument("--baseline", required=True, choices=sorted(BASELINE_REPOS))
    parser.add_argument("--benchmark-root", default=str(PROJECT_ROOT / "provbench"))
    parser.add_argument("--start", default="1")
    parser.add_argument("--end", default="")
    parser.add_argument("--sample-ids", default="")
    parser.add_argument("--sample-file", default="")
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--evaluate-only", action="store_true")
    parser.add_argument("--ground-truth-dir", default="")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--workers", type=int, default=1, help="Maximum concurrent sample scans.")
    parser.add_argument("--smoke", action="store_true", help="Run the fixed first-20 smoke set without reading labels.")
    parser.add_argument("--random-sample-count", type=int, default=0, help="Randomly select N sample IDs without reading labels.")
    parser.add_argument("--random-seed", type=int, default=0, help="Seed for --random-sample-count.")
    parser.add_argument("--inter-sample-delay", type=int, default=0, help="Seconds to sleep after each completed serial sample.")
    parser.add_argument("--rate-limit-retry-wait", type=int, default=0, help="Seconds to wait before retrying a provider-rate-limited sample.")
    parser.add_argument("--max-rate-limit-retries", type=int, default=0, help="Whole-sample retries for provider rate limits.")
    parser.add_argument("--auto-full-output-root", default="", help="If calibration is all completed, launch a full scan into this output root.")
    parser.add_argument("--auto-full-start", default="1")
    parser.add_argument("--auto-full-end", default="800")
    parser.add_argument("--base-url", default=os.environ.get("PROVLOOM_SCAN_BASE_URL", "https://llm-provider.example/v1"))
    parser.add_argument("--model", default=os.environ.get("PROVLOOM_SCAN_MODEL", "glm-5.2"))
    parser.add_argument("--skillscan-mode", choices=["scan", "audit"], default="scan")
    args = parser.parse_args()
    args.workers = max(1, min(32, int(args.workers)))
    return args


def select_sample_ids(args: argparse.Namespace) -> list[str]:
    if args.smoke:
        return list(SMOKE_SET)
    ids: list[str] = []
    if args.sample_ids:
        ids.extend(normalize_sample_id(x) for x in args.sample_ids.split(",") if x.strip())
    if args.sample_file:
        ids.extend(
            normalize_sample_id(line)
            for line in Path(args.sample_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
    if ids:
        if args.random_sample_count:
            rng = random.Random(args.random_seed)
            ids = rng.sample(ids, min(args.random_sample_count, len(ids)))
        return ids
    if args.end:
        start = int(str(args.start).replace("BV3-", ""))
        end = int(str(args.end).replace("BV3-", ""))
        ids = [f"BV3-{i:04d}" for i in range(start, end + 1)]
    else:
        manifest = Path(args.benchmark_root).resolve() / "manifest.jsonl"
        ids = [json.loads(line)["sample_id"] for line in manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.random_sample_count:
        rng = random.Random(args.random_seed)
        ids = rng.sample(ids, min(args.random_sample_count, len(ids)))
    return ids


def normalize_sample_id(value: str) -> str:
    text = str(value).strip().upper()
    if text.startswith("BV3-"):
        return text
    return f"BV3-{int(text):04d}"


def scan_one(baseline: str, sample_id: str, args: argparse.Namespace) -> dict[str, Any]:
    repo_url, repo = BASELINE_REPOS[baseline]
    sample_dir = Path(args.benchmark_root).resolve() / "cases" / sample_id
    started = time.perf_counter()
    base_row: dict[str, Any] = {
        "sample_id": sample_id,
        "baseline": baseline,
        "repo": repo_url,
        "commit": git_commit(repo),
        "mode": MAPPINGS[baseline]["mode"],
        "api_key_redacted": True,
        "ground_truth_loaded_by_analyzer": False,
        "model": args.model if baseline in {"cisco_llm", "skillscan", "ai_infra_guard"} else "",
        "request_count": None,
        "tokens": {},
    }
    if not sample_dir.exists():
        return {**base_row, **failed_row("missing_sample", f"Missing sample directory: {sample_dir}", started)}
    if not repo.exists():
        return {**base_row, **failed_row("missing_baseline_repo", f"Missing repo: {repo}", started)}

    try:
        with tempfile.TemporaryDirectory(prefix=f"{baseline}-{sample_id}-") as tmp:
            output_path = Path(tmp) / "result.json"
            command, env, cwd, blocker = build_command(baseline, repo, sample_dir, args, output_path)
            if blocker:
                return {**base_row, **failed_row("configuration_blocker", blocker, started)}
            result = subprocess.run(
                command,
                cwd=str(cwd),
                env=env,
                text=True,
                capture_output=True,
                timeout=args.timeout_seconds,
            )
            payload = parse_json_output(output_path.read_text(encoding="utf-8")) if output_path.exists() else parse_json_output(result.stdout)
            mapped = normalize_prediction(baseline, payload, returncode=result.returncode, stderr=sanitize(result.stderr))
        stderr_text = sanitize(result.stderr)[-4000:]
        tool_error = mapped.get("tool_error") or stderr_text
        if mapped.get("status") == "failed" and stderr_text and stderr_text not in str(tool_error):
            tool_error = f"{tool_error}\n{stderr_text}"
        row = {
            **base_row,
            **mapped,
            "raw_output": payload if payload is not None else sanitize(result.stdout)[-12000:],
            "raw_label": mapped.get("raw_verdict", ""),
            "tool_error": tool_error,
            "returncode": result.returncode,
            "runtime_seconds": round(time.perf_counter() - started, 3),
            "command": redact_command(command),
        }
        return row
    except subprocess.TimeoutExpired as exc:
        return {**base_row, **failed_row("timeout", f"timeout after {args.timeout_seconds}s", started), "raw_output": sanitize(exc.stdout or "")[-4000:]}
    except Exception as exc:
        return {**base_row, **failed_row(type(exc).__name__, str(exc), started)}


def scan_one_with_retries(baseline: str, sample_id: str, args: argparse.Namespace) -> dict[str, Any]:
    attempts = max(1, int(args.max_rate_limit_retries) + 1)
    retry_rows: list[dict[str, Any]] = []
    last_row: dict[str, Any] | None = None
    for attempt in range(1, attempts + 1):
        row = scan_one(baseline, sample_id, args)
        row["attempt"] = attempt
        row["max_attempts"] = attempts
        row["retry_count"] = attempt - 1
        last_row = row
        retry_rows.append(compact_retry_row(row))
        if not is_rate_limited_row(row):
            row["rate_limit_retries"] = retry_rows[:-1]
            row["rate_limit_retry_count"] = attempt - 1
            return row
        if attempt < attempts:
            wait_seconds = max(0, int(args.rate_limit_retry_wait))
            print(
                f"[RETRY] {sample_id} provider_rate_limited attempt={attempt}/{attempts}; "
                f"sleep={wait_seconds}s",
                flush=True,
            )
            if wait_seconds:
                time.sleep(wait_seconds)
    row = retry_rows_to_final(last_row or {}, retry_rows)
    return row


def scan_one_in_slot(baseline: str, sample_id: str, args: argparse.Namespace, sleep_before: bool) -> dict[str, Any]:
    if sleep_before:
        sleep_seconds = max(0, int(args.inter_sample_delay))
        if sleep_seconds:
            print(f"[SLEEP] slot inter_sample_delay={sleep_seconds}s before {sample_id}", flush=True)
            time.sleep(sleep_seconds)
    return scan_one_with_retries(baseline, sample_id, args)


def sleep_between_serial_samples(args: argparse.Namespace, has_next: bool) -> None:
    sleep_seconds = max(0, int(args.inter_sample_delay))
    if has_next and sleep_seconds:
        print(f"[SLEEP] inter_sample_delay={sleep_seconds}s", flush=True)
        time.sleep(sleep_seconds)


def compact_retry_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "attempt": row.get("attempt"),
        "status": row.get("status"),
        "normalized_prediction": row.get("normalized_prediction"),
        "error_type": row.get("error_type"),
        "runtime_seconds": row.get("runtime_seconds"),
        "returncode": row.get("returncode"),
    }


def retry_rows_to_final(last: dict[str, Any], retry_rows: list[dict[str, Any]]) -> dict[str, Any]:
    row = dict(last)
    row["status"] = "failed"
    row["normalized_prediction"] = "failed"
    row["error_type"] = row.get("error_type") or "provider_rate_limited"
    row["rate_limit_retries"] = retry_rows[:-1]
    row["rate_limit_retry_count"] = max(0, len(retry_rows) - 1)
    return row


def is_rate_limited_row(row: dict[str, Any]) -> bool:
    haystack = " ".join(
        str(row.get(key) or "")
        for key in ("status", "normalized_prediction", "error_type", "tool_error", "raw_verdict")
    ).lower()
    return any(token in haystack for token in ("provider_rate_limited", "rate limit", "429", "too many requests"))


def build_command(
    baseline: str,
    repo: Path,
    sample_dir: Path,
    args: argparse.Namespace,
    output_path: Path | None = None,
) -> tuple[list[str], dict[str, str], Path, str]:
    env = safe_env()
    if baseline == "sentry_full":
        script = repo / "skills" / "skill-scanner" / "scripts" / "scan_skill.py"
        return [sys.executable, str(script), str(sample_dir)], env, repo / "skills" / "skill-scanner", ""
    if baseline == "skillscan":
        env["PYTHONPATH"] = str(repo / "src")
        if args.skillscan_mode == "audit":
            return [python_for("skillscan"), "-m", "skillscan.cli", "audit", str(sample_dir), "--format", "json"], env, repo, ""
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            return [], env, repo, "OPENAI_API_KEY is not present in the current environment"
        env["OPENAI_API_KEY"] = key
        env["OPENAI_BASE_URL"] = args.base_url
        env["OPENAI_MODEL"] = args.model
        return [python_for("skillscan"), "-m", "skillscan.cli", "scan", str(sample_dir), "--format", "json", "--provider", "openai"], env, repo, ""
    if baseline == "snyk_agent_scan":
        env["PYTHONPATH"] = str(repo / "src")
        return [python_for("snyk_agent_scan"), "-m", "agent_scan.run", "scan", "--json", str(sample_dir)], env, repo, ""
    if baseline == "cisco_llm":
        key = os.environ.get("PROVLOOM_SCAN_API_KEY")
        if not key:
            return [], env, repo, "PROVLOOM_SCAN_API_KEY is not set; Cisco LLM mode requires an API key."
        env["PYTHONPATH"] = str(repo)
        env["SKILL_SCANNER_LLM_API_KEY"] = key
        env["SKILL_SCANNER_LLM_PROVIDER"] = "openai"
        env["SKILL_SCANNER_LLM_BASE_URL"] = args.base_url
        env["SKILL_SCANNER_LLM_MODEL"] = f"openai/{args.model}"
        return [
            python_for("cisco_llm"),
            "-m",
            "skill_scanner.cli.cli",
            "scan",
            str(sample_dir),
            "--use-behavioral",
            "--use-llm",
            "--llm-provider",
            "openai",
            "--format",
            "json",
        ], env, repo, ""
    if baseline == "ai_infra_guard":
        skill_scan_repo = repo / "skill-scan"
        if not skill_scan_repo.exists():
            return [], env, repo, f"Missing AI-Infra-Guard skill-scan directory: {skill_scan_repo}"
        key = os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("PROVLOOM_SCAN_API_KEY")
        if not key:
            return [], env, skill_scan_repo, "LLM_API_KEY/OPENAI_API_KEY is not present in the current environment"
        env["PYTHONPATH"] = str(skill_scan_repo)
        env["LLM_API_KEY"] = key
        env["OPENAI_API_KEY"] = key
        env["LLM_BASE_URL"] = args.base_url
        env["OPENAI_BASE_URL"] = args.base_url
        env["LLM_MODEL"] = args.model
        env["OPENAI_MODEL"] = args.model
        command = [
            python_for("ai_infra_guard"),
            "-m",
            "skill_scan",
            "--repo",
            str(sample_dir),
            "--model",
            args.model,
            "--base_url",
            args.base_url,
            "--language",
            "en",
        ]
        if output_path is not None:
            command.extend(["--output", str(output_path)])
        return command, env, skill_scan_repo, ""
    return [], env, repo, f"Unsupported baseline {baseline}"


def python_for(baseline: str) -> str:
    candidate = BASELINE_PYTHONS.get(baseline)
    if candidate and candidate.exists():
        return str(candidate)
    return sys.executable


def safe_env() -> dict[str, str]:
    keep = {"PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"}
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


def parse_json_output(stdout: str) -> Any:
    text = stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = min([idx for idx in (text.find("{"), text.find("[")) if idx >= 0], default=-1)
        if start >= 0:
            try:
                return json.loads(text[start:])
            except json.JSONDecodeError:
                return None
    return None


def failed_row(error_type: str, message: str, started: float) -> dict[str, Any]:
    return {
        "status": "failed",
        "normalized_prediction": "failed",
        "raw_verdict": "",
        "raw_severity": "",
        "severity": "",
        "error_type": error_type,
        "tool_error": message,
        "runtime_seconds": round(time.perf_counter() - started, 3),
    }


def write_sample(output_root: Path, row: dict[str, Any]) -> None:
    path = output_root / "samples" / f"{row['sample_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, row)


def write_summary(output_root: Path, args: argparse.Namespace, rows: list[dict[str, Any]], started: float, started_at: str) -> dict[str, Any]:
    total_runtime = round(time.perf_counter() - started, 3)
    payload = {
        "schema_version": "provloom-baseline-benchmark-v3-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "started_at": started_at,
        "benchmark_root": str(Path(args.benchmark_root).resolve()),
        "baseline": args.baseline,
        "mode": MAPPINGS[args.baseline]["mode"],
        "api_key_redacted": True,
        "ground_truth_loaded_by_analyzer": False,
        "sample_count": len(rows),
        "total_runtime_seconds": total_runtime,
        "summary_counts": dict(Counter(str(row.get("normalized_prediction")) for row in rows)),
        "status_counts": dict(Counter(str(row.get("status")) for row in rows)),
        "error_counts": dict(Counter(str(row.get("error_type") or "") for row in rows if row.get("status") != "completed")),
        "retry_counts": {
            "rate_limit_retry_count": sum(int(row.get("rate_limit_retry_count") or 0) for row in rows),
            "rate_limited_final_count": sum(1 for row in rows if is_rate_limited_row(row)),
        },
        "workers": args.workers,
        "run_config": run_config(args, rows),
        "samples": rows,
    }
    atomic_write_json(output_root / "run_config.json", payload["run_config"])
    atomic_write_json(output_root / "summary.json", payload)
    return payload


def load_prior(summary_path: Path) -> dict[str, dict[str, Any]]:
    if not summary_path.exists():
        return {}
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    return {str(row.get("sample_id")): row for row in payload.get("samples", []) if row.get("sample_id")}


def load_completed_sample(output_root: Path, sample_id: str) -> dict[str, Any] | None:
    path = output_root / "samples" / f"{sample_id}.json"
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if payload.get("status") == "completed" and payload.get("sample_id") == sample_id else None


def run_config(args: argparse.Namespace, rows: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {
        "baseline": args.baseline,
        "mode": MAPPINGS[args.baseline]["mode"],
        "llm_model": args.model if args.baseline in {"skillscan", "cisco_llm"} else "",
        "llm_base_url": args.base_url if args.baseline in {"skillscan", "cisco_llm"} else "",
            "max_concurrency": args.workers,
            "inter_sample_delay_seconds": args.inter_sample_delay,
            "rate_limit_retry_wait_seconds": args.rate_limit_retry_wait,
            "max_rate_limit_retries": args.max_rate_limit_retries,
        "benchmark_samples": len(rows),
        "ground_truth_used_during_scan": False,
        "api_key_redacted": True,
    }
    if args.baseline == "skillscan":
        payload.update({
            "baseline": "NMitchem/SkillScan",
            "mode": args.skillscan_mode,
            "llm_provider": "openai" if args.skillscan_mode == "scan" else "",
            "llm_model": args.model if args.skillscan_mode == "scan" else "",
            "llm_base_url": args.base_url if args.skillscan_mode == "scan" else "",
            "provider_compatibility_patch": True,
            "sandbox_stage": getattr(args, "skillscan_sandbox_stage", "unknown"),
        })
    return payload


def maybe_start_auto_full(args: argparse.Namespace, calibration_root: Path, rows: list[dict[str, Any]]) -> int:
    completed = [row for row in rows if row.get("status") == "completed"]
    failures = [row for row in rows if row.get("status") != "completed"]
    report = {
        "configuration_status": "CALIBRATION_PASSED" if len(completed) == len(rows) and rows else "CALIBRATION_FAILED",
        "completed": len(completed),
        "failed": len(failures),
        "failed_samples": [
            {
                "sample_id": row.get("sample_id"),
                "status": row.get("status"),
                "error_type": row.get("error_type"),
                "retry_count": row.get("rate_limit_retry_count", row.get("retry_count", 0)),
            }
            for row in failures
        ],
        "total_rate_limit_retry_count": sum(int(row.get("rate_limit_retry_count") or 0) for row in rows),
        "ground_truth_used_during_scan": False,
    }
    atomic_write_json(calibration_root / "calibration_decision.json", report)
    if failures or not rows:
        print("[AUTO_FULL] calibration failed; full scan not started.", flush=True)
        print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
        return 2

    full_root = Path(args.auto_full_output_root).resolve()
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--baseline",
        args.baseline,
        "--start",
        str(args.auto_full_start),
        "--end",
        str(args.auto_full_end),
        "--output-root",
        str(full_root),
        "--resume",
        "--workers",
        "1",
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--base-url",
        args.base_url,
        "--model",
        args.model,
        "--skillscan-mode",
        args.skillscan_mode,
        "--inter-sample-delay",
        str(args.inter_sample_delay),
        "--rate-limit-retry-wait",
        str(args.rate_limit_retry_wait),
        "--max-rate-limit-retries",
        str(args.max_rate_limit_retries),
    ]
    full_root.mkdir(parents=True, exist_ok=True)
    log_path = full_root / "scan.log"
    with log_path.open("ab") as log:
        proc = subprocess.Popen(
            command,
            cwd=str(PROJECT_ROOT),
            env=os.environ.copy(),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    (full_root / "scan.pid").write_text(f"{proc.pid}\n", encoding="utf-8")
    report.update({
        "full_scan_started": True,
        "full_scan_pid": proc.pid,
        "full_output_root": str(full_root),
        "full_log_path": str(log_path),
        "full_command": redact_command(command),
    })
    atomic_write_json(calibration_root / "calibration_decision.json", report)
    print(f"[AUTO_FULL] started pid={proc.pid} output={full_root} log={log_path}", flush=True)
    return 0


def detect_skillscan_sandbox_stage(baseline: str) -> str:
    if baseline != "skillscan":
        return ""
    repo = BASELINE_REPOS["skillscan"][1]
    try:
        result = subprocess.run(
            [
                python_for("skillscan"),
                "-c",
                "from skillscan.sandbox.runtimes import docker_sandbox_available; print(docker_sandbox_available())",
            ],
            cwd=str(repo),
            env={**safe_env(), "PYTHONPATH": str(repo / "src")},
            text=True,
            capture_output=True,
            timeout=10,
        )
    except Exception:
        return "unknown"
    return "available" if result.stdout.strip() == "True" else "unavailable/skipped"


def evaluate_only(args: argparse.Namespace, output_root: Path) -> int:
    if not args.ground_truth_dir:
        raise SystemExit("--evaluate-only requires --ground-truth-dir.")
    prediction_file = output_root / "summary.json"
    if not prediction_file.exists():
        raise SystemExit(f"Missing prediction file: {prediction_file}")
    prediction_bytes = prediction_file.read_bytes()
    summary = json.loads(prediction_bytes.decode("utf-8"))
    rows = list(summary.get("samples") or [])
    # Ground truth is loaded only after prediction file parsing.
    gt = load_ground_truth(Path(args.ground_truth_dir))
    payload = build_metrics(
        rows=rows,
        gt=gt,
        baseline=args.baseline,
        prediction_file=prediction_file,
        prediction_sha256=hashlib.sha256(prediction_bytes).hexdigest(),
        ground_truth_dir=Path(args.ground_truth_dir).resolve(),
        source_summary=summary,
    )
    atomic_write_json(output_root / "metrics.json", payload)
    write_metrics_csv(output_root / "metrics.csv", payload)
    write_metrics_md(output_root / "metrics.md", payload)
    write_error_csvs(output_root, payload)
    update_comparison(args.baseline, output_root, payload)
    print(json.dumps(payload["overall"], ensure_ascii=False, indent=2), flush=True)
    return 0


def load_ground_truth(root: Path) -> dict[str, dict[str, Any]]:
    records = {}
    for path in sorted(root.glob("BV3-*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        records[path.stem] = payload
    if not records:
        raise SystemExit(f"No ground truth records under {root}")
    return records


def build_metrics(
    *,
    rows: list[dict[str, Any]],
    gt: dict[str, dict[str, Any]],
    baseline: str,
    prediction_file: Path,
    prediction_sha256: str,
    ground_truth_dir: Path,
    source_summary: dict[str, Any],
) -> dict[str, Any]:
    by_id = {str(row.get("sample_id")): row for row in rows if row.get("sample_id")}
    eval_ids = sorted(sid for sid in gt if sid in by_id)
    missing = sorted(sid for sid in gt if sid not in by_id)
    eval_rows = [evaluation_record(sid, by_id[sid], gt[sid]) for sid in eval_ids]
    valid = [row for row in eval_rows if row["predicted_label"] in {"malicious", "benign"}]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline": baseline,
        "evaluation_only": True,
        "prediction_file": str(prediction_file),
        "prediction_sha256": prediction_sha256,
        "ground_truth_dir": str(ground_truth_dir),
        "ground_truth_loaded_by_analyzer": False,
        "api_key_redacted": True,
        "scan_mode": source_summary.get("mode"),
        "overall": {
            **metric_bundle(valid),
            "evaluated_count": len(eval_ids),
            "valid_prediction_count": len(valid),
            "missing_prediction_count": len(missing),
            "failed_count": sum(1 for row in eval_rows if row["predicted_label"] == "failed"),
            "abstain_count": sum(1 for row in eval_rows if row["predicted_label"] not in {"malicious", "benign", "failed"}),
            "coverage_rate": ratio(len(valid), len(eval_ids)),
            "average_runtime_seconds": ratio(sum(float(row.get("runtime_seconds") or 0.0) for row in eval_rows), len(eval_rows)),
            "total_runtime_seconds": sum(float(row.get("runtime_seconds") or 0.0) for row in eval_rows),
        },
        "groups": {
            "per_outcome": grouped(valid, "expected_policy_outcome"),
            "per_risk_family": grouped(valid, "risk_family"),
            "per_split": grouped(valid, "split"),
        },
        "samples": eval_rows,
        "metric_definitions": {
            "malicious_ground_truth": "expected_policy_outcome in {confirmed_violation, candidate_violation, violation}",
            "chain_recall": "N/A for external baselines without provenance chains.",
        },
    }


def evaluation_record(sample_id: str, prediction: dict[str, Any], gt: dict[str, Any]) -> dict[str, Any]:
    expected = expected_binary_label(gt)
    pred = str(prediction.get("normalized_prediction") or "failed")
    outcome = str(gt.get("expected_policy_outcome") or "unknown")
    return {
        "sample_id": sample_id,
        "split": gt.get("split") or prediction.get("split") or "",
        "expected_policy_outcome": outcome,
        "expected_label": expected,
        "predicted_label": pred,
        "correct": expected == pred,
        "risk_family": str(gt.get("risk_family") or "unknown"),
        "raw_verdict": prediction.get("raw_verdict"),
        "severity": prediction.get("severity"),
        "error_type": prediction.get("error_type") or "",
        "runtime_seconds": prediction.get("runtime_seconds") or 0.0,
        "is_benign_lookalike": outcome == "benign_lookalike",
        "is_trusted_allowed": outcome == "trusted_allowed" or any("scoped approval" in str(item).lower() for item in gt.get("authorization_context") or []),
    }


def expected_binary_label(gt: dict[str, Any]) -> str:
    outcome = str(gt.get("expected_policy_outcome") or "").lower()
    return "malicious" if outcome in {"confirmed_violation", "candidate_violation", "violation"} else "benign"


def metric_bundle(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    tp = sum(1 for r in rows if r["expected_label"] == "malicious" and r["predicted_label"] == "malicious")
    tn = sum(1 for r in rows if r["expected_label"] == "benign" and r["predicted_label"] == "benign")
    fp = sum(1 for r in rows if r["expected_label"] == "benign" and r["predicted_label"] == "malicious")
    fn = sum(1 for r in rows if r["expected_label"] == "malicious" and r["predicted_label"] == "benign")
    bl = [r for r in rows if r["is_benign_lookalike"]]
    trusted = [r for r in rows if r["is_trusted_allowed"]]
    return {
        "count": total,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": ratio(tp + tn, total),
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "specificity": ratio(tn, tn + fp),
        "fpr": ratio(fp, fp + tn),
        "fnr": ratio(fn, fn + tp),
        "benign_lookalike_fpr": ratio(sum(1 for r in bl if r["predicted_label"] == "malicious"), len(bl)),
        "trusted_allowed_fpr": ratio(sum(1 for r in trusted if r["predicted_label"] == "malicious"), len(trusted)),
        "review_rate": 0.0,
        "error_capture_rate": 0.0,
        "confirmed_violation_chain_recall": None,
        "complete_chain_recall": None,
        "false_closure_rate": None,
    }


def grouped(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        buckets.setdefault(str(row.get(key) or "unknown"), []).append(row)
    return {name: metric_bundle(items) for name, items in sorted(buckets.items())}


def ratio(num: float, den: float) -> float:
    return round(float(num) / float(den), 6) if den else 0.0


def write_metrics_csv(path: Path, payload: dict[str, Any]) -> None:
    fields = ["group_type", "group", "count", "tp", "tn", "fp", "fn", "accuracy", "precision", "recall", "f1", "specificity", "fpr", "fnr", "benign_lookalike_fpr", "trusted_allowed_fpr"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(flat_metric("overall", "overall", payload["overall"]))
        for group_type, groups in payload["groups"].items():
            for group, metrics in groups.items():
                writer.writerow(flat_metric(group_type, group, metrics))


def flat_metric(group_type: str, group: str, metrics: dict[str, Any]) -> dict[str, Any]:
    cm = metrics.get("confusion_matrix") or {}
    return {**{k: metrics.get(k) for k in ("count", "accuracy", "precision", "recall", "f1", "specificity", "fpr", "fnr", "benign_lookalike_fpr", "trusted_allowed_fpr")}, "group_type": group_type, "group": group, "tp": cm.get("tp", 0), "tn": cm.get("tn", 0), "fp": cm.get("fp", 0), "fn": cm.get("fn", 0)}


def write_metrics_md(path: Path, payload: dict[str, Any]) -> None:
    overall = payload["overall"]
    cm = overall["confusion_matrix"]
    lines = [
        f"# {payload['baseline']} ProvBench Metrics",
        "",
        f"- Evaluation only: `{payload['evaluation_only']}`",
        f"- Prediction file: `{payload['prediction_file']}`",
        f"- Prediction SHA256: `{payload['prediction_sha256']}`",
        f"- Ground truth loaded by analyzer: `{payload['ground_truth_loaded_by_analyzer']}`",
        f"- Valid predictions: `{overall['valid_prediction_count']}`",
        f"- Failed: `{overall['failed_count']}`",
        "",
        "| TP | TN | FP | FN | Acc | Precision | Recall | F1 | FPR | BL-FPR | Trusted-FPR |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {cm['tp']} | {cm['tn']} | {cm['fp']} | {cm['fn']} | {overall['accuracy']} | {overall['precision']} | {overall['recall']} | {overall['f1']} | {overall['fpr']} | {overall['benign_lookalike_fpr']} | {overall['trusted_allowed_fpr']} |",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_error_csvs(output_root: Path, payload: dict[str, Any]) -> None:
    fields = ["sample_id", "ground_truth_class", "ground_truth_outcome", "raw_verdict", "normalized_prediction", "severity", "error_type"]
    for name, pred, expected in (("false_positives.csv", "malicious", "benign"), ("false_negatives.csv", "benign", "malicious")):
        with (output_root / name).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in payload["samples"]:
                if row["predicted_label"] == pred and row["expected_label"] == expected:
                    writer.writerow({
                        "sample_id": row["sample_id"],
                        "ground_truth_class": row["expected_label"],
                        "ground_truth_outcome": row["expected_policy_outcome"],
                        "raw_verdict": row.get("raw_verdict"),
                        "normalized_prediction": row["predicted_label"],
                        "severity": row.get("severity"),
                        "error_type": row.get("error_type"),
                    })


def update_comparison(baseline: str, output_root: Path, payload: dict[str, Any]) -> None:
    root = DEFAULT_ARTIFACT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    records = {}
    for metrics_path in root.glob("*/metrics.json"):
        try:
            data = json.loads(metrics_path.read_text(encoding="utf-8"))
            records[data["baseline"]] = data
        except Exception:
            continue
    records[baseline] = payload
    if PROVLOOM_METRICS.exists():
        records["ProvLoom"] = json.loads(PROVLOOM_METRICS.read_text(encoding="utf-8"))
    comparison = build_comparison(records)
    atomic_write_json(root / "comparison.json", comparison)
    write_comparison_csv(root / "comparison.csv", comparison)
    write_comparison_md(root / "comparison.md", comparison)


def build_comparison(records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for system, payload in sorted(records.items()):
        overall = payload.get("overall") or {}
        if system == "ProvLoom" and "baseline" not in payload:
            system_name = "ProvLoom"
        else:
            system_name = system
        rows.append({
            "system": system_name,
            "accuracy": overall.get("accuracy"),
            "precision": overall.get("precision"),
            "recall": overall.get("recall"),
            "f1": overall.get("f1"),
            "fpr": overall.get("fpr"),
            "benign_lookalike_fpr": overall.get("benign_lookalike_fpr"),
            "trusted_allowed_fpr": overall.get("trusted_allowed_fpr"),
            "failed": overall.get("failed_count") or overall.get("failed_sample_count") or 0,
            "confirmed_violation_chain_recall": overall.get("confirmed_violation_chain_recall"),
            "complete_chain_recall": overall.get("complete_chain_recall"),
        })
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "systems": rows}


def write_comparison_csv(path: Path, comparison: dict[str, Any]) -> None:
    fields = ["system", "accuracy", "precision", "recall", "f1", "fpr", "benign_lookalike_fpr", "trusted_allowed_fpr", "failed", "confirmed_violation_chain_recall", "complete_chain_recall"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(comparison["systems"])


def write_comparison_md(path: Path, comparison: dict[str, Any]) -> None:
    lines = [
        "# Baseline Comparison",
        "",
        "| System | Acc | Precision | Recall | F1 | FPR | BL-FPR | Trusted-FPR | Failed |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in comparison["systems"]:
        lines.append(
            f"| {row['system']} | {row.get('accuracy')} | {row.get('precision')} | {row.get('recall')} | {row.get('f1')} | {row.get('fpr')} | {row.get('benign_lookalike_fpr')} | {row.get('trusted_allowed_fpr')} | {row.get('failed')} |"
        )
    lines += [
        "",
        "## Explanation Capability",
        "",
        "| System | Runtime Evidence | Instruction-Runtime Alignment | Provenance Chain | Complete-chain Recall |",
        "|---|---|---|---|---:|",
    ]
    for row in comparison["systems"]:
        if row["system"] == "ProvLoom":
            lines.append(f"| ProvLoom | Yes | Yes | Yes | {row.get('complete_chain_recall')} |")
        else:
            lines.append(f"| {row['system']} | No | No | No | N/A |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_versions(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        name: {
            "repo": repo,
            "path": str(path_),
            "commit": git_commit(path_),
            "branch": git_branch(path_),
            "mode": MAPPINGS[name]["mode"],
            "llm_backend": llm_backend_status(name),
        }
        for name, (repo, path_) in BASELINE_REPOS.items()
    }
    payload["environment"] = {"python": sys.version, "platform": platform.platform()}
    atomic_write_json(path, payload)


def llm_backend_status(name: str) -> dict[str, Any]:
    if name == "cisco_llm":
        return {"native_backend_available": bool(os.environ.get("PROVLOOM_SCAN_API_KEY")), "adapted_backend": "openai-compatible via env", "api_key_redacted": True}
    if name == "skillscan":
        return {"native_backend_available": bool(os.environ.get("OPENAI_API_KEY")), "adapted_backend": "openai-compatible via OPENAI_BASE_URL/OPENAI_MODEL", "api_key_redacted": True}
    if name == "snyk_agent_scan":
        return {"native_backend_available": bool(os.environ.get("SNYK_TOKEN")), "adapted_backend": "not applicable; uses Snyk Agent Scan API", "api_key_redacted": True}
    return {"native_backend_available": False, "adapted_backend": "", "api_key_redacted": True}


def write_verdict_mapping(path: Path) -> None:
    lines = ["# External Baseline Verdict Mapping", ""]
    for name, mapping in MAPPINGS.items():
        lines += [f"## {name}", "", f"- Mode: {mapping['mode']}", f"- Rule: {mapping['rule']}", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def git_commit(path: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return ""


def git_branch(path: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(path), "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
    except Exception:
        return ""


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(path.parent), delete=False) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, default=str)
        handle.write("\n")
        tmp = Path(handle.name)
    tmp.replace(path)


def sanitize(text: str) -> str:
    for key in (os.environ.get("PROVLOOM_SCAN_API_KEY"), os.environ.get("OPENAI_API_KEY")):
        if not key:
            continue
        text = text.replace(key, "[REDACTED_API_KEY]")
    return text


def redact_command(command: list[str]) -> list[str]:
    keys = {key for key in (os.environ.get("PROVLOOM_SCAN_API_KEY"), os.environ.get("OPENAI_API_KEY")) if key}
    return ["[REDACTED_API_KEY]" if part in keys else part for part in command]


if __name__ == "__main__":
    raise SystemExit(main())
