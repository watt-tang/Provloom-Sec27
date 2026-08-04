from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.analysis.pipeline import analyze_skill_bundle
from app.backend.schemas import LLMConfig
from app.benchmark.replay_adapter import BenchmarkV3ReplayAdapter
from app.runner.docker_runner import DEFAULT_SANDBOX_IMAGE, DockerRunner


DEFAULT_BASE_URL = "https://sec.llm.autos/v1/chat/completions"
DEFAULT_MODEL = "glm-5.2"


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    summary_path = output_root / "summary.json"

    adapter = BenchmarkV3ReplayAdapter(args.benchmark_root)
    manifest_rows = select_rows(adapter, args)
    if not manifest_rows:
        raise SystemExit("No Benchmark v3 samples selected.")

    prior_rows = load_prior_rows(summary_path) if args.resume and not args.force else {}
    labels = load_labels(adapter, args)
    llm_config = LLMConfig(
        enabled=True,
        provider=args.provider,
        base_url=args.base_url,
        api_key=resolve_api_key(args),
        model=args.model,
        temperature=args.temperature,
        max_steps=args.max_steps,
    )
    runner = DockerRunner(
        image_name=args.image,
        force_rebuild=args.force_rebuild,
        reuse_existing_image=not args.force_rebuild,
    )

    rows: list[dict[str, Any]] = []
    started_all = time.perf_counter()
    started_at = datetime.now(timezone.utc)
    print(
        f"[START] samples={len(manifest_rows)} image={runner.image_name} model={args.model} "
        f"output={output_root} resume={args.resume and not args.force}",
        flush=True,
    )
    print("[INFO] ground truth is not passed to analyzer; labels are report-only when explicitly provided.", flush=True)

    for index, manifest_row in enumerate(manifest_rows, 1):
        sample_id = str(manifest_row["sample_id"])
        prior = prior_rows.get(sample_id)
        if prior and prior.get("status") == "completed":
            row = dict(prior)
            row["resumed_from_summary"] = True
            rows.append(row)
            print(
                f"[SKIP] {index:04d}/{len(manifest_rows):04d} {sample_id} "
                f"final={row.get('final_decision')} review={row.get('review_required')} "
                f"tokens={(row.get('token_usage') or {}).get('total_tokens', 0)}",
                flush=True,
            )
            write_outputs(summary_path, rows, args, runner.image_name, labels, started_all, started_at)
            continue

        started = time.perf_counter()
        print(f"[RUN]  {index:04d}/{len(manifest_rows):04d} {sample_id}", flush=True)
        try:
            bundle = adapter.prepare(
                manifest_row,
                output_root=output_root,
                llm_config=llm_config,
                timeout_seconds=args.timeout_seconds,
                run_id_prefix=args.run_prefix,
            )
            result = analyze_skill_bundle(str(bundle.bundle_path), execution_config=bundle.execution_config, runner=runner)
            row = build_result_row(
                sample_id=sample_id,
                manifest_row=manifest_row,
                result=result,
                elapsed_seconds=round(time.perf_counter() - started, 2),
            )
            print(
                f"[DONE] {index:04d}/{len(manifest_rows):04d} {sample_id} "
                f"final={row.get('final_decision')} review={row.get('review_required')} "
                f"score={row.get('decision_score')} coverage={row.get('coverage_state')} "
                f"risk={row.get('risk_chain_status')} tokens={(row.get('token_usage') or {}).get('total_tokens', 0)} "
                f"elapsed={row.get('elapsed_seconds')}s",
                flush=True,
            )
        except Exception as exc:
            row = {
                "sample_id": sample_id,
                "status": "failed",
                "split": manifest_row.get("split"),
                "error_type": type(exc).__name__,
                "error": str(exc),
                "traceback": traceback.format_exc(limit=8),
                "elapsed_seconds": round(time.perf_counter() - started, 2),
            }
            print(f"[FAIL] {index:04d}/{len(manifest_rows):04d} {sample_id} {type(exc).__name__}: {exc}", flush=True)

        rows.append(row)
        write_outputs(summary_path, rows, args, runner.image_name, labels, started_all, started_at)

    payload = write_outputs(summary_path, rows, args, runner.image_name, labels, started_all, started_at)
    print("[SUMMARY]", summary_path, flush=True)
    print(
        f"[RUNTIME] total={payload['total_runtime_human']} "
        f"seconds={payload['total_runtime_seconds']} started={payload['started_at']} finished={payload['finished_at']}",
        flush=True,
    )
    print(json.dumps(payload["metrics"], ensure_ascii=False, indent=2), flush=True)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run resumable full-system ProvLoom scans over Benchmark v3 samples.")
    parser.add_argument("--benchmark-root", default="benchmark_v3")
    parser.add_argument("--output-root", default="artifacts/benchmark_v3_full_manual")
    parser.add_argument("--run-prefix", default="BV3FULL")
    parser.add_argument("--sample-ids", default="", help="Comma-separated sample ids, e.g. BV3-0001,BV3-0002.")
    parser.add_argument("--sample-file", default="", help="Text file with one sample id per line.")
    parser.add_argument("--start", default="", help="Start id or number, e.g. BV3-0001 or 1.")
    parser.add_argument("--end", default="", help="End id or number, inclusive.")
    parser.add_argument("--split", default="", help="Optional manifest split filter.")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--force", action="store_true", help="Rerun selected samples even if summary.json has completed rows.")
    parser.add_argument("--api-key", default="", help="LLM API key. Prefer env PROVLOOM_SCAN_API_KEY for shell history safety.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--provider", default="siliconflow")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-steps", type=int, default=16)
    parser.add_argument("--timeout-seconds", type=int, default=None)
    parser.add_argument("--image", default=DEFAULT_SANDBOX_IMAGE)
    parser.add_argument("--force-rebuild", action="store_true")
    parser.add_argument("--ground-truth-dir", default="", help="Optional report-only labels directory; never passed to analyzer.")
    parser.add_argument("--labels-json", default="", help="Optional report-only label map JSON; never passed to analyzer.")
    return parser.parse_args()


def resolve_api_key(args: argparse.Namespace) -> str:
    key = args.api_key or os.environ.get("PROVLOOM_SCAN_API_KEY") or os.environ.get("PROVLOOM_LLM_API_KEY") or ""
    if not key:
        raise SystemExit("Missing API key. Pass --api-key or set PROVLOOM_SCAN_API_KEY.")
    return key


def select_rows(adapter: BenchmarkV3ReplayAdapter, args: argparse.Namespace) -> list[dict[str, Any]]:
    explicit_ids: list[str] = []
    if args.sample_ids.strip():
        explicit_ids.extend(item.strip() for item in args.sample_ids.split(",") if item.strip())
    if args.sample_file:
        explicit_ids.extend(
            line.strip()
            for line in Path(args.sample_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
    if explicit_ids:
        rows = [adapter.by_sample_id(normalize_sample_id(item)) for item in explicit_ids]
    else:
        rows = adapter.rows(split=args.split or None)
        if args.start or args.end:
            start = normalize_sample_id(args.start or "1")
            end = normalize_sample_id(args.end or "999999")
            rows = [row for row in rows if start <= str(row.get("sample_id")) <= end]
    if args.limit and args.limit > 0:
        rows = rows[: args.limit]
    return rows


def normalize_sample_id(value: str) -> str:
    raw = str(value).strip()
    if raw.upper().startswith("BV3-"):
        return raw.upper()
    return f"BV3-{int(raw):04d}"


def load_prior_rows(summary_path: Path) -> dict[str, dict[str, Any]]:
    if not summary_path.exists():
        return {}
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    return {str(row.get("sample_id")): row for row in payload.get("samples", []) if row.get("sample_id")}


def build_result_row(*, sample_id: str, manifest_row: dict[str, Any], result: Any, elapsed_seconds: float) -> dict[str, Any]:
    report = result.report
    execution = result.execution
    dynamic_payload = result.dynamic_result.to_dict() if result.dynamic_result else {}
    canonical = (result.unified_explanation or {}).get("canonical_assessment", {})
    coverage = (result.unified_explanation or {}).get("coverage_certificate", {})
    token_usage = report.get("llm_token_usage") or getattr(execution, "llm_token_usage", {}) or {}
    return {
        "sample_id": sample_id,
        "status": "completed",
        "split": manifest_row.get("split"),
        "run_id": result.execution_id,
        "exit_code": getattr(execution, "exit_code", None),
        "timed_out": bool(getattr(execution, "timed_out", False)),
        "termination_reason": getattr(execution, "termination_reason", ""),
        "max_steps_exhausted": bool(getattr(execution, "max_steps_exhausted", False)),
        "final_decision": report.get("final_decision") or canonical.get("final_decision"),
        "binary_prediction": report.get("binary_prediction") or canonical.get("binary_prediction"),
        "decision_score": report.get("decision_score") if report.get("decision_score") is not None else canonical.get("decision_score"),
        "review_required": bool(report.get("review_required", canonical.get("review_required", False))),
        "review_lean": report.get("review_lean") or canonical.get("review_lean"),
        "review_reason": report.get("review_reason") or canonical.get("review_reason"),
        "decision_reason": canonical.get("decision_reason"),
        "coverage_state": canonical.get("coverage_state") or coverage.get("coverage_state"),
        "risk_chain_status": canonical.get("risk_chain_status") or coverage.get("risk_chain_status"),
        "security_resolution_status": canonical.get("security_resolution_status") or (coverage.get("security_resolution") or {}).get("status"),
        "runtime_chain_count": len(dynamic_payload.get("runtime_chains", []) or []),
        "policy_violation_count": int(report.get("policy_violation_count") or canonical.get("policy_violation_count") or 0),
        "model": token_usage.get("model") or getattr(execution, "llm_model_name", ""),
        "token_usage": token_usage,
        "llm_request_retry_count": getattr(execution, "llm_request_retry_count", 0),
        "llm_request_retry_reasons": list(getattr(execution, "llm_request_retry_reasons", []) or []),
        "artifacts_dir": result.artifacts_dir,
        "unified_analysis_path": report.get("unified_analysis_path"),
        "markdown_path": report.get("unified_explanation_report_path"),
        "elapsed_seconds": elapsed_seconds,
    }


def load_labels(adapter: BenchmarkV3ReplayAdapter, args: argparse.Namespace) -> dict[str, str]:
    labels: dict[str, str] = {}
    for row in adapter.rows():
        label = normalize_label(row.get("label") or row.get("ground_truth") or row.get("expected_label"))
        if label:
            labels[str(row["sample_id"])] = label
    if args.labels_json:
        payload = json.loads(Path(args.labels_json).read_text(encoding="utf-8"))
        items = payload.items() if isinstance(payload, dict) else ((item.get("sample_id"), item.get("label")) for item in payload)
        for sample_id, label in items:
            normalized = normalize_label(label)
            if sample_id and normalized:
                labels[str(sample_id)] = normalized
    if args.ground_truth_dir:
        root = Path(args.ground_truth_dir)
        for path in root.glob("BV3-*.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            label = normalize_label(payload.get("label") or payload.get("ground_truth") or payload.get("is_malicious"))
            if label:
                labels[path.stem] = label
    return labels


def normalize_label(value: Any) -> str:
    if isinstance(value, bool):
        return "malicious" if value else "benign"
    text = str(value or "").strip().lower()
    if text in {"malicious", "unsafe", "positive", "1", "true"}:
        return "malicious"
    if text in {"benign", "safe", "negative", "0", "false"}:
        return "benign"
    return ""


def write_outputs(
    summary_path: Path,
    rows: list[dict[str, Any]],
    args: argparse.Namespace,
    image: str,
    labels: dict[str, str],
    started_all: float,
    started_at: datetime,
) -> dict[str, Any]:
    metrics = compute_metrics(rows, labels)
    finished_at = datetime.now(timezone.utc)
    total_runtime_seconds = round(time.perf_counter() - started_all, 2)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "benchmark_root": args.benchmark_root,
        "sample_count": len(rows),
        "model": args.model,
        "base_url": args.base_url,
        "api_key_redacted": True,
        "image": image,
        "resume_enabled": bool(args.resume and not args.force),
        "ground_truth_loaded_by_analyzer": False,
        "labels_loaded_for_reporting": bool(labels),
        "elapsed_seconds": total_runtime_seconds,
        "total_runtime_seconds": total_runtime_seconds,
        "total_runtime_human": format_duration(total_runtime_seconds),
        "metrics": metrics,
        "samples": rows,
    }
    summary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=json_default), encoding="utf-8")
    write_csv(summary_path.with_suffix(".csv"), rows, labels)
    write_markdown(summary_path.with_suffix(".md"), payload, labels)
    return payload


def compute_metrics(rows: list[dict[str, Any]], labels: dict[str, str]) -> dict[str, Any]:
    completed = [row for row in rows if row.get("status") == "completed"]
    failed = [row for row in rows if row.get("status") != "completed"]
    decision_counts = Counter(str(row.get("final_decision") or "unknown") for row in completed)
    coverage_counts = Counter(str(row.get("coverage_state") or "unknown") for row in completed)
    risk_counts = Counter(str(row.get("risk_chain_status") or "unknown") for row in completed)
    token_totals = {
        "prompt_tokens": sum(int((row.get("token_usage") or {}).get("prompt_tokens") or 0) for row in completed),
        "completion_tokens": sum(int((row.get("token_usage") or {}).get("completion_tokens") or 0) for row in completed),
        "total_tokens": sum(int((row.get("token_usage") or {}).get("total_tokens") or 0) for row in completed),
        "request_count": sum(int((row.get("token_usage") or {}).get("request_count") or 0) for row in completed),
    }
    metrics: dict[str, Any] = {
        "completed": len(completed),
        "failed": len(failed),
        "decision_counts": dict(sorted(decision_counts.items())),
        "coverage_counts": dict(sorted(coverage_counts.items())),
        "risk_chain_counts": dict(sorted(risk_counts.items())),
        "review_required_count": sum(1 for row in completed if row.get("review_required")),
        "review_rate": ratio(sum(1 for row in completed if row.get("review_required")), len(completed)),
        "confirmed_violation_count": sum(1 for row in completed if row.get("risk_chain_status") == "confirmed_violation"),
        "confirmed_chain_recovery_rate": ratio(sum(1 for row in completed if row.get("risk_chain_status") == "confirmed_violation"), len(completed)),
        "token_totals": token_totals,
        "avg_tokens_per_completed_sample": ratio(token_totals["total_tokens"], len(completed)),
    }
    labeled = [row for row in completed if labels.get(str(row.get("sample_id")))]
    if labeled:
        tp = sum(1 for row in labeled if labels[str(row["sample_id"])] == "malicious" and prediction(row) == "malicious")
        tn = sum(1 for row in labeled if labels[str(row["sample_id"])] == "benign" and prediction(row) == "benign")
        fp = sum(1 for row in labeled if labels[str(row["sample_id"])] == "benign" and prediction(row) == "malicious")
        fn = sum(1 for row in labeled if labels[str(row["sample_id"])] == "malicious" and prediction(row) == "benign")
        true_malicious = tp + fn
        metrics.update(
            {
                "labeled_count": len(labeled),
                "tp": tp,
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "accuracy": ratio(tp + tn, len(labeled)),
                "precision": ratio(tp, tp + fp),
                "recall_detection_rate": ratio(tp, tp + fn),
                "f1": ratio(2 * tp, 2 * tp + fp + fn),
                "fpr": ratio(fp, fp + tn),
                "malicious_chain_recovery_rate": ratio(
                    sum(1 for row in labeled if labels[str(row["sample_id"])] == "malicious" and row.get("risk_chain_status") == "confirmed_violation"),
                    true_malicious,
                ),
            }
        )
    else:
        metrics["labeled_count"] = 0
        metrics["metrics_note"] = "No labels loaded; accuracy/precision/recall/F1 are not computed."
    return metrics


def prediction(row: dict[str, Any]) -> str:
    return str(row.get("binary_prediction") or row.get("final_decision") or "unknown")


def ratio(numerator: float, denominator: float) -> float:
    return round(float(numerator) / float(denominator), 6) if denominator else 0.0


def format_duration(seconds: float) -> str:
    total = int(round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def write_csv(path: Path, rows: list[dict[str, Any]], labels: dict[str, str]) -> None:
    fields = [
        "sample_id",
        "label",
        "status",
        "final_decision",
        "binary_prediction",
        "review_required",
        "decision_score",
        "coverage_state",
        "risk_chain_status",
        "security_resolution_status",
        "exit_code",
        "termination_reason",
        "total_tokens",
        "request_count",
        "elapsed_seconds",
        "artifacts_dir",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            token_usage = row.get("token_usage") or {}
            writer.writerow(
                {
                    "sample_id": row.get("sample_id"),
                    "label": labels.get(str(row.get("sample_id")), ""),
                    "status": row.get("status"),
                    "final_decision": row.get("final_decision"),
                    "binary_prediction": row.get("binary_prediction"),
                    "review_required": row.get("review_required"),
                    "decision_score": row.get("decision_score"),
                    "coverage_state": row.get("coverage_state"),
                    "risk_chain_status": row.get("risk_chain_status"),
                    "security_resolution_status": row.get("security_resolution_status"),
                    "exit_code": row.get("exit_code"),
                    "termination_reason": row.get("termination_reason"),
                    "total_tokens": token_usage.get("total_tokens", 0),
                    "request_count": token_usage.get("request_count", 0),
                    "elapsed_seconds": row.get("elapsed_seconds"),
                    "artifacts_dir": row.get("artifacts_dir"),
                }
            )


def write_markdown(path: Path, payload: dict[str, Any], labels: dict[str, str]) -> None:
    metrics = payload["metrics"]
    lines = [
        "# Benchmark v3 Full-System Scan",
        "",
        f"- Generated at: `{payload['generated_at']}`",
        f"- Started at: `{payload['started_at']}`",
        f"- Finished at: `{payload['finished_at']}`",
        f"- Total runtime: `{payload['total_runtime_human']}` (`{payload['total_runtime_seconds']}` seconds)",
        f"- Model: `{payload['model']}`",
        f"- Base URL: `{payload['base_url']}`",
        f"- Image: `{payload['image']}`",
        f"- API key redacted: `{payload['api_key_redacted']}`",
        f"- Ground truth loaded by analyzer: `{payload['ground_truth_loaded_by_analyzer']}`",
        "",
        "## Metrics",
        "",
    ]
    for key, value in metrics.items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(
        [
            "",
            "## Samples",
            "",
            "| Sample | Label | Status | Final | Review | Score | Coverage | Risk Chain | Security | Tokens | Requests |",
            "|---|---|---|---|---:|---:|---|---|---|---:|---:|",
        ]
    )
    for row in payload["samples"]:
        token_usage = row.get("token_usage") or {}
        sample_id = str(row.get("sample_id") or "")
        lines.append(
            "| "
            + " | ".join(
                [
                    sample_id,
                    labels.get(sample_id, ""),
                    str(row.get("status") or ""),
                    str(row.get("final_decision") or ""),
                    str(row.get("review_required") or False),
                    str(row.get("decision_score") or ""),
                    str(row.get("coverage_state") or ""),
                    str(row.get("risk_chain_status") or ""),
                    str(row.get("security_resolution_status") or ""),
                    str(token_usage.get("total_tokens", 0)),
                    str(token_usage.get("request_count", 0)),
                ]
            )
            + " |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def json_default(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return str(value)


if __name__ == "__main__":
    raise SystemExit(main())
