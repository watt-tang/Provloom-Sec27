from __future__ import annotations

import argparse
import csv
import hashlib
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
    summary_path = output_root / "summary.json"
    if args.evaluate_only:
        return evaluate_only(args, output_root, summary_path)
    output_root.mkdir(parents=True, exist_ok=True)

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
    parser.add_argument("--evaluate-only", action="store_true", help="Only evaluate an existing summary.json; never run analyzer, LLM, Docker, or pipelines.")
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


def evaluate_only(args: argparse.Namespace, output_root: Path, summary_path: Path) -> int:
    if not any(item == "--output-root" or item.startswith("--output-root=") for item in sys.argv):
        raise SystemExit("--evaluate-only requires an explicit --output-root.")
    if not args.ground_truth_dir:
        raise SystemExit("--evaluate-only requires --ground-truth-dir.")
    if not summary_path.exists():
        raise SystemExit(f"--evaluate-only requires existing prediction file: {summary_path}")

    prediction_bytes = summary_path.read_bytes()
    prediction_payload = json.loads(prediction_bytes.decode("utf-8"))
    rows = list(prediction_payload.get("samples", []) or [])
    if not isinstance(rows, list):
        raise SystemExit(f"Prediction file has invalid samples field: {summary_path}")

    # Ground truth is intentionally loaded only after the prediction file has been
    # fully parsed. It is used for report-only metrics and is never passed to the analyzer.
    ground_truth = load_ground_truth_records(Path(args.ground_truth_dir))
    metrics_payload = build_evaluation_payload(
        rows=rows,
        ground_truth=ground_truth,
        prediction_file=summary_path,
        prediction_sha256=hashlib.sha256(prediction_bytes).hexdigest(),
        ground_truth_dir=Path(args.ground_truth_dir).resolve(),
        source_summary=prediction_payload,
    )
    write_evaluation_outputs(output_root, metrics_payload)
    print("[EVALUATE_ONLY]", output_root / "metrics.json", flush=True)
    print(json.dumps(metrics_payload["overall"], ensure_ascii=False, indent=2), flush=True)
    return 0


def load_ground_truth_records(root: Path) -> dict[str, dict[str, Any]]:
    if not root.exists():
        raise SystemExit(f"Ground truth directory does not exist: {root}")
    records: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("BV3-*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        sample_id = str(payload.get("sample_id") or path.stem)
        records[sample_id] = payload
    if not records:
        raise SystemExit(f"No BV3-*.json ground truth files found in: {root}")
    return records


def build_evaluation_payload(
    *,
    rows: list[dict[str, Any]],
    ground_truth: dict[str, dict[str, Any]],
    prediction_file: Path,
    prediction_sha256: str,
    ground_truth_dir: Path,
    source_summary: dict[str, Any],
) -> dict[str, Any]:
    prediction_by_id = {str(row.get("sample_id")): row for row in rows if row.get("sample_id")}
    evaluated_sample_ids = sorted(sample_id for sample_id in ground_truth if sample_id in prediction_by_id)
    missing_prediction_ids = sorted(sample_id for sample_id in ground_truth if sample_id not in prediction_by_id)
    failed_sample_ids = sorted(
        sample_id
        for sample_id in evaluated_sample_ids
        if str(prediction_by_id[sample_id].get("status") or "") != "completed"
    )
    evaluated_rows = [
        evaluation_record(sample_id, prediction_by_id[sample_id], ground_truth[sample_id])
        for sample_id in evaluated_sample_ids
    ]
    completed_rows = [row for row in evaluated_rows if row["prediction_status"] == "completed"]
    overall = metric_bundle(completed_rows)
    overall.update(
        {
            "evaluated_count": len(evaluated_sample_ids),
            "completed_evaluated_count": len(completed_rows),
            "missing_prediction_count": len(missing_prediction_ids),
            "failed_sample_count": len(failed_sample_ids),
            "missing_prediction_ids": missing_prediction_ids,
            "failed_sample_ids": failed_sample_ids,
        }
    )
    groups = {
        "per_outcome": grouped_metrics(completed_rows, "expected_policy_outcome"),
        "per_risk_family": grouped_metrics(completed_rows, "risk_family"),
        "per_split": grouped_metrics(completed_rows, "split"),
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evaluation_only": True,
        "prediction_file": str(prediction_file),
        "prediction_sha256": prediction_sha256,
        "ground_truth_dir": str(ground_truth_dir),
        "ground_truth_loaded_by_analyzer": False,
        "source_summary_generated_at": source_summary.get("generated_at"),
        "source_model": source_summary.get("model"),
        "source_image": source_summary.get("image"),
        "overall": overall,
        "groups": groups,
        "samples": evaluated_rows,
        "metric_definitions": metric_definitions(),
    }


def evaluation_record(sample_id: str, prediction_row: dict[str, Any], gt: dict[str, Any]) -> dict[str, Any]:
    outcome = str(gt.get("expected_policy_outcome") or "unknown")
    expected = expected_binary_label(gt)
    pred = prediction(prediction_row)
    risk_chain_status = str(prediction_row.get("risk_chain_status") or "")
    coverage_state = str(prediction_row.get("coverage_state") or "")
    expected_complete_chains = list(gt.get("expected_complete_chains") or [])
    forbidden_false_chains = list(gt.get("forbidden_false_chains") or [])
    return {
        "sample_id": sample_id,
        "split": prediction_row.get("split") or gt.get("split") or "",
        "expected_policy_outcome": outcome,
        "expected_label": expected,
        "predicted_label": pred,
        "correct": expected == pred,
        "risk_family": str(gt.get("risk_family") or "unknown"),
        "control_conditions": list(gt.get("control_conditions") or []),
        "authorization_context": list(gt.get("authorization_context") or []),
        "prediction_status": str(prediction_row.get("status") or "unknown"),
        "final_decision": prediction_row.get("final_decision"),
        "binary_prediction": prediction_row.get("binary_prediction"),
        "review_required": bool(prediction_row.get("review_required")),
        "decision_score": prediction_row.get("decision_score"),
        "coverage_state": coverage_state,
        "risk_chain_status": risk_chain_status,
        "security_resolution_status": prediction_row.get("security_resolution_status"),
        "confirmed_violation_chain": risk_chain_status == "confirmed_violation",
        "complete_chain_recovered": bool(expected_complete_chains) and risk_chain_status == "confirmed_violation" and coverage_state == "complete",
        "false_closure": expected == "benign" and risk_chain_status == "confirmed_violation",
        "has_expected_complete_chain": bool(expected_complete_chains),
        "has_forbidden_false_chain": bool(forbidden_false_chains),
        "is_benign_lookalike": outcome == "benign_lookalike",
        "is_trusted_allowed": outcome == "trusted_allowed" or any("scoped approval" in str(item).lower() for item in gt.get("authorization_context") or []),
        "is_error_condition": outcome == "review_coverage" or any(str(item) != "covered" for item in gt.get("control_conditions") or []),
    }


def expected_binary_label(gt: dict[str, Any]) -> str:
    outcome = str(gt.get("expected_policy_outcome") or "").lower()
    if outcome in {"confirmed_violation", "candidate_violation", "violation"}:
        return "malicious"
    return "benign"


def metric_bundle(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    tp = sum(1 for row in rows if row["expected_label"] == "malicious" and row["predicted_label"] == "malicious")
    tn = sum(1 for row in rows if row["expected_label"] == "benign" and row["predicted_label"] == "benign")
    fp = sum(1 for row in rows if row["expected_label"] == "benign" and row["predicted_label"] == "malicious")
    fn = sum(1 for row in rows if row["expected_label"] == "malicious" and row["predicted_label"] == "benign")
    benign_lookalike = [row for row in rows if row["is_benign_lookalike"]]
    trusted_allowed = [row for row in rows if row["is_trusted_allowed"]]
    error_condition = [row for row in rows if row["is_error_condition"]]
    expected_complete = [row for row in rows if row["has_expected_complete_chain"]]
    malicious_rows = [row for row in rows if row["expected_label"] == "malicious"]
    return {
        "count": total,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": ratio(tp + tn, total),
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "specificity": ratio(tn, tn + fp),
        "fpr": ratio(fp, fp + tn),
        "benign_lookalike_fpr": ratio(sum(1 for row in benign_lookalike if row["predicted_label"] == "malicious"), len(benign_lookalike)),
        "trusted_allowed_fpr": ratio(sum(1 for row in trusted_allowed if row["predicted_label"] == "malicious"), len(trusted_allowed)),
        "review_rate": ratio(sum(1 for row in rows if row["review_required"]), total),
        "error_capture_rate": ratio(sum(1 for row in error_condition if row["review_required"]), len(error_condition)),
        "confirmed_violation_chain_recall": ratio(sum(1 for row in malicious_rows if row["confirmed_violation_chain"]), len(malicious_rows)),
        "complete_chain_recall": ratio(sum(1 for row in expected_complete if row["complete_chain_recovered"]), len(expected_complete)),
        "false_closure_rate": ratio(sum(1 for row in rows if row["false_closure"]), sum(1 for row in rows if row["expected_label"] == "benign")),
        "decision_counts": dict(sorted(Counter(row["predicted_label"] for row in rows).items())),
        "review_count": sum(1 for row in rows if row["review_required"]),
    }


def grouped_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row.get(key) or "unknown"), []).append(row)
    return {name: metric_bundle(group_rows) for name, group_rows in sorted(groups.items())}


def write_evaluation_outputs(output_root: Path, payload: dict[str, Any]) -> None:
    (output_root / "metrics.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=json_default), encoding="utf-8")
    write_evaluation_csv(output_root / "metrics.csv", payload)
    write_evaluation_markdown(output_root / "metrics.md", payload)


def write_evaluation_csv(path: Path, payload: dict[str, Any]) -> None:
    fields = [
        "group_type",
        "group",
        "count",
        "tp",
        "tn",
        "fp",
        "fn",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "specificity",
        "fpr",
        "benign_lookalike_fpr",
        "trusted_allowed_fpr",
        "review_rate",
        "error_capture_rate",
        "confirmed_violation_chain_recall",
        "complete_chain_recall",
        "false_closure_rate",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(flat_metric_row("overall", "overall", payload["overall"]))
        for group_type, group_payload in payload["groups"].items():
            for group_name, metrics in group_payload.items():
                writer.writerow(flat_metric_row(group_type, group_name, metrics))


def flat_metric_row(group_type: str, group_name: str, metrics: dict[str, Any]) -> dict[str, Any]:
    cm = metrics.get("confusion_matrix") or {}
    return {
        "group_type": group_type,
        "group": group_name,
        "count": metrics.get("count", 0),
        "tp": cm.get("tp", 0),
        "tn": cm.get("tn", 0),
        "fp": cm.get("fp", 0),
        "fn": cm.get("fn", 0),
        "accuracy": metrics.get("accuracy", 0.0),
        "precision": metrics.get("precision", 0.0),
        "recall": metrics.get("recall", 0.0),
        "f1": metrics.get("f1", 0.0),
        "specificity": metrics.get("specificity", 0.0),
        "fpr": metrics.get("fpr", 0.0),
        "benign_lookalike_fpr": metrics.get("benign_lookalike_fpr", 0.0),
        "trusted_allowed_fpr": metrics.get("trusted_allowed_fpr", 0.0),
        "review_rate": metrics.get("review_rate", 0.0),
        "error_capture_rate": metrics.get("error_capture_rate", 0.0),
        "confirmed_violation_chain_recall": metrics.get("confirmed_violation_chain_recall", 0.0),
        "complete_chain_recall": metrics.get("complete_chain_recall", 0.0),
        "false_closure_rate": metrics.get("false_closure_rate", 0.0),
    }


def write_evaluation_markdown(path: Path, payload: dict[str, Any]) -> None:
    overall = payload["overall"]
    lines = [
        "# Benchmark v3 Evaluation Metrics",
        "",
        f"- Evaluation only: `{payload['evaluation_only']}`",
        f"- Prediction file: `{payload['prediction_file']}`",
        f"- Prediction SHA256: `{payload['prediction_sha256']}`",
        f"- Ground truth dir: `{payload['ground_truth_dir']}`",
        f"- Ground truth loaded by analyzer: `{payload['ground_truth_loaded_by_analyzer']}`",
        f"- Evaluated count: `{overall['evaluated_count']}`",
        f"- Missing prediction count: `{overall['missing_prediction_count']}`",
        f"- Failed sample count: `{overall['failed_sample_count']}`",
        "",
        "## Overall",
        "",
    ]
    for key, value in overall.items():
        lines.append(f"- {key}: `{value}`")
    for group_type, group_payload in payload["groups"].items():
        lines.extend(["", f"## {group_type}", "", "| Group | Count | Accuracy | Precision | Recall | F1 | FPR | Review | Chain Recall | False Closure |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"])
        for group_name, metrics in group_payload.items():
            lines.append(
                "| "
                + " | ".join(
                    [
                        group_name,
                        str(metrics.get("count", 0)),
                        str(metrics.get("accuracy", 0.0)),
                        str(metrics.get("precision", 0.0)),
                        str(metrics.get("recall", 0.0)),
                        str(metrics.get("f1", 0.0)),
                        str(metrics.get("fpr", 0.0)),
                        str(metrics.get("review_rate", 0.0)),
                        str(metrics.get("confirmed_violation_chain_recall", 0.0)),
                        str(metrics.get("false_closure_rate", 0.0)),
                    ]
                )
                + " |"
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def metric_definitions() -> dict[str, str]:
    return {
        "prediction_label": "binary_prediction if present, otherwise final_decision",
        "malicious_ground_truth": "expected_policy_outcome in {confirmed_violation, candidate_violation, violation}",
        "benign_ground_truth": "all other expected_policy_outcome values, including benign_lookalike, trusted_allowed, and review_coverage",
        "error_capture_rate": "share of review_coverage or non-covered control-condition samples marked review_required",
        "confirmed_violation_chain_recall": "share of malicious samples whose prediction has risk_chain_status=confirmed_violation",
        "complete_chain_recall": "share of samples with expected_complete_chains whose prediction has risk_chain_status=confirmed_violation and coverage_state=complete",
        "false_closure_rate": "share of benign samples whose prediction has risk_chain_status=confirmed_violation",
    }


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
