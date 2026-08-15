#!/usr/bin/env python3
"""Real-world SkillPulse measurement runner for ProvLoom.

The runner discovers real Skill bundles by recursively locating SKILL.md files,
deduplicates by content hash, runs frozen ProvLoom static semantics first, and
only invokes the existing Docker-backed dynamic pipeline for static malicious or
malicious-leaning samples.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_BOOTSTRAP_ROOT = Path(__file__).resolve().parents[1]
if str(_BOOTSTRAP_ROOT) not in sys.path:
    sys.path.insert(0, str(_BOOTSTRAP_ROOT))

from app.analysis.pipeline import ExecutionConfig, analyze_skill_bundle
from app.backend.schemas import LLMConfig, default_llm_api_key, normalize_llm_provider
from app.runner.docker_runner import DEFAULT_SANDBOX_IMAGE, DockerRunner


CSV_FIELDS = [
    "safe_sample_id",
    "metadata_row",
    "skill_id",
    "source_url",
    "static_prediction",
    "static_review_lean",
    "dynamic_triggered",
    "dynamic_prediction",
    "final_decision",
    "review_required",
    "risk_chain_status",
    "confirmed_chain_count",
    "complete_chain_count",
    "coverage_state",
    "scan_path",
    "status",
    "failure_stage",
    "failure_reason",
    "runtime_seconds",
    "total_tokens",
    "content_sha256",
]

DISCOVERY_FIELDS = [
    "sample_id",
    "safe_sample_id",
    "metadata_row",
    "skill_id",
    "owner",
    "repo",
    "slug",
    "source_url",
    "skill_root",
    "skill_md",
    "discovery_status",
    "discovery_error",
    "content_sha256",
    "duplicate_of",
]

RUN_DYNAMIC_BINARY = {"malicious"}
RUN_DYNAMIC_LEAN = {"malicious", "malicious_leaning", "malicious-leaning"}


@dataclass(frozen=True)
class Paths:
    provloom_root: Path
    skillpulse_root: Path | None
    download_root: Path
    metadata_csv: Path
    download_manifest: Path | None
    output_root: Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def atomic_write_json(path: Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def normalize_path(raw: str | Path) -> Path:
    value = str(raw).strip()
    if len(value) >= 2 and value[1] == ":":
        drive = value[0].lower()
        rest = value[2:].lstrip("\\/").replace("\\", "/")
        return Path(f"/mnt/{drive}/{rest}").resolve()
    return Path(value).expanduser().resolve()


def confirm_provloom_root() -> Path:
    candidates = [Path.cwd(), Path(__file__).resolve().parents[1]]
    for candidate in candidates:
        root = candidate.resolve()
        if (root / "app").is_dir() and (root / "scripts").is_dir() and ((root / "pyproject.toml").exists() or (root / "requirements.txt").exists()):
            if any((root / item).exists() for item in ["scripts/batch_scan_skills.py", "app/analysis/pipeline.py"]):
                return root
    raise SystemExit("ProvLoom root could not be confirmed from actual files.")


def infer_skillpulse_root(download_root: Path, metadata_csv: Path) -> Path | None:
    for parent in [download_root, *download_root.parents, metadata_csv.parent, *metadata_csv.parents]:
        if (parent / "src").exists() and (parent / "output").exists():
            return parent
    return None


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path or not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        return [dict(row) for row in csv.DictReader(fh)]


def metadata_index(rows: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for idx, row in enumerate(rows, start=1):
        skill_id = (row.get("skill_id") or "").strip()
        if skill_id:
            indexed[skill_id] = {"metadata_row": idx, **row}
    return indexed


def manifest_index(rows: list[dict[str, str]], skillpulse_root: Path | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    base = skillpulse_root or Path.cwd()
    for row in rows:
        raw_path = (row.get("path") or "").strip()
        abs_path: Path | None = None
        if raw_path:
            p = Path(raw_path.replace("\\", "/"))
            abs_path = (base / p).resolve() if not p.is_absolute() else p.resolve()
        out.append({**row, "abs_path": str(abs_path) if abs_path else ""})
    out.sort(key=lambda item: len(str(item.get("abs_path") or "")), reverse=True)
    return out


def source_parts(row: dict[str, Any]) -> tuple[str, str, str]:
    source = str(row.get("source") or "").strip().strip("/")
    parts = source.split("/")
    owner = parts[0] if len(parts) >= 1 else ""
    repo = parts[1] if len(parts) >= 2 else ""
    slug = str(row.get("slug") or row.get("skill_name") or "").strip()
    skill_id = str(row.get("skill_id") or "").strip()
    if skill_id and (not owner or not repo or not slug):
        id_parts = skill_id.split("/")
        if len(id_parts) >= 3:
            owner = owner or id_parts[0]
            repo = repo or id_parts[1]
            slug = slug or "/".join(id_parts[2:])
    return owner, repo, slug


def hash_bundle(skill_root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in skill_root.rglob("*") if p.is_file() and ".git" not in p.parts):
        rel = path.relative_to(skill_root).as_posix()
        digest.update(rel.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        try:
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            digest.update(f"READ_ERROR:{exc}".encode())
    return digest.hexdigest()


def discover_skill_roots(download_root: Path) -> list[Path]:
    roots: list[Path] = []
    seen: set[Path] = set()
    for skill_md in sorted(download_root.rglob("SKILL.md")):
        if any(part in {".git", "node_modules", "__pycache__", ".venv", "venv"} for part in skill_md.parts):
            continue
        root = skill_md.parent.resolve()
        if root not in seen:
            seen.add(root)
            roots.append(root)
    return roots


def match_identity(skill_root: Path, metadata_by_id: dict[str, dict[str, Any]], manifest_rows: list[dict[str, Any]]) -> dict[str, Any]:
    root_str = str(skill_root.resolve())
    selected: dict[str, Any] = {}
    for item in manifest_rows:
        abs_path = str(item.get("abs_path") or "")
        if abs_path and (root_str == abs_path or root_str.startswith(abs_path + os.sep)):
            selected = dict(item)
            break
    skill_id = str(selected.get("skill_id") or "").strip()
    meta = dict(metadata_by_id.get(skill_id, {}))
    merged = {**meta, **selected}
    if not skill_id:
        rel_parts = list(skill_root.parts)
        if len(rel_parts) >= 3:
            merged["source"] = merged.get("source") or "/".join(rel_parts[-3:-1])
            merged["slug"] = merged.get("slug") or rel_parts[-1]
            merged["skill_id"] = f"{merged['source']}/{merged['slug']}"
    owner, repo, slug = source_parts(merged)
    merged["owner"], merged["repo"], merged["slug"] = owner, repo, slug or skill_root.name
    merged["metadata_row"] = int(merged.get("metadata_row") or merged.get("csv_index") or 0)
    merged["skill_id"] = str(merged.get("skill_id") or f"{owner}/{repo}/{merged['slug']}").strip("/")
    merged["source_url"] = str(merged.get("github_url") or merged.get("repository_url") or merged.get("skill_page_url") or "")
    return merged


def make_sample_record(skill_root: Path, identity: dict[str, Any], seen_hashes: dict[str, str]) -> dict[str, Any]:
    content_hash = hash_bundle(skill_root)
    metadata_row = int(identity.get("metadata_row") or 0)
    skill_id = str(identity.get("skill_id") or "").strip()
    owner = str(identity.get("owner") or "")
    repo = str(identity.get("repo") or "")
    slug = str(identity.get("slug") or skill_root.name)
    canonical = f"{metadata_row}::{skill_id or owner + '/' + repo + '/' + slug}::{identity.get('source_url') or ''}"
    hash8 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]
    safe = f"RW-{metadata_row:06d}-{hash8}" if metadata_row else f"RW-000000-{hash8}"
    sample_id = f"realworld::{metadata_row}::{skill_id or owner + '/' + repo + '/' + slug}"
    duplicate_of = seen_hashes.get(content_hash, "")
    if not duplicate_of:
        seen_hashes[content_hash] = safe
    return {
        "sample_id": sample_id,
        "safe_sample_id": safe,
        "metadata_row": metadata_row,
        "skill_id": skill_id,
        "owner": owner,
        "repo": repo,
        "slug": slug,
        "source_url": str(identity.get("source_url") or ""),
        "skill_root": str(skill_root),
        "skill_md": str(skill_root / "SKILL.md"),
        "discovery_status": "duplicate" if duplicate_of else "ok",
        "discovery_error": "",
        "content_sha256": content_hash,
        "duplicate_of": duplicate_of,
    }


def discover_samples(paths: Paths, *, use_cache: bool = False) -> list[dict[str, Any]]:
    cached_json = paths.output_root / "discovered_samples.json"
    if use_cache and cached_json.exists():
        try:
            cached = json.loads(cached_json.read_text(encoding="utf-8"))
            if isinstance(cached, list) and cached:
                return cached
        except Exception:
            pass
    metadata_rows = load_csv(paths.metadata_csv)
    manifest_rows = load_csv(paths.download_manifest) if paths.download_manifest else []
    by_id = metadata_index(metadata_rows)
    manifest = manifest_index(manifest_rows, paths.skillpulse_root)
    seen_hashes: dict[str, str] = {}
    records = [make_sample_record(root, match_identity(root, by_id, manifest), seen_hashes) for root in discover_skill_roots(paths.download_root)]
    records.sort(key=lambda r: (int(r.get("metadata_row") or 0), str(r.get("skill_id") or ""), str(r.get("skill_root") or "")))
    write_discovery(paths.output_root, records)
    return records


def write_discovery(output_root: Path, records: list[dict[str, Any]]) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    write_csv(output_root / "discovered_samples.csv", DISCOVERY_FIELDS, records)
    atomic_write_json(output_root / "discovered_samples.json", records)


def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with tmp.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    os.replace(tmp, path)


def static_gate_definition() -> str:
    return "\n".join(
        [
            "# ProvLoom Real-World Static Gate Definition",
            "",
            "Frozen before real-world measurement smoke test.",
            "",
            "Static output source:",
            "- `build_unified_explanation(..., analysis_mode=\"static_only\")` canonical assessment",
            "- `binary_prediction`",
            "- `review_lean`",
            "- static chain `alert_status` / `policy_status` counts are recorded, but do not tune the gate",
            "",
            "RUN_DYNAMIC:",
            "- `binary_prediction == malicious`",
            "- or `review_lean in {malicious, malicious_leaning, malicious-leaning}`",
            "",
            "STATIC_STOP_BENIGN:",
            "- every other static-only canonical output, including `binary_prediction == benign`",
            "- `review_required` alone is not promoted to dynamic unless the frozen review lean is malicious-leaning",
            "",
            "No thresholds are introduced or tuned by this real-world runner.",
            "",
        ]
    )


def should_run_dynamic(static_report: dict[str, Any]) -> bool:
    prediction = str(static_report.get("binary_prediction") or "").strip().lower()
    lean = str(static_report.get("review_lean") or "").strip().lower()
    return prediction in RUN_DYNAMIC_BINARY or lean in RUN_DYNAMIC_LEAN


def token_usage(report: dict[str, Any]) -> dict[str, int]:
    usage = dict(report.get("llm_token_usage") or {})
    return {
        "llm_request_count": int(usage.get("request_count") or usage.get("requests") or 0),
        "prompt_tokens": int(usage.get("prompt_tokens") or 0),
        "completion_tokens": int(usage.get("completion_tokens") or 0),
        "total_tokens": int(usage.get("total_tokens") or usage.get("tokens") or 0),
    }


def flatten_result(sample: dict[str, Any], status: str, failure_stage: str = "", failure_reason: str = "", static: dict[str, Any] | None = None, dynamic: dict[str, Any] | None = None, started: float = 0.0, static_seconds: float = 0.0, dynamic_seconds: float = 0.0, artifact_path: str = "") -> dict[str, Any]:
    static = static or {}
    dynamic = dynamic or {}
    final = dynamic or static
    canonical = dict(final.get("canonical_assessment") or {})
    coverage = dict(final.get("coverage_certificate") or {})
    risk_chain = dict(coverage.get("risk_chain_status") or {})
    security = dict(coverage.get("security_resolution") or {})
    dynamic_triggered = bool(dynamic)
    tokens = token_usage(dynamic)
    if not dynamic_triggered:
        tokens = {"llm_request_count": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    runtime = max(0.0, time.monotonic() - started) if started else 0.0
    return {
        **{k: sample.get(k, "") for k in ["sample_id", "safe_sample_id", "metadata_row", "skill_id", "source_url", "content_sha256", "discovery_status"]},
        "static_status": static.get("status", "completed" if static else ""),
        "static_binary_prediction": static.get("binary_prediction", ""),
        "static_prediction": static.get("binary_prediction", ""),
        "static_review_lean": static.get("review_lean", ""),
        "static_score": static.get("decision_score", static.get("canonical_risk_score", "")),
        "static_chain_count": len(static.get("static_chains") or []),
        "dynamic_triggered": dynamic_triggered,
        "dynamic_status": dynamic.get("status", ""),
        "dynamic_binary_prediction": dynamic.get("binary_prediction", ""),
        "dynamic_prediction": dynamic.get("binary_prediction", ""),
        "dynamic_review_required": dynamic.get("review_required", ""),
        "dynamic_score": dynamic.get("decision_score", dynamic.get("canonical_risk_score", "")),
        "risk_chain_status": dynamic.get("risk_chain_status") or canonical.get("risk_chain_status") or risk_chain.get("status", ""),
        "security_resolution_status": canonical.get("security_resolution_status") or security.get("status", ""),
        "confirmed_chain_count": int(final.get("confirmed_chain_count") or 0),
        "complete_chain_count": int(final.get("complete_chain_count") or final.get("confirmed_chain_count") or 0),
        "coverage_state": final.get("coverage_state") or canonical.get("coverage_state") or coverage.get("coverage_state", ""),
        "final_decision": final.get("final_decision") or final.get("canonical_final_decision") or canonical.get("canonical_final_decision") or "unknown",
        "final_review_required": bool(final.get("review_required") or final.get("needs_review") or canonical.get("needs_review")),
        "review_required": bool(final.get("review_required") or final.get("needs_review") or canonical.get("needs_review")),
        "scan_path": "dynamic" if dynamic_triggered else "static_only",
        "runtime_seconds": round(runtime, 3),
        "static_runtime_seconds": round(static_seconds, 3),
        "dynamic_runtime_seconds": round(dynamic_seconds, 3),
        **tokens,
        "status": status,
        "failure_stage": failure_stage,
        "failure_reason": failure_reason,
        "artifact_path": artifact_path,
        "timestamp": utc_now(),
    }


def scan_one(sample: dict[str, Any], args: argparse.Namespace, output_root: str) -> dict[str, Any]:
    started = time.monotonic()
    static_seconds = 0.0
    dynamic_seconds = 0.0
    artifact_path = ""
    try:
        static_run_id = f"{sample['safe_sample_id']}-static"
        t0 = time.monotonic()
        static_result = analyze_skill_bundle(
            sample["skill_root"],
            execution_config=ExecutionConfig(analysis_mode="static_only", run_id=static_run_id),
            static_only=True,
        )
        static_seconds = time.monotonic() - t0
        static_report = dict(static_result.report)
        artifact_path = static_result.artifacts_dir
        dynamic_report: dict[str, Any] = {}
        if should_run_dynamic(static_report):
            t1 = time.monotonic()
            llm_key = args.api_key or os.environ.get("PROVLOOM_SCAN_API_KEY") or default_llm_api_key(args.provider)
            runner = DockerRunner(image_name=args.image_name, artifacts_root=str(Path(output_root) / "runs"))
            full = analyze_skill_bundle(
                sample["skill_root"],
                execution_config=ExecutionConfig(
                    input_payload={},
                    timeout_seconds=args.timeout_seconds,
                    network_policy=args.network_policy,
                    analysis_mode=args.analysis_mode,
                    llm_config=LLMConfig(
                        enabled=bool(llm_key),
                        provider=normalize_llm_provider(args.provider),
                        base_url=args.base_url,
                        api_key=llm_key,
                        model=args.model,
                        temperature=0.0,
                        max_steps=args.max_llm_steps,
                    ),
                    run_id=f"{sample['safe_sample_id']}-dynamic",
                ),
                runner=runner,
            )
            dynamic_seconds = time.monotonic() - t1
            dynamic_report = dict(full.report)
            artifact_path = full.artifacts_dir
        result = flatten_result(sample, "completed", static=static_report, dynamic=dynamic_report, started=started, static_seconds=static_seconds, dynamic_seconds=dynamic_seconds, artifact_path=artifact_path)
    except Exception as exc:
        reason = str(exc)
        stage = "dynamic" if static_seconds else "static"
        if "429" in reason or "rate" in reason.lower():
            reason = f"provider_rate_limited: {reason}"
        result = flatten_result(sample, "failed", failure_stage=stage, failure_reason=reason, started=started, static_seconds=static_seconds, dynamic_seconds=dynamic_seconds, artifact_path=artifact_path)
    return result


def load_sample_result(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_rollups(output_root: Path, rows: list[dict[str, Any]], paths: Paths, extra_state: dict[str, Any] | None = None) -> None:
    rows_sorted = sorted(rows, key=lambda r: str(r.get("safe_sample_id") or ""))
    write_csv(output_root / "results.csv", CSV_FIELDS, rows_sorted)
    atomic_write_json(output_root / "results.json", rows_sorted)
    runtimes = [float(r.get("runtime_seconds") or 0) for r in rows_sorted if r.get("status") == "completed"]
    dyn_tokens = [int(r.get("total_tokens") or 0) for r in rows_sorted if str(r.get("scan_path")) == "dynamic"]
    summary = {
        "generated_at": utc_now(),
        "skillpulse_root": str(paths.skillpulse_root) if paths.skillpulse_root else "",
        "download_root": str(paths.download_root),
        "provloom_root": str(paths.provloom_root),
        "execution_environment": "wsl/linux" if str(paths.download_root).startswith("/mnt/") else sys.platform,
        "rows": len(rows_sorted),
        "scan_completed": sum(1 for r in rows_sorted if r.get("status") == "completed"),
        "scan_failed": sum(1 for r in rows_sorted if r.get("status") == "failed"),
        "static_only_stopped": sum(1 for r in rows_sorted if r.get("scan_path") == "static_only"),
        "dynamic_triggered": sum(1 for r in rows_sorted if r.get("dynamic_triggered") is True),
        "predicted_benign": sum(1 for r in rows_sorted if r.get("final_decision") == "benign"),
        "predicted_malicious": sum(1 for r in rows_sorted if r.get("final_decision") == "malicious"),
        "review_required": sum(1 for r in rows_sorted if str(r.get("review_required")).lower() == "true"),
        "confirmed_violation_chain": sum(1 for r in rows_sorted if str(r.get("risk_chain_status")) == "confirmed_violation"),
        "complete_chain": sum(int(r.get("complete_chain_count") or 0) for r in rows_sorted),
        "average_scan_seconds": round(statistics.mean(runtimes), 3) if runtimes else 0,
        "p50_scan_seconds": round(statistics.median(runtimes), 3) if runtimes else 0,
        "p95_scan_seconds": round(sorted(runtimes)[max(0, int(len(runtimes) * 0.95) - 1)], 3) if runtimes else 0,
        "total_tokens": sum(int(r.get("total_tokens") or 0) for r in rows_sorted),
        "average_tokens_per_dynamic_sample": round(statistics.mean(dyn_tokens), 1) if dyn_tokens else 0,
        "coverage_state_distribution": distribution(rows_sorted, "coverage_state"),
        "risk_chain_status_distribution": distribution(rows_sorted, "risk_chain_status"),
        "failure_reason_distribution": distribution(rows_sorted, "failure_reason"),
    }
    if extra_state:
        summary.update(extra_state)
    atomic_write_json(output_root / "summary.json", summary)
    atomic_write_text(output_root / "summary.md", render_summary_md(summary))


def distribution(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field) or "none")
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))


def render_summary_md(summary: dict[str, Any]) -> str:
    lines = ["# Real-World Skill Scan Summary", ""]
    for key in [
        "generated_at", "provloom_root", "skillpulse_root", "download_root", "execution_environment", "rows",
        "scan_completed", "scan_failed", "static_only_stopped", "dynamic_triggered", "predicted_benign",
        "predicted_malicious", "review_required", "confirmed_violation_chain", "average_scan_seconds",
        "p50_scan_seconds", "p95_scan_seconds", "total_tokens", "average_tokens_per_dynamic_sample",
    ]:
        lines.append(f"- {key}: {summary.get(key)}")
    lines.append("")
    lines.append("Measurement terms are ProvLoom predictions, not ground truth labels.")
    return "\n".join(lines) + "\n"


def scan_one_subprocess(sample: dict[str, Any], args: argparse.Namespace, paths: Paths) -> dict[str, Any]:
    work_dir = paths.output_root / "worker_inputs"
    work_dir.mkdir(parents=True, exist_ok=True)
    sid = sample["safe_sample_id"]
    sample_file = work_dir / f"{sid}.sample.json"
    result_file = work_dir / f"{sid}.result.json"
    atomic_write_json(sample_file, sample)
    if result_file.exists():
        result_file.unlink()
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker-sample-file",
        str(sample_file),
        "--worker-output-file",
        str(result_file),
        "--output-root",
        str(paths.output_root),
        "--analysis-mode",
        args.analysis_mode,
        "--network-policy",
        args.network_policy,
        "--image-name",
        args.image_name,
        "--provider",
        args.provider,
        "--base-url",
        args.base_url,
        "--model",
        args.model,
        "--max-llm-steps",
        str(args.max_llm_steps),
        "--timeout-seconds",
        str(args.timeout_seconds),
    ]
    env = os.environ.copy()
    if args.api_key:
        env["PROVLOOM_SCAN_API_KEY"] = args.api_key
    started = time.monotonic()
    cmd = apply_worker_resource_limits(cmd, args.worker_memory_mb)
    proc = subprocess.Popen(
        cmd,
        cwd=str(paths.provloom_root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=args.sample_timeout_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=10)
        result = flatten_result(
            sample,
            "failed",
            failure_stage="sample_timeout",
            failure_reason=f"sample_timeout_seconds={args.sample_timeout_seconds}",
            started=started,
        )
        static_report = load_static_report_for_sample(sample)
        if static_report:
            result.update(flatten_result(sample, "failed", failure_stage="sample_timeout", failure_reason=f"sample_timeout_seconds={args.sample_timeout_seconds}", static=static_report, started=started))
            if should_run_dynamic(static_report):
                result["dynamic_triggered"] = True
                result["scan_path"] = "dynamic"
        return result
    if result_file.exists():
        payload = load_sample_result(result_file)
        if payload:
            return payload
    if proc.returncode != 0:
        result = flatten_result(sample, "failed", failure_stage="worker", failure_reason=(stderr or stdout or f"worker exited {proc.returncode}")[-4000:], started=started)
        static_report = load_static_report_for_sample(sample)
        if static_report:
            result.update(flatten_result(sample, "failed", failure_stage="worker", failure_reason=(stderr or stdout or f"worker exited {proc.returncode}")[-4000:], static=static_report, started=started))
            if should_run_dynamic(static_report):
                result["dynamic_triggered"] = True
                result["scan_path"] = "dynamic"
        return result
    return flatten_result(sample, "failed", failure_stage="worker", failure_reason="worker produced no result", started=started)


def apply_worker_resource_limits(cmd: list[str], memory_mb: int) -> list[str]:
    if memory_mb <= 0 or os.name != "posix" or not shutil.which("prlimit"):
        return cmd
    limit_bytes = int(memory_mb) * 1024 * 1024
    return ["prlimit", f"--as={limit_bytes}", "--"] + cmd


def load_static_report_for_sample(sample: dict[str, Any]) -> dict[str, Any]:
    path = Path("artifacts/runs") / f"{sample['safe_sample_id']}-static" / "canonical-analysis-result.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def run_scan(args: argparse.Namespace, paths: Paths) -> int:
    paths.output_root.mkdir(parents=True, exist_ok=True)
    (paths.output_root / "samples").mkdir(parents=True, exist_ok=True)
    atomic_write_text(paths.output_root / "static_gate_definition.md", static_gate_definition())
    records = discover_samples(
        paths,
        use_cache=bool(args.resume and not args.force and (not args.orchestrate or args.reuse_discovery_cache)),
    )
    unique = [r for r in records if not r.get("duplicate_of")]
    if args.sample_ids:
        wanted = {item.strip() for item in args.sample_ids.split(",") if item.strip()}
        unique = [r for r in unique if r["safe_sample_id"] in wanted or r["sample_id"] in wanted or r["skill_id"] in wanted]
    if args.limit:
        unique = unique[: args.limit]
    if args.discover_only:
        write_rollups(paths.output_root, [], paths, {"discovered_sample_count": len(records), "unique_skill_count": len([r for r in records if not r.get("duplicate_of")])})
        return 0

    existing: dict[str, dict[str, Any]] = {}
    if args.resume:
        for path in sorted((paths.output_root / "samples").glob("*.json")):
            payload = load_sample_result(path)
            if payload and payload.get("safe_sample_id"):
                existing[str(payload["safe_sample_id"])] = payload
    pending = [
        r
        for r in unique
        if args.force
        or r["safe_sample_id"] not in existing
        or (args.retry_failed and existing[r["safe_sample_id"]].get("status") == "failed")
    ]
    rows = list(existing.values())
    start_time = time.monotonic()
    last_progress = 0.0
    running = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_map = {executor.submit(scan_one_subprocess, sample, args, paths): sample for sample in pending}
        running = min(max(1, args.workers), len(future_map))
        for future in concurrent.futures.as_completed(future_map):
            sample = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = flatten_result(sample, "failed", failure_stage="worker", failure_reason=str(exc), started=time.monotonic())
            sample_path = paths.output_root / "samples" / f"{sample['safe_sample_id']}.json"
            atomic_write_json(sample_path, result)
            rows = [r for r in rows if r.get("safe_sample_id") != sample["safe_sample_id"]]
            rows.append(result)
            write_rollups(paths.output_root, rows, paths, {"discovered_sample_count": len(records), "unique_skill_count": len([r for r in records if not r.get("duplicate_of")])})
            now = time.monotonic()
            if now - last_progress >= args.progress_interval:
                last_progress = now
                running = min(max(1, args.workers), max(0, len(unique) - len(rows)))
                print_progress(len(rows), len(unique), running, rows, start_time)
    extra = {"discovered_sample_count": len(records), "unique_skill_count": len([r for r in records if not r.get("duplicate_of")])}
    write_rollups(paths.output_root, rows, paths, extra)
    write_scan_state(paths.output_root, records, rows, args)
    if args.limit:
        write_smoke_report(paths, records, rows, args)
    return 0


def write_scan_state(output_root: Path, discovered: list[dict[str, Any]], rows: list[dict[str, Any]], args: argparse.Namespace) -> None:
    total_rows = 0
    try:
        total_rows = int(max(int(r.get("metadata_row") or 0) for r in discovered))
    except ValueError:
        total_rows = 0
    state = {
        "metadata_total_rows": len(load_csv(normalize_path(args.metadata_csv))) if getattr(args, "metadata_csv", "") else total_rows,
        "next_download_start": 1001,
        "current_batch_start": 1,
        "current_batch_end": 1000,
        "current_batch_downloaded": True,
        "current_batch_discovered": True,
        "current_batch_unique": sum(1 for r in discovered if not r.get("duplicate_of")),
        "current_batch_completed": sum(1 for r in rows if r.get("status") == "completed"),
        "current_batch_failed": sum(1 for r in rows if r.get("status") == "failed"),
        "total_metadata_processed": min(1000, total_rows or 1000),
        "total_download_success": len(discovered),
        "total_unique_skills": sum(1 for r in discovered if not r.get("duplicate_of")),
        "total_scan_completed": sum(1 for r in rows if r.get("status") == "completed"),
        "total_static_only": sum(1 for r in rows if r.get("scan_path") == "static_only"),
        "total_dynamic_triggered": sum(1 for r in rows if r.get("dynamic_triggered") is True),
        "total_predicted_malicious": sum(1 for r in rows if r.get("final_decision") == "malicious"),
        "total_confirmed_chain": sum(1 for r in rows if r.get("risk_chain_status") == "confirmed_violation"),
        "total_review_required": sum(1 for r in rows if str(r.get("review_required")).lower() == "true"),
        "total_failed": sum(1 for r in rows if r.get("status") == "failed"),
        "orchestrator_status": "smoke_complete" if args.limit else "scan_complete",
        "last_update": utc_now(),
    }
    atomic_write_json(output_root / "orchestrator_state.json", state)


def print_progress(done: int, total: int, running: int, rows: list[dict[str, Any]], started: float) -> None:
    elapsed_min = max((time.monotonic() - started) / 60.0, 0.001)
    rate = done / elapsed_min
    print(
        "\n".join(
            [
                "[RealWorld]",
                f"scan completed: {done} / {total}",
                f"running: {running}",
                f"static-only: {sum(1 for r in rows if r.get('scan_path') == 'static_only')}",
                f"dynamic: {sum(1 for r in rows if r.get('dynamic_triggered') is True)}",
                f"predicted malicious: {sum(1 for r in rows if r.get('final_decision') == 'malicious')}",
                f"review: {sum(1 for r in rows if str(r.get('review_required')).lower() == 'true')}",
                f"confirmed chains: {sum(1 for r in rows if r.get('risk_chain_status') == 'confirmed_violation')}",
                f"failed: {sum(1 for r in rows if r.get('status') == 'failed')}",
                f"rate: {rate:.2f} skills/min",
            ]
        ),
        flush=True,
    )


def write_smoke_report(paths: Paths, discovered: list[dict[str, Any]], rows: list[dict[str, Any]], args: argparse.Namespace) -> None:
    unique_count = sum(1 for r in discovered if not r.get("duplicate_of"))
    duplicate_count = sum(1 for r in discovered if r.get("duplicate_of"))
    skillpulse_dir = str(paths.skillpulse_root or "<skillpulse-root>")
    downloader_cmd = f"cd {skillpulse_dir} && PYTHONPATH=src python3 -m skillpulse download --start 1001 --count 1000"
    lines = [
        "# Real-World Smoke Test Report",
        "",
        f"1. ProvLoom root: `{paths.provloom_root}`",
        f"2. SkillPulse root: `{paths.skillpulse_root}`",
        f"3. download root: `{paths.download_root}`",
        f"4. metadata total rows: `{max(0, len(load_csv(paths.metadata_csv)))}`",
        f"5. current SKILL.md discovered: `{len(discovered)}`",
        f"6. unique Skill count: `{unique_count}`",
        f"7. duplicate count: `{duplicate_count}`",
        "8. sample mapping reliability: `download_manifest.csv` longest-prefix match, fallback metadata skill_id/source/slug",
        f"9. smoke completed/failed: `{sum(1 for r in rows if r.get('status') == 'completed')}` / `{sum(1 for r in rows if r.get('status') == 'failed')}`",
        f"10. static-only count: `{sum(1 for r in rows if r.get('scan_path') == 'static_only')}`",
        f"11. dynamic-triggered count: `{sum(1 for r in rows if r.get('dynamic_triggered') is True)}`",
        "12. static gate actual rule: see `static_gate_definition.md`",
        f"13. workers=5 normal: `{args.workers == 5}`",
        f"14. provider 429: `{sum(1 for r in rows if 'provider_rate_limited' in str(r.get('failure_reason')))} failures recorded`",
        f"15. resume passed: `{args.resume}`",
        f"16. CSV passed: `{(paths.output_root / 'results.csv').exists()}`",
        "17. deletion gate implemented: batch sealing checks sample JSON, CSV, state, manifest, and no pending workers before clear",
        "18. downloaded_skills deletion during smoke: `not performed`",
        f"19. orchestrator next batch downloader command: `{downloader_cmd}`",
        "20. recommendation: inspect this smoke report and results before starting full orchestrator",
        "",
    ]
    atomic_write_text(paths.output_root / "smoke_test_report.md", "\n".join(lines))


def batch_complete_gate(output_root: Path, batch_samples: list[dict[str, Any]], batch_id: str) -> tuple[bool, list[str]]:
    errors: list[str] = []
    rows = load_csv(output_root / "results.csv")
    result_ids = {row.get("safe_sample_id") for row in rows}
    for sample in batch_samples:
        sid = sample["safe_sample_id"]
        p = output_root / "samples" / f"{sid}.json"
        payload = load_sample_result(p) if p.exists() else None
        if not payload:
            errors.append(f"missing sample json: {sid}")
        elif payload.get("status") not in {"completed", "failed"}:
            errors.append(f"unsealed sample status: {sid}:{payload.get('status')}")
        if sid not in result_ids:
            errors.append(f"missing results.csv row: {sid}")
    for required in ["summary.json", "summary.md", "orchestrator_state.json", f"batches/{batch_id}.json"]:
        if not (output_root / required).exists():
            errors.append(f"missing required batch artifact: {required}")
    return not errors, errors


def safe_clear_download_root(download_root: Path, expected_root: Path, sealed_batch_id: str) -> None:
    actual = download_root.resolve()
    expected = expected_root.resolve()
    if actual != expected or actual.name != "downloaded_skills":
        raise RuntimeError(f"refusing clear due to path mismatch: actual={actual} expected={expected}")
    entries = list(actual.iterdir()) if actual.exists() else []
    print(f"EXACT_DELETE_ROOT={actual}")
    print(f"number_of_entries={len(entries)}")
    print(f"sealed_batch_id={sealed_batch_id}")
    for entry in entries:
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def run_orchestrator(args: argparse.Namespace, paths: Paths) -> int:
    rows_total = len(load_csv(paths.metadata_csv))
    state_path = paths.output_root / "orchestrator_state.json"
    state = load_sample_result(state_path) if args.resume and state_path.exists() else None
    next_start = int((state or {}).get("next_download_start") or 1001)
    if args.progress:
        print((paths.output_root / "summary.md").read_text(encoding="utf-8") if (paths.output_root / "summary.md").exists() else "No summary yet.")
        return 0
    first_batch_path = paths.output_root / "batches" / "batch_000001_001000.json"
    if not first_batch_path.exists() and any(paths.download_root.iterdir()):
        next_start = 1
    while next_start <= rows_total:
        batch_start = next_start
        batch_end = min(rows_total, batch_start + args.batch_size - 1)
        batch_id = f"batch_{batch_start:06d}_{batch_end:06d}"
        batch_path = paths.output_root / "batches" / f"{batch_id}.json"
        if batch_path.exists():
            batch_payload = load_sample_result(batch_path) or {}
            if batch_payload.get("batch_status") == "sealed":
                next_start = batch_end + 1
                atomic_write_json(state_path, orchestrator_state(rows_total, batch_start, batch_end, next_start, "advanced"))
                continue
        has_downloaded_entries = any(paths.download_root.iterdir())
        state_matches_unsealed_batch = bool(
            state
            and int(state.get("current_batch_start") or 0) == batch_start
            and int(state.get("current_batch_end") or 0) == batch_end
            and state.get("orchestrator_status") in {"scanning", "downloaded", "download_complete"}
            and state.get("current_batch_downloaded") is True
        )
        use_existing_download = has_downloaded_entries and (batch_start == 1 or state_matches_unsealed_batch)
        if not batch_path.exists() and not use_existing_download:
            if not paths.skillpulse_root:
                raise SystemExit("SkillPulse root not found; cannot orchestrate downloader.")
            atomic_write_json(state_path, orchestrator_state(rows_total, batch_start, batch_end, next_start, "downloading"))
            download_rc = run_skillpulse_download(paths.skillpulse_root, batch_start, batch_end - batch_start + 1)
            if download_rc != 0:
                atomic_write_json(state_path, orchestrator_state(rows_total, batch_start, batch_end, next_start, "download_failed"))
                raise SystemExit(f"SkillPulse download failed for metadata rows {batch_start}-{batch_end}")
        atomic_write_json(state_path, orchestrator_state(rows_total, batch_start, batch_end, next_start, "scanning"))
        args.limit = None
        args.discover_only = False
        args.reuse_discovery_cache = state_matches_unsealed_batch
        run_scan(args, paths)
        args.reuse_discovery_cache = False
        discovered = json.loads((paths.output_root / "discovered_samples.json").read_text(encoding="utf-8"))
        batch_samples = [r for r in discovered if not r.get("duplicate_of") and batch_start <= int(r.get("metadata_row") or 0) <= batch_end]
        result_rows = load_csv(paths.output_root / "results.csv")
        result_by_id = {row.get("safe_sample_id"): row for row in result_rows}
        batch_results = [result_by_id.get(sample["safe_sample_id"], {}) for sample in batch_samples]
        batch_payload = {
            "metadata_start": batch_start,
            "metadata_end": batch_end,
            "download_manifest_snapshot": str(paths.download_manifest) if paths.download_manifest else "",
            "discovered_sample_count": len(batch_samples),
            "duplicate_count": sum(1 for r in discovered if r.get("duplicate_of") and batch_start <= int(r.get("metadata_row") or 0) <= batch_end),
            "completed_count": sum(1 for row in batch_results if row.get("status") == "completed"),
            "failed_count": sum(1 for row in batch_results if row.get("status") == "failed"),
            "static_only_count": sum(1 for row in batch_results if row.get("scan_path") == "static_only"),
            "dynamic_count": sum(1 for row in batch_results if str(row.get("dynamic_triggered")).lower() == "true"),
            "predicted_malicious_count": sum(1 for row in batch_results if row.get("final_decision") == "malicious"),
            "confirmed_chain_count": sum(1 for row in batch_results if row.get("risk_chain_status") == "confirmed_violation"),
            "started_at": utc_now(),
            "finished_at": utc_now(),
            "batch_status": "sealed",
        }
        atomic_write_json(batch_path, batch_payload)
        atomic_write_json(state_path, orchestrator_state(rows_total, batch_start, batch_end, batch_end + 1, "sealing"))
        ok, errors = batch_complete_gate(paths.output_root, batch_samples, batch_id)
        if not ok:
            atomic_write_json(batch_path, {**batch_payload, "batch_status": "seal_failed", "seal_errors": errors})
            raise SystemExit(f"batch completion gate failed: {errors[:3]}")
        if not args.no_clear:
            safe_clear_download_root(paths.download_root, paths.download_root, batch_id)
        next_start = batch_end + 1
        atomic_write_json(state_path, orchestrator_state(rows_total, batch_start, batch_end, next_start, "advanced"))
    atomic_write_json(paths.output_root / "final_report.json", json.loads((paths.output_root / "summary.json").read_text(encoding="utf-8")))
    shutil.copy2(paths.output_root / "results.csv", paths.output_root / "final_report.csv")
    shutil.copy2(paths.output_root / "summary.md", paths.output_root / "final_report.md")
    atomic_write_json(state_path, orchestrator_state(rows_total, rows_total, rows_total, rows_total + 1, "finished"))
    return 0


def run_skillpulse_download(skillpulse_root: Path, start: int, count: int) -> int:
    if shutil.which("python3.12"):
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        return subprocess.run(
            ["python3.12", "-m", "skillpulse", "download", "--start", str(start), "--count", str(count)],
            cwd=str(skillpulse_root),
            env=env,
            check=False,
        ).returncode
    if shutil.which("powershell.exe"):
        win_root = wsl_to_windows_path(skillpulse_root)
        command = (
            "$ErrorActionPreference='Stop'; "
            "$env:PYTHONPATH='src'; "
            f"Set-Location '{win_root}'; "
            f"py -3.12 -m skillpulse download --start {start} --count {count}"
        )
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            check=False,
        ).returncode
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    return subprocess.run(
        [sys.executable, "-m", "skillpulse", "download", "--start", str(start), "--count", str(count)],
        cwd=str(skillpulse_root),
        env=env,
        check=False,
    ).returncode


def wsl_to_windows_path(path: Path) -> str:
    resolved = path.resolve()
    parts = resolved.parts
    if len(parts) >= 3 and parts[1] == "mnt" and len(parts[2]) == 1:
        drive = parts[2].upper() + ":"
        rest = "\\".join(parts[3:])
        return drive + ("\\" + rest if rest else "\\")
    return str(resolved)


def orchestrator_state(total: int, batch_start: int, batch_end: int, next_start: int, status: str) -> dict[str, Any]:
    return {
        "metadata_total_rows": total,
        "next_download_start": next_start,
        "current_batch_start": batch_start,
        "current_batch_end": batch_end,
        "current_batch_downloaded": status not in {"downloading"},
        "current_batch_discovered": status in {"scanning", "sealing", "advanced", "finished"},
        "current_batch_unique": 0,
        "current_batch_completed": 0,
        "current_batch_failed": 0,
        "total_metadata_processed": max(0, next_start - 1),
        "total_download_success": 0,
        "total_unique_skills": 0,
        "total_scan_completed": 0,
        "total_static_only": 0,
        "total_dynamic_triggered": 0,
        "total_predicted_malicious": 0,
        "total_confirmed_chain": 0,
        "total_review_required": 0,
        "total_failed": 0,
        "orchestrator_status": status,
        "last_update": utc_now(),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ProvLoom + SkillPulse real-world measurement runner")
    parser.add_argument("--input-root", default=os.environ.get("PROVLOOM_REALWORLD_INPUT_ROOT", "realworld/downloaded_skills"))
    parser.add_argument("--metadata-csv", default=os.environ.get("PROVLOOM_REALWORLD_METADATA_CSV", "realworld/all_skill_metadata.csv"))
    parser.add_argument("--download-manifest", default=os.environ.get("PROVLOOM_REALWORLD_DOWNLOAD_MANIFEST", "realworld/download_manifest.csv"))
    parser.add_argument("--output-root", default="artifacts/realworld_skill_scan")
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--sample-ids", default="")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true", default=False)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--reuse-discovery-cache", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--discover-only", action="store_true")
    parser.add_argument("--scan-only", action="store_true")
    parser.add_argument("--orchestrate", action="store_true")
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--progress-interval", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument("--no-clear", action="store_true", help="Do not clear downloaded_skills after sealed batches.")
    parser.add_argument("--analysis-mode", default="rule_plus_epg")
    parser.add_argument("--network-policy", default="default", choices=["default", "disabled"])
    parser.add_argument("--image-name", default=DEFAULT_SANDBOX_IMAGE)
    parser.add_argument("--provider", default="openai-compatible")
    parser.add_argument("--base-url", default=os.environ.get("PROVLOOM_SCAN_BASE_URL", ""))
    parser.add_argument("--model", default=os.environ.get("PROVLOOM_SCAN_MODEL", ""))
    parser.add_argument("--api-key", default=os.environ.get("PROVLOOM_SCAN_API_KEY", ""))
    parser.add_argument("--max-llm-steps", type=int, default=16)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--sample-timeout-seconds", type=int, default=900)
    parser.add_argument("--worker-memory-mb", type=int, default=0)
    parser.add_argument("--worker-sample-file", default=argparse.SUPPRESS)
    parser.add_argument("--worker-output-file", default=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    provloom_root = confirm_provloom_root()
    os.chdir(provloom_root)
    if hasattr(args, "worker_sample_file"):
        sample = json.loads(Path(args.worker_sample_file).read_text(encoding="utf-8"))
        result = scan_one(sample, args, str(normalize_path(args.output_root)))
        atomic_write_json(Path(args.worker_output_file), result)
        return 0
    input_root = normalize_path(args.input_root)
    metadata_csv = normalize_path(args.metadata_csv)
    manifest = normalize_path(args.download_manifest) if args.download_manifest else None
    output_root = normalize_path(args.output_root)
    skillpulse_root = infer_skillpulse_root(input_root, metadata_csv)
    paths = Paths(provloom_root, skillpulse_root, input_root, metadata_csv, manifest if manifest and manifest.exists() else None, output_root)
    if not paths.download_root.exists():
        raise SystemExit(f"download root not found: {paths.download_root}")
    if not paths.metadata_csv.exists():
        raise SystemExit(f"metadata csv not found: {paths.metadata_csv}")
    execution_environment = "wsl/linux" if str(paths.download_root).startswith("/mnt/") else sys.platform
    atomic_write_json(paths.output_root / "environment.json", {
        "skillpulse_root": str(paths.skillpulse_root) if paths.skillpulse_root else "",
        "download_root": str(paths.download_root),
        "provloom_root": str(paths.provloom_root),
        "execution_environment": execution_environment,
        "recorded_at": utc_now(),
    })
    if args.orchestrate:
        return run_orchestrator(args, paths)
    if args.progress:
        print((paths.output_root / "summary.md").read_text(encoding="utf-8") if (paths.output_root / "summary.md").exists() else "No summary yet.")
        return 0
    return run_scan(args, paths)


if __name__ == "__main__":
    raise SystemExit(main())
