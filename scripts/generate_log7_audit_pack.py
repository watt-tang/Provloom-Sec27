from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_DIR = Path("/mnt/e/log7")
OUTPUT_ROOT = PROJECT_ROOT / "real_world_audit" / "log7_completed_subset"

NOTE_RE = re.compile(r"note|memo|summary|brief|report|inventory|audit|mirror", re.I)
HELPER_RE = re.compile(r"helper|list|listing|catalog|index|archive", re.I)
UPLOAD_RE = re.compile(r"upload|sync|relay|post|publish|share|send|push|webhook|mirror", re.I)

STRATA_QUOTAS = {
    "chain_backed_critical": 5,
    "partial_evidence_medium": 5,
    "note_like_fp_cluster": 8,
    "upload_or_mirror_outward": 4,
    "llm_decision_heavy": 4,
    "representative_low_risk": 4,
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_results(path: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            results.append(json.loads(line))
    return results


def completed_results(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("status") == "completed"]


def name_blob(row: dict[str, Any]) -> str:
    return " ".join([str(row.get("skill_id", "")), str(row.get("name", "")), str(row.get("skill_root", ""))]).lower()


def primary_chain_nonempty(row: dict[str, Any]) -> bool:
    return bool(row.get("primary_chain"))


def predicted_behaviors(row: dict[str, Any]) -> str:
    return ", ".join(row.get("detected_behaviors") or [])


def classify_cluster(row: dict[str, Any]) -> tuple[str, str]:
    blob = name_blob(row)
    if NOTE_RE.search(blob):
        return "note_like_local_output", "note_report_inventory_or_mirror"
    if HELPER_RE.search(blob):
        return "helper_listing", "helper_listing_or_archive"
    if UPLOAD_RE.search(blob):
        return "upload_or_mirror_outward", "upload_sync_relay_surface"
    if row.get("root_cause_detail") == "llm_decision_induced_action":
        return "llm_decision_heavy", "llm_mediated_workflow"
    if row.get("risk_level") == "low":
        return "representative_low_risk", "representative_low_risk"
    if primary_chain_nonempty(row):
        return "chain_backed", "chain_backed"
    return "partial_evidence", "partial_evidence_medium"


def review_priority(row: dict[str, Any], stratum: str) -> str:
    if stratum in {"note_like_fp_cluster", "upload_or_mirror_outward", "chain_backed_critical"}:
        return "high"
    if row.get("risk_level") in {"critical", "high"}:
        return "high"
    if row.get("risk_level") == "medium":
        return "medium"
    return "low"


def candidate_manual_label(row: dict[str, Any], stratum: str) -> str:
    if stratum in {"note_like_fp_cluster", "representative_low_risk"}:
        return "likely_benign"
    if stratum == "chain_backed_critical":
        return "likely_needs_review"
    return ""


def row_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}
    return (
        risk_order.get(row.get("risk_level"), 5),
        0 if primary_chain_nonempty(row) else 1,
        str(row.get("skill_id", "")),
    )


def select_stratum(rows: list[dict[str, Any]], stratum: str) -> list[dict[str, Any]]:
    if stratum == "chain_backed_critical":
        selected = [row for row in rows if row.get("risk_level") == "critical" and primary_chain_nonempty(row)]
    elif stratum == "partial_evidence_medium":
        selected = [row for row in rows if row.get("risk_level") == "medium" and not primary_chain_nonempty(row)]
    elif stratum == "note_like_fp_cluster":
        selected = [
            row
            for row in rows
            if classify_cluster(row)[0] in {"note_like_local_output", "helper_listing"}
            and row.get("risk_level") in {"critical", "high", "medium"}
        ]
    elif stratum == "upload_or_mirror_outward":
        selected = [
            row
            for row in rows
            if classify_cluster(row)[0] == "upload_or_mirror_outward"
            and (primary_chain_nonempty(row) or row.get("risk_level") in {"critical", "high", "medium"})
        ]
    elif stratum == "llm_decision_heavy":
        selected = [
            row
            for row in rows
            if row.get("root_cause_detail") == "llm_decision_induced_action"
            and row.get("risk_level") in {"critical", "high", "medium"}
        ]
    elif stratum == "representative_low_risk":
        selected = [row for row in rows if row.get("risk_level") == "low"]
    else:
        selected = []
    return sorted(selected, key=row_sort_key)


def dedupe_sample(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for row in rows:
        key = str(row.get("skill_id", ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result


def build_sample(completed: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    selections: dict[str, list[dict[str, Any]]] = {}
    chosen_ids: set[str] = set()
    sample_rows: list[dict[str, Any]] = []
    sample_index = 1

    for stratum, quota in STRATA_QUOTAS.items():
        candidates = [row for row in select_stratum(completed, stratum) if str(row.get("skill_id", "")) not in chosen_ids]
        picked = candidates[:quota]
        selections[stratum] = picked
        for row in picked:
            chosen_ids.add(str(row.get("skill_id", "")))
            cluster_tag, suspected_fp_type = classify_cluster(row)
            sample_rows.append(
                {
                    "sample_id": f"S{sample_index:03d}",
                    "stratum": stratum,
                    "skill_id": row.get("skill_id", ""),
                    "skill_name": row.get("name", ""),
                    "skill_root": row.get("skill_root", ""),
                    "status": row.get("status", ""),
                    "risk_level": row.get("risk_level", ""),
                    "risk_score": row.get("risk_score", ""),
                    "execution_outcome": row.get("execution_outcome", ""),
                    "primary_chain_nonempty": primary_chain_nonempty(row),
                    "primary_chain_length": len(row.get("primary_chain") or []),
                    "predicted_root_cause": row.get("root_cause_detail") or row.get("root_cause") or "",
                    "predicted_behaviors": predicted_behaviors(row),
                    "cluster_tag": cluster_tag,
                    "suspected_fp_type": suspected_fp_type,
                    "candidate_manual_label": candidate_manual_label(row, stratum),
                    "manual_label": "",
                    "manual_root_cause": "",
                    "manual_notes": "",
                    "review_priority": review_priority(row, stratum),
                    "needs_manual_review": True,
                    "annotation_status": "sampled-manual-review-pending",
                    "artifact_dir": row.get("execution_artifact_dir", ""),
                }
            )
            sample_index += 1

    return sample_rows, selections


def cluster_breakdown(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, bool], int] = defaultdict(int)
    for row in rows:
        cluster_tag, suspected_fp_type = classify_cluster(row)
        grouped[(cluster_tag, row.get("risk_level", ""), primary_chain_nonempty(row))] += 1
    breakdown = []
    for (cluster_tag, risk_level, chain_flag), count in sorted(grouped.items()):
        breakdown.append(
            {
                "cluster_tag": cluster_tag,
                "risk_level": risk_level,
                "primary_chain_nonempty": chain_flag,
                "count": count,
            }
        )
    return breakdown


def note_like_focus(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    focus = []
    for row in rows:
        cluster_tag, suspected_fp_type = classify_cluster(row)
        if cluster_tag not in {"note_like_local_output", "helper_listing"}:
            continue
        focus.append(
            {
                "skill_id": row.get("skill_id", ""),
                "skill_name": row.get("name", ""),
                "risk_level": row.get("risk_level", ""),
                "primary_chain_nonempty": primary_chain_nonempty(row),
                "predicted_root_cause": row.get("root_cause_detail", ""),
                "suspected_fp_type": suspected_fp_type,
            }
        )
    return sorted(focus, key=lambda item: (item["risk_level"], item["skill_id"]))


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def write_tables(
    summary: dict[str, Any],
    selections: dict[str, list[dict[str, Any]]],
    sample_rows: list[dict[str, Any]],
    breakdown: list[dict[str, Any]],
    note_rows: list[dict[str, Any]],
) -> None:
    md_lines = [
        "# log7 Completed-Subset Sampled Audit Tables",
        "",
        "These tables are a mix of `code-generated` and `placeholder` outputs. No population-level accuracy claims are made.",
        "",
        "## Completed-Subset Sampled Audit Summary",
        "",
        "| Field | Value | Status |",
        "| --- | ---: | --- |",
        f"| Scheduled skills | {summary['scheduled']} | code-generated |",
        f"| Completed executions | {summary['completed']} | code-generated |",
        f"| Skipped executions | {summary['skipped']} | code-generated |",
        f"| Sampled completed cases | {len(sample_rows)} | code-generated |",
        f"| Manual review completed | 0 | sampled-manual-review-pending |",
        "",
        "## Sampling by Stratum",
        "",
        "| Stratum | Selected | Status |",
        "| --- | ---: | --- |",
    ]
    for stratum, rows in selections.items():
        md_lines.append(f"| `{stratum}` | {len(rows)} | code-generated |")
    md_lines.extend(
        [
            "",
            "## Predicted vs Manually Reviewed Label Comparison",
            "",
            "| Bucket | Count | Status |",
            "| --- | ---: | --- |",
            f"| Predicted review-worthy (`critical`/`high`/`medium`) | {sum(1 for row in sample_rows if row['risk_level'] in {'critical', 'high', 'medium'})} | code-generated |",
            "| Manually confirmed malicious | 0 | sampled-manual-review-pending |",
            "| Manually confirmed benign | 0 | sampled-manual-review-pending |",
            f"| Pending manual labels | {len(sample_rows)} | sampled-manual-review-pending |",
            "",
            "## FP Cluster Breakdown in Completed Subset",
            "",
            "| Cluster | Risk Level | Primary Chain Nonempty | Count | Status |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    for row in breakdown:
        md_lines.append(
            f"| `{row['cluster_tag']}` | `{row['risk_level']}` | `{row['primary_chain_nonempty']}` | {row['count']} | code-generated |"
        )
    md_lines.extend(
        [
            "",
            "## Note-Like Benign-FP Focus",
            "",
            "| skill_id | risk_level | primary_chain_nonempty | suspected_fp_type | Status |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for row in note_rows[:20]:
        md_lines.append(
            f"| `{row['skill_id']}` | `{row['risk_level']}` | `{row['primary_chain_nonempty']}` | `{row['suspected_fp_type']}` | code-generated |"
        )
    (OUTPUT_ROOT / "summary_tables.md").write_text("\n".join(md_lines), encoding="utf-8")

    tex_lines = [
        "% log7 sampled audit tables",
        "\\begin{table}[htbp]",
        "\\caption{Completed-subset sampled audit summary for log7.}",
        "\\centering",
        "\\small",
        "\\begin{tabular}{lrl}",
        "\\toprule",
        "Field & Value & Status \\\\",
        "\\midrule",
        f"Scheduled skills & {summary['scheduled']} & code-generated \\\\",
        f"Completed executions & {summary['completed']} & code-generated \\\\",
        f"Skipped executions & {summary['skipped']} & code-generated \\\\",
        f"Sampled completed cases & {len(sample_rows)} & code-generated \\\\",
        "Manual review completed & 0 & sampled-manual-review-pending \\\\",
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
        "\\begin{table}[htbp]",
        "\\caption{Sampling strata for the completed-subset audit pack.}",
        "\\centering",
        "\\small",
        "\\begin{tabular}{lr}",
        "\\toprule",
        "Stratum & Selected \\\\",
        "\\midrule",
    ]
    for stratum, rows in selections.items():
        tex_lines.append(f"\\texttt{{{stratum}}} & {len(rows)} \\\\")
    tex_lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular}",
            "\\end{table}",
        ]
    )
    (OUTPUT_ROOT / "summary_tables.tex").write_text("\n".join(tex_lines), encoding="utf-8")


def write_review_instructions() -> None:
    text = "\n".join(
        [
            "# log7 Sample Review Instructions",
            "",
            "This pack is for a completed-subset sampled audit, not a population-level accuracy benchmark.",
            "",
            "## Minimal Manual Workflow",
            "",
            "1. Open the sampled skill root and the referenced execution artifact directory.",
            "2. Inspect `primary_chain`, detected behaviors, and root-cause fields before reading the full trace.",
            "3. Fill `manual_label` with `malicious`, `benign`, or `uncertain` only after checking whether an actual source-to-outward path exists.",
            "4. Use `manual_root_cause` only when the execution evidence supports a concrete mechanism.",
            "5. Keep `manual_notes` short and evidence-backed; mention whether the concern is note-like, helper-like, upload-like, or chain-backed.",
            "",
            "## Boundary Rules",
            "",
            "- Treat `completed_full` as the sampling boundary; skipped cases are out of scope for the sampled audit sheet.",
            "- Do not convert this audit into overall precision/recall claims.",
            "- When evidence is incomplete, record `uncertain` and keep `needs_manual_review=true`.",
        ]
    )
    (OUTPUT_ROOT / "sample_review_instructions.md").write_text(text, encoding="utf-8")


def write_paper_text(summary: dict[str, Any], sample_rows: list[dict[str, Any]], selections: dict[str, list[dict[str, Any]]]) -> None:
    text_md = "\n".join(
        [
            "# Completed-Subset Sampled Audit Text",
            "",
            "## Setup",
            "",
            f"The supporting real-world rerun in `/mnt/e/log7` contains {summary['scheduled']} scheduled Skills, {summary['completed']} completed executions, and {summary['skipped']} skipped executions. "
            "We treat the completed executions as the sampling boundary for a lightweight manual audit package rather than as a fully labeled benchmark.",
            "",
            "## Why This Is Not a Population-Level Accuracy Benchmark",
            "",
            "The log7 rerun is a candidate-risk corpus with an explicit execution-availability boundary. Completed executions reflect what could be exercised under the current sandbox, trigger, adapter, and credential setup; they are not a random sample of the public Skill ecosystem, and they do not carry gold labels by default.",
            "",
            "## What The Sampled Audit Still Adds",
            "",
            f"We generate a stratified audit pack over {len(sample_rows)} completed cases spanning chain-backed critical findings, partial-evidence medium findings, note-like or local-output suspected benign-FP clusters, upload-like or mirror-like outward workflows, LLM-decision-heavy cases, and representative low-risk cases. "
            "This does not replace benchmark metrics, but it does improve external credibility by making the completed subset auditable, by reducing cherry-picking risk, and by forcing explicit error-analysis notes for the exact clusters that remain hard to calibrate.",
            "",
            "## Sampling Boundary",
            "",
            "The pack is `code-generated` from `results.jsonl` and remains `sampled-manual-review-pending` until a reviewer fills the annotation sheet. Tables that compare prediction to manual labels are therefore exported as placeholders with pending fields instead of invented accuracies.",
        ]
    )
    (OUTPUT_ROOT / "paper_ready_text.md").write_text(text_md, encoding="utf-8")

    text_tex = "\n".join(
        [
            "% log7 completed-subset audit text",
            f"The supporting real-world rerun in \\texttt{{/mnt/e/log7}} contains {summary['scheduled']} scheduled Skills, {summary['completed']} completed executions, and {summary['skipped']} skipped executions. We treat the completed executions as the sampling boundary for a lightweight manual audit package rather than as a fully labeled benchmark.",
            "",
            "This rerun should not be read as a population-level accuracy benchmark. It is a candidate-risk corpus with an explicit execution-availability boundary: completed executions are the cases that could be exercised under the current sandbox, trigger, adapter, and credential setup, and they do not carry gold labels by default.",
            "",
            f"We therefore generate a stratified audit pack over {len(sample_rows)} completed cases spanning chain-backed critical findings, partial-evidence medium findings, note-like or local-output suspected benign-FP clusters, upload-like or mirror-like outward workflows, LLM-decision-heavy cases, and representative low-risk cases. The pack is code-generated from \\texttt{{results.jsonl}} and remains manual-review-pending until the annotation sheet is completed.",
        ]
    )
    (OUTPUT_ROOT / "paper_ready_text.tex").write_text(text_tex, encoding="utf-8")


def main() -> int:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    summary_payload = load_json(DEFAULT_LOG_DIR / "summary.json")
    progress_payload = load_json(DEFAULT_LOG_DIR / "progress.json")
    results = load_results(DEFAULT_LOG_DIR / "results.jsonl")
    completed = completed_results(results)
    sample_rows, selections = build_sample(completed)
    breakdown = cluster_breakdown(completed)
    note_rows = note_like_focus(completed)

    summary = {
        "scheduled": progress_payload["totals"]["discovered"],
        "completed": progress_payload["totals"]["completed"],
        "skipped": progress_payload["totals"]["skipped"],
        "failed": progress_payload["totals"]["failed"],
        "primary_chain_nonempty": sum(1 for row in completed if primary_chain_nonempty(row)),
        "sampled_completed_cases": len(sample_rows),
    }

    write_json(
        OUTPUT_ROOT / "sampling_manifest.json",
        {
            "source_log_dir": str(DEFAULT_LOG_DIR),
            "sampling_summary": summary,
            "sampling_quotas": STRATA_QUOTAS,
            "selections": {key: [row.get("skill_id", "") for row in value] for key, value in selections.items()},
            "sample_rows": sample_rows,
        },
    )
    write_csv(
        OUTPUT_ROOT / "sample_annotation_sheet.csv",
        sample_rows,
        [
            "sample_id",
            "stratum",
            "skill_id",
            "skill_name",
            "skill_root",
            "status",
            "risk_level",
            "risk_score",
            "execution_outcome",
            "primary_chain_nonempty",
            "primary_chain_length",
            "predicted_root_cause",
            "predicted_behaviors",
            "cluster_tag",
            "suspected_fp_type",
            "candidate_manual_label",
            "manual_label",
            "manual_root_cause",
            "manual_notes",
            "review_priority",
            "needs_manual_review",
            "annotation_status",
            "artifact_dir",
        ],
    )
    write_json(OUTPUT_ROOT / "fp_cluster_breakdown.json", breakdown)
    write_csv(
        OUTPUT_ROOT / "fp_cluster_breakdown.csv",
        breakdown,
        ["cluster_tag", "risk_level", "primary_chain_nonempty", "count"],
    )
    write_csv(
        OUTPUT_ROOT / "note_like_focus.csv",
        note_rows,
        ["skill_id", "skill_name", "risk_level", "primary_chain_nonempty", "predicted_root_cause", "suspected_fp_type"],
    )
    write_review_instructions()
    write_tables(summary, selections, sample_rows, breakdown, note_rows)
    write_paper_text(summary, sample_rows, selections)
    print(json.dumps({"output_root": str(OUTPUT_ROOT), "sample_count": len(sample_rows)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
