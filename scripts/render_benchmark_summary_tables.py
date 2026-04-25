from __future__ import annotations

import argparse
import json
from pathlib import Path


DISPLAY_NAMES = {
    "static_only": "static-only",
    "rule_only": "rule-only",
    "rule_plus_epg": "rule+EPG",
    "epg_with_filtering": "EPG+filtering",
}

METRIC_ROWS = [
    ("detection_rate", "Detection rate"),
    ("false_positive_rate", "False positive rate"),
    ("endpoint_accuracy", "Endpoint accuracy"),
    ("edge_level_f1", "Edge-level F1"),
    ("complete_chain_rate", "Complete chain rate"),
    ("partial_chain_usefulness", "Partial-chain usefulness"),
    ("root_cause_accuracy", "Root-cause accuracy"),
    ("avg_latency_ms", "Avg. latency (ms)"),
]


def format_metric(key: str, value: float) -> str:
    if key == "avg_latency_ms":
        return f"{value:.2f}"
    return f"{value:.4f}".rstrip("0").rstrip(".") if value not in {0.0, 1.0} else f"{value:.1f}"


def render_md(payload: dict) -> str:
    baseline_order = payload["baseline_order"]
    lines = [
        "# Benchmark Summary Tables",
        "",
        f"Source: `{payload.get('source_path', 'summary json')}`.",
        "",
        "## Coverage by Baseline",
        "",
        "| Baseline | Cases | Done | Skip | Mal. | Ben. |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for mode in baseline_order:
        summary = payload["baseline_results"][mode]["summary"]
        lines.append(
            f"| {DISPLAY_NAMES.get(mode, mode)} | {summary['case_count']} | "
            f"{summary['completed_case_count']} | {summary['skipped_case_count']} | "
            f"{summary['malicious_case_count']} | {summary['benign_case_count']} |"
        )

    lines.extend(
        [
            "",
            "## Main Results",
            "",
            "| Metric | " + " | ".join(DISPLAY_NAMES.get(mode, mode) for mode in baseline_order) + " |",
            "| --- | " + " | ".join("---:" for _ in baseline_order) + " |",
        ]
    )
    for key, label in METRIC_ROWS:
        row = [label]
        for mode in baseline_order:
            value = payload["baseline_results"][mode]["summary"][key]
            row.append(format_metric(key, value))
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def render_tex(payload: dict) -> str:
    baseline_order = payload["baseline_order"]
    coverage_lines = [
        "% Code-generated benchmark summary tables",
        "\\begin{table}[htbp]",
        "\\caption{Benchmark coverage by baseline (code-generated).}",
        "\\centering",
        "\\small",
        "\\setlength{\\tabcolsep}{4pt}",
        "\\begin{tabular*}{\\columnwidth}{@{\\extracolsep{\\fill}}lccccc}",
        "\\toprule",
        "\\textbf{Baseline} & \\textbf{Cases} & \\textbf{Done} & \\textbf{Skip} & \\textbf{Mal.} & \\textbf{Ben.} \\\\",
        "\\midrule",
    ]
    for mode in baseline_order:
        summary = payload["baseline_results"][mode]["summary"]
        coverage_lines.append(
            f"{DISPLAY_NAMES.get(mode, mode)} & {summary['case_count']} & {summary['completed_case_count']} & "
            f"{summary['skipped_case_count']} & {summary['malicious_case_count']} & {summary['benign_case_count']} \\\\"
        )
    coverage_lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular*}",
            "\\end{table}",
            "",
            "\\begin{table}[htbp]",
            "\\caption{Benchmark summary from exported baseline results (code-generated).}",
            "\\centering",
            "\\scriptsize",
            "\\setlength{\\tabcolsep}{3pt}",
            "\\begin{tabular*}{\\columnwidth}{@{\\extracolsep{\\fill}}l" + "c" * len(baseline_order) + "}",
            "\\toprule",
            "\\textbf{Metric} & "
            + " & ".join(f"\\textbf{{{DISPLAY_NAMES.get(mode, mode)}}}" for mode in baseline_order)
            + " \\\\",
            "\\midrule",
        ]
    )
    for key, label in METRIC_ROWS:
        values = " & ".join(format_metric(key, payload["baseline_results"][mode]["summary"][key]) for mode in baseline_order)
        coverage_lines.append(f"{label} & {values} \\\\")
    coverage_lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular*}",
            "\\end{table}",
        ]
    )
    return "\n".join(coverage_lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render Markdown and LaTeX tables from a benchmark summary JSON file.")
    parser.add_argument("--summary-json", required=True, help="Path to a benchmark summary JSON file.")
    parser.add_argument("--output-md", required=True, help="Path to the output Markdown file.")
    parser.add_argument("--output-tex", required=True, help="Path to the output LaTeX file.")
    args = parser.parse_args()

    summary_path = Path(args.summary_json).resolve()
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    payload["source_path"] = str(summary_path)

    output_md = Path(args.output_md)
    output_tex = Path(args.output_tex)
    output_md.write_text(render_md(payload), encoding="utf-8")
    output_tex.write_text(render_tex(payload), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
