#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import sys
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = PROJECT_ROOT / "skillscan_benchmark_cmp"
PER_CASE_DIR = OUT_DIR / "per_case_reports"
MANIFEST_PATH = PROJECT_ROOT / "benchmark_v2" / "generated" / "benchmark_v2_manifest.json"
RULES_PATH = PROJECT_ROOT / "skillscan_results" / "skillscan_rules.yaml"
SITE_PACKAGES = PROJECT_ROOT / "skillscan" / ".venv" / "lib" / "python3.10" / "site-packages"

RESULTS_JSONL = OUT_DIR / "skillscan_benchmark_results.jsonl"
RESULTS_CSV = OUT_DIR / "skillscan_benchmark_results.csv"
METRICS_JSON = OUT_DIR / "skillscan_benchmark_metrics.json"
RAW_LOG = OUT_DIR / "raw_output.txt"
SUMMARY_MD = OUT_DIR / "skillscan_benchmark_cmp_summary.md"


def load_skillscan_backend():
    if str(SITE_PACKAGES) not in sys.path:
        sys.path.insert(0, str(SITE_PACKAGES))

    from src.rules_factory import RulesFactory
    from src.scanner import SecurityDetector
    from src.reporters import JSONReporter

    with RULES_PATH.open("r", encoding="utf-8") as f:
        rules_config = yaml.safe_load(f)

    rules = []
    for _, rule_list in rules_config.items():
        rules.extend(rule_list)

    return SecurityDetector(RulesFactory.create_rules(rules), whitelist=[]), JSONReporter(indent=2)


def load_cases():
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return manifest, manifest["cases"]


def confusion(records, predicate_key):
    counts = Counter()
    for row in records:
        pred = bool(row[predicate_key])
        actual = row["malicious_or_benign"] == "malicious"
        if pred and actual:
            counts["TP"] += 1
        elif pred and not actual:
            counts["FP"] += 1
        elif not pred and actual:
            counts["FN"] += 1
        else:
            counts["TN"] += 1
    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    accuracy = (tp + tn) / max(1, tp + fp + fn + tn)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "accuracy": accuracy,
        "f1": f1,
    }


def rule_counts(issues):
    return dict(Counter(issue.get("rule_id", "UNKNOWN") for issue in issues).most_common())


def scan_cases(cases):
    detector, reporter = load_skillscan_backend()
    rows = []
    logs = [
        "SkillScan benchmark_v2 comparison run",
        f"started_at={datetime.now(timezone.utc).isoformat()}",
        f"manifest={MANIFEST_PATH}",
        f"rules={RULES_PATH}",
        f"cases={len(cases)}",
    ]

    for idx, case in enumerate(cases, 1):
        case_id = case["case_id"]
        skill_path = PROJECT_ROOT / case["skill_path"]
        started = datetime.now(timezone.utc)
        try:
            report = detector.scan(str(skill_path))
            data = json.loads(reporter.generate(report))
            data["status"] = "success"
            data["case_id"] = case_id
            data["duration_seconds"] = (datetime.now(timezone.utc) - started).total_seconds()
            (PER_CASE_DIR / f"{case_id}.json").write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            issues = data.get("issues", [])
            row = {
                "case_id": case_id,
                "skill_path": case["skill_path"],
                "family": case["family"],
                "malicious_or_benign": case["malicious_or_benign"],
                "evaluation_status": case["evaluation_status"],
                "source_type": case["source_type"],
                "relay_shape": case["relay_shape"],
                "sink_type": case["sink_type"],
                "trigger_type": case["trigger_type"],
                "camouflage_style": case["camouflage_style"],
                "lookalike_group_id": case.get("lookalike_group_id") or "",
                "pair_role": case.get("pair_role") or "",
                "status": "success",
                "risk_level": data.get("risk_level", "UNKNOWN"),
                "risk_score": data.get("risk_score", 0),
                "total_issues": data.get("total_issues", 0),
                "total_files": data.get("total_files", 0),
                "any_hit_pred": data.get("total_issues", 0) > 0,
                "risk_level_pred": data.get("risk_level", "UNKNOWN") != "SAFE",
                "rule_counts": rule_counts(issues),
                "top_evidence": issues[:5],
                "duration_seconds": data["duration_seconds"],
                "error": "",
            }
            logs.append(
                f"[{idx}/{len(cases)}] OK {case_id}: actual={row['malicious_or_benign']} "
                f"risk={row['risk_level']} issues={row['total_issues']} rules={row['rule_counts']}"
            )
        except Exception as exc:
            row = {
                "case_id": case_id,
                "skill_path": case["skill_path"],
                "family": case["family"],
                "malicious_or_benign": case["malicious_or_benign"],
                "evaluation_status": case["evaluation_status"],
                "source_type": case["source_type"],
                "relay_shape": case["relay_shape"],
                "sink_type": case["sink_type"],
                "trigger_type": case["trigger_type"],
                "camouflage_style": case["camouflage_style"],
                "lookalike_group_id": case.get("lookalike_group_id") or "",
                "pair_role": case.get("pair_role") or "",
                "status": "failed",
                "risk_level": "ERROR",
                "risk_score": 0,
                "total_issues": 0,
                "total_files": 0,
                "any_hit_pred": False,
                "risk_level_pred": False,
                "rule_counts": {},
                "top_evidence": [],
                "duration_seconds": (datetime.now(timezone.utc) - started).total_seconds(),
                "error": f"{exc}\n{traceback.format_exc()}",
            }
            logs.append(f"[{idx}/{len(cases)}] FAIL {case_id}: {exc}")
        rows.append(row)
        if idx % 25 == 0:
            RAW_LOG.write_text("\n".join(logs) + "\n", encoding="utf-8")

    RAW_LOG.write_text("\n".join(logs) + "\n", encoding="utf-8")
    return rows


def grouped_metrics(rows, group_key, pred_key):
    out = {}
    groups = defaultdict(list)
    for row in rows:
        groups[row[group_key]].append(row)
    for key, group_rows in sorted(groups.items()):
        out[key] = {
            "count": len(group_rows),
            "malicious": sum(1 for r in group_rows if r["malicious_or_benign"] == "malicious"),
            "benign": sum(1 for r in group_rows if r["malicious_or_benign"] == "benign"),
            **confusion(group_rows, pred_key),
            "risk_levels": dict(Counter(r["risk_level"] for r in group_rows)),
            "total_issues": sum(int(r["total_issues"]) for r in group_rows),
        }
    return out


def write_outputs(rows, manifest):
    with RESULTS_JSONL.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    fieldnames = [
        "case_id", "malicious_or_benign", "family", "evaluation_status", "source_type",
        "relay_shape", "sink_type", "trigger_type", "camouflage_style", "risk_level",
        "risk_score", "total_issues", "any_hit_pred", "risk_level_pred", "rule_counts",
        "skill_path", "status", "error",
    ]
    with RESULTS_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(row[k], ensure_ascii=False) if k == "rule_counts" else row[k] for k in fieldnames})

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_version": manifest.get("benchmark_version"),
        "case_count": len(rows),
        "success_count": sum(1 for r in rows if r["status"] == "success"),
        "failure_count": sum(1 for r in rows if r["status"] != "success"),
        "actual_counts": dict(Counter(r["malicious_or_benign"] for r in rows)),
        "risk_level_counts": dict(Counter(r["risk_level"] for r in rows)),
        "rule_counts": dict(
            sum((Counter(r["rule_counts"]) for r in rows), Counter()).most_common()
        ),
        "any_hit_confusion": confusion(rows, "any_hit_pred"),
        "risk_level_confusion": confusion(rows, "risk_level_pred"),
        "by_family_any_hit": grouped_metrics(rows, "family", "any_hit_pred"),
        "by_family_risk_level": grouped_metrics(rows, "family", "risk_level_pred"),
        "by_eval_status_risk_level": grouped_metrics(rows, "evaluation_status", "risk_level_pred"),
        "false_positives_risk_level": [r["case_id"] for r in rows if r["risk_level_pred"] and r["malicious_or_benign"] == "benign"],
        "false_negatives_risk_level": [r["case_id"] for r in rows if not r["risk_level_pred"] and r["malicious_or_benign"] == "malicious"],
        "false_positives_any_hit": [r["case_id"] for r in rows if r["any_hit_pred"] and r["malicious_or_benign"] == "benign"],
        "false_negatives_any_hit": [r["case_id"] for r in rows if not r["any_hit_pred"] and r["malicious_or_benign"] == "malicious"],
    }
    METRICS_JSON.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    write_summary_md(rows, metrics)
    return metrics


def pct(x):
    return f"{100 * x:.1f}%"


def md_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(x) for x in row) + " |")
    return "\n".join(lines)


def write_summary_md(rows, metrics):
    risk = metrics["risk_level_confusion"]
    any_hit = metrics["any_hit_confusion"]
    family_rows = []
    for family, data in metrics["by_family_risk_level"].items():
        family_rows.append([
            family,
            data["count"],
            data["malicious"],
            data["benign"],
            data["TP"],
            data["FP"],
            data["FN"],
            data["TN"],
            pct(data["recall"]),
            pct(data["specificity"]),
            data["risk_levels"],
        ])
    any_family_rows = []
    for family, data in metrics["by_family_any_hit"].items():
        any_family_rows.append([
            family,
            data["count"],
            data["malicious"],
            data["benign"],
            data["TP"],
            data["FP"],
            data["FN"],
            data["TN"],
            pct(data["recall"]),
            pct(data["specificity"]),
            data["total_issues"],
        ])

    examples = []
    interesting = (
        metrics["false_positives_risk_level"][:5]
        + metrics["false_negatives_risk_level"][:5]
        + [r["case_id"] for r in rows if r["malicious_or_benign"] == "malicious" and r["risk_level_pred"]][:5]
    )
    seen = set()
    for case_id in interesting:
        if case_id in seen:
            continue
        seen.add(case_id)
        row = next(r for r in rows if r["case_id"] == case_id)
        snippets = []
        for issue in row.get("top_evidence", [])[:3]:
            pattern = str(issue.get("pattern", "")).replace("|", "\\|")
            if len(pattern) > 120:
                pattern = pattern[:117] + "..."
            snippets.append(f"`{issue.get('rule_id')}` `{Path(issue.get('file', '')).name}:{issue.get('line')}` `{pattern}`")
        examples.append([
            row["case_id"],
            row["malicious_or_benign"],
            row["family"],
            row["risk_level"],
            row["total_issues"],
            "<br>".join(snippets),
        ])

    md = f"""# SkillScan Benchmark v2 Comparison

## Setup

- SkillScan code: `{PROJECT_ROOT / "skillscan"}`
- Static backend: `skill-security-scan==1.0.0` from `{SITE_PACKAGES}`
- Rules: `{RULES_PATH}`
- Benchmark manifest: `{MANIFEST_PATH}`
- Cases scanned: {metrics["case_count"]}
- Successful scans: {metrics["success_count"]}
- Failed scans: {metrics["failure_count"]}
- Outputs:
  - Per-case JSON: `{PER_CASE_DIR}`
  - JSONL: `{RESULTS_JSONL}`
  - CSV: `{RESULTS_CSV}`
  - Metrics: `{METRICS_JSON}`
  - Raw log: `{RAW_LOG}`

Actual command:

```bash
cd {PROJECT_ROOT}
source {PROJECT_ROOT / "skillscan/.venv/bin/activate"}
python {OUT_DIR / "run_skillscan_benchmark_cmp.py"}
```

## Main Binary Comparison

Two comparison policies are reported:

- `any_hit`: any static rule hit means the case is flagged.
- `risk_level`: only `risk_level != SAFE` means the case is flagged.

### Risk-Level Policy

{md_table(["TP", "FP", "FN", "TN", "Precision", "Recall", "Specificity", "Accuracy", "F1"], [[risk["TP"], risk["FP"], risk["FN"], risk["TN"], pct(risk["precision"]), pct(risk["recall"]), pct(risk["specificity"]), pct(risk["accuracy"]), pct(risk["f1"])]])}

### Any-Hit Policy

{md_table(["TP", "FP", "FN", "TN", "Precision", "Recall", "Specificity", "Accuracy", "F1"], [[any_hit["TP"], any_hit["FP"], any_hit["FN"], any_hit["TN"], pct(any_hit["precision"]), pct(any_hit["recall"]), pct(any_hit["specificity"]), pct(any_hit["accuracy"]), pct(any_hit["f1"])]])}

## Distribution

- Ground truth: {metrics["actual_counts"]}
- SkillScan risk levels: {metrics["risk_level_counts"]}
- Rule hit counts: {metrics["rule_counts"]}
- Risk-level false positives: {len(metrics["false_positives_risk_level"])}
- Risk-level false negatives: {len(metrics["false_negatives_risk_level"])}
- Any-hit false positives: {len(metrics["false_positives_any_hit"])}
- Any-hit false negatives: {len(metrics["false_negatives_any_hit"])}

## By Family, Risk-Level Policy

{md_table(["Family", "N", "Mal", "Benign", "TP", "FP", "FN", "TN", "Recall", "Specificity", "Risk levels"], family_rows)}

## By Family, Any-Hit Policy

{md_table(["Family", "N", "Mal", "Benign", "TP", "FP", "FN", "TN", "Recall", "Specificity", "Total issues"], any_family_rows)}

## Representative Cases

{md_table(["Case", "GT", "Family", "Risk", "Issues", "Evidence"], examples)}

## Interpretation for ProvLoom Comparison

SkillScan is useful as a static screening baseline: under the `any_hit` policy it catches visible URL and command indicators in benchmark Skill instructions. Its own risk-score threshold is conservative on this synthetic v2 suite: all cases remain `SAFE` because most cases contain only one static indicator line.

The comparison also exposes the expected limitation: benign lookalikes and policy-approved upload/relay cases can still be flagged because static scanning sees URLs, local file actions, and command-like strings without proving a closed source-relay-sink provenance chain.

ProvLoom should be compared as a provenance explanation system rather than merely a higher/lower detector: its key advantage is distinguishing observed runtime chains, instruction-derived latent chains, hybrid evidence, and no-closed-chain cases.
"""
    SUMMARY_MD.write_text(md, encoding="utf-8")


def main():
    OUT_DIR.mkdir(exist_ok=True)
    PER_CASE_DIR.mkdir(exist_ok=True)
    manifest, cases = load_cases()
    rows = scan_cases(cases)
    metrics = write_outputs(rows, manifest)
    print(json.dumps({
        "out_dir": str(OUT_DIR),
        "case_count": metrics["case_count"],
        "success_count": metrics["success_count"],
        "risk_level_confusion": metrics["risk_level_confusion"],
        "any_hit_confusion": metrics["any_hit_confusion"],
        "summary": str(SUMMARY_MD),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
