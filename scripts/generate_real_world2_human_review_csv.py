from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLASSIFICATION_CSV = PROJECT_ROOT / "real_world2" / "doc" / "log8_result_classification.csv"
DEFAULT_ANNOTATION_MD = PROJECT_ROOT / "real_world2" / "doc" / "标注2.md"
DEFAULT_OUTPUT_CSV = PROJECT_ROOT / "real_world2" / "human_review_sheet.csv"

REVIEW_COLUMNS = [
    "sample_id",
    "stratum",
    "skill_id",
    "name",
    "skill_root",
    "risk_level",
    "risk_score",
    "detected_behaviors",
    "primary_chain_length",
    "primary_chain",
    "root_cause",
    "root_cause_detail",
    "mechanism_class",
    "primary_driver",
    "evidence_status",
    "trace_overview",
    "trace_summary",
    "external_endpoints",
    "execution_artifact_dir",
    "snippet_digest",
    "snippet_refs",
    "machine_gt_risk",
    "machine_gt_behavior",
    "machine_gt_chain_valid",
    "machine_gt_root_cause",
    "machine_confidence",
    "evidence_summary",
    "needs_human_review",
    "machine_assisted_status",
    "human_decision",
    "human_gt_behavior",
    "human_gt_chain_valid",
    "human_gt_root_cause",
    "human_notes",
    "reviewer",
    "review_status",
]

SECTION_RE = re.compile(r"^##\s+(RW-[A-Z]+-\d+)\s+—\s+(.+?)\s*$", re.M)
KV_RE = re.compile(
    r"^(human_decision|human_gt_behavior|human_gt_chain_valid|human_gt_root_cause|human_notes|reviewer|review_status)\s*=\s*(.*?)\s*$",
    re.M,
)


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def risk_rank(row: dict[str, Any]) -> int:
    risk = (row.get("final_risk_level") or row.get("risk_level_name") or "").lower()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(risk, 9)


def parse_annotations(path: Path) -> list[dict[str, str]]:
    content = path.read_text(encoding="utf-8")
    matches = list(SECTION_RE.finditer(content))
    results: list[dict[str, str]] = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(content)
        block = content[start:end]
        fields = {k: v.strip() for k, v in KV_RE.findall(block)}
        if not fields:
            continue
        results.append(
            {
                "sample_id": match.group(1).strip(),
                "annotated_name": match.group(2).strip(),
                **fields,
            }
        )
    return results


def split_aliases(name: str) -> list[str]:
    aliases = [name]
    aliases.extend(x.strip() for x in re.split(r"[|/,]", name) if x.strip())
    dedup: list[str] = []
    seen = set()
    for alias in aliases:
        key = normalize(alias)
        if not key or key in seen:
            continue
        seen.add(key)
        dedup.append(alias)
    return dedup


def score_candidate(annotation_name: str, row: dict[str, str]) -> int:
    row_name = row.get("name", "")
    row_skill_id = row.get("skill_id", "")
    row_name_n = normalize(row_name)
    row_skill_n = normalize(row_skill_id)

    best = 0
    for alias in split_aliases(annotation_name):
        alias_n = normalize(alias)
        if not alias_n:
            continue
        if alias_n == row_name_n:
            best = max(best, 120)
        if alias_n == row_skill_n:
            best = max(best, 110)
        if row_skill_n.endswith(alias_n):
            best = max(best, 108)
        if row_name_n.endswith(alias_n):
            best = max(best, 104)
        if alias_n in row_skill_n:
            best = max(best, 100)
        if alias_n in row_name_n:
            best = max(best, 95)
        if row_name_n and row_name_n in alias_n:
            best = max(best, 80)
    return best


def pick_row(annotation_name: str, rows: list[dict[str, str]]) -> dict[str, str] | None:
    scored: list[tuple[int, int, dict[str, str]]] = []
    for row in rows:
        score = score_candidate(annotation_name, row)
        if score <= 0:
            continue
        scored.append((score, -risk_rank(row), row))
    if not scored:
        return None
    scored.sort(key=lambda x: (x[0], x[1], float(x[2].get("risk_score") or 0.0)), reverse=True)
    return scored[0][2]


def parse_stratum(sample_id: str) -> str:
    if sample_id.startswith("RW-HC-"):
        return "rw_hc"
    if sample_id.startswith("RW-AUDIT-"):
        return "rw_audit"
    return "unknown"


def evidence_summary(row: dict[str, str] | None) -> str:
    if not row:
        return ""
    parts = []
    for key in ("status", "evidence_strength", "execution_outcome", "skip_reason"):
        value = (row.get(key) or "").strip()
        if value:
            parts.append(f"{key}={value}")
    return "; ".join(parts)


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def build_review_rows(annotations: list[dict[str, str]], classification_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for ann in annotations:
        matched = pick_row(ann["annotated_name"], classification_rows)
        risk_level = ""
        risk_score = ""
        if matched:
            risk_level = matched.get("final_risk_level") or matched.get("risk_level_name") or ""
            risk_score = matched.get("risk_score") or ""

        row = {
            "sample_id": ann.get("sample_id", ""),
            "stratum": parse_stratum(ann.get("sample_id", "")),
            "skill_id": (matched or {}).get("skill_id", ""),
            "name": (matched or {}).get("name", ann.get("annotated_name", "")),
            "skill_root": (matched or {}).get("skill_root", ""),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "detected_behaviors": (matched or {}).get("detected_behaviors", ""),
            "primary_chain_length": "",
            "primary_chain": "",
            "root_cause": (matched or {}).get("root_cause", ""),
            "root_cause_detail": (matched or {}).get("root_cause_detail", ""),
            "mechanism_class": (matched or {}).get("root_cause_v2_mechanism_class", ""),
            "primary_driver": (matched or {}).get("root_cause_v2_primary_driver", ""),
            "evidence_status": (matched or {}).get("root_cause_v2_evidence_status", ""),
            "trace_overview": "",
            "trace_summary": "",
            "external_endpoints": "",
            "execution_artifact_dir": "",
            "snippet_digest": "",
            "snippet_refs": "",
            "machine_gt_risk": "",
            "machine_gt_behavior": "",
            "machine_gt_chain_valid": "",
            "machine_gt_root_cause": "",
            "machine_confidence": (matched or {}).get("evidence_strength", ""),
            "evidence_summary": evidence_summary(matched),
            "needs_human_review": "false",
            "machine_assisted_status": "human_reviewed_from_annotations",
            "human_decision": ann.get("human_decision", ""),
            "human_gt_behavior": ann.get("human_gt_behavior", ""),
            "human_gt_chain_valid": ann.get("human_gt_chain_valid", ""),
            "human_gt_root_cause": ann.get("human_gt_root_cause", ""),
            "human_notes": ann.get("human_notes", ""),
            "reviewer": ann.get("reviewer", ""),
            "review_status": ann.get("review_status", ""),
        }
        rows.append(row)
    return rows


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=REVIEW_COLUMNS,
            quoting=csv.QUOTE_ALL,
            escapechar="\\",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in REVIEW_COLUMNS})


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate real_world2 human review CSV from 标注2.md.")
    parser.add_argument("--classification-csv", type=Path, default=DEFAULT_CLASSIFICATION_CSV)
    parser.add_argument("--annotation-md", type=Path, default=DEFAULT_ANNOTATION_MD)
    parser.add_argument("--output-csv", type=Path, default=DEFAULT_OUTPUT_CSV)
    args = parser.parse_args()

    annotations = parse_annotations(args.annotation_md)
    classification_rows = load_rows(args.classification_csv)
    review_rows = build_review_rows(annotations, classification_rows)
    write_csv(args.output_csv, review_rows)

    missing = [row for row in review_rows if not row.get("skill_id")]
    print(f"Generated {len(review_rows)} review rows -> {args.output_csv}")
    print(f"Matched rows: {len(review_rows) - len(missing)}, unmatched rows: {len(missing)}")
    if missing:
        print("Unmatched sample_ids:")
        for row in missing:
            print(f"  - {row['sample_id']}: {row['name']}")


if __name__ == "__main__":
    main()
