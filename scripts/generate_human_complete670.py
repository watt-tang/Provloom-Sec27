from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path, PurePosixPath


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = PROJECT_ROOT / "docs"
OUTPUT_CSV = DOCS_DIR / "human_complete670.csv"

HIGH_RISK_ROOT = Path("/mnt/e/dangerous_skills")
HIGH_RISK_PROVLOOM_DIR = Path("/mnt/e/log8/skills")
HIGH_RISK_STATIC_CSV = Path("/mnt/e/log10_stasticduibi/stats/highest_risk_per_skill.csv")
HIGH_RISK_SKILLSCAN_RESULTS = PROJECT_ROOT / "skillscan_results" / "results.jsonl"

SAFE_SAMPLE_ROOT = Path("/mnt/e/sample")
SAFE_SAMPLE_PROVLOOM_DIR = Path("/mnt/e/log9sample/skills")
SAFE_SAMPLE_STATIC_CSV = Path("/mnt/e/log9sample_stastic/stats/highest_risk_per_skill.csv")
SAFE_SAMPLE_SKILLSCAN_RESULTS = PROJECT_ROOT / "skillscan_results" / "sample_results" / "results.jsonl"
SAFE_SAMPLE_SKILLSCAN_MANIFEST = PROJECT_ROOT / "skillscan_results" / "sample_results" / "manifest.json"

HUMAN_REVIEW_SHEET = PROJECT_ROOT / "real_world2" / "human_review_sheet.csv"

RISK_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "safe": 1,
    "info": 0,
    "unavailable": -1,
}


def normalize_risk_level(value: str | None) -> str:
    if not value:
        return "unavailable"
    lowered = value.strip().lower()
    aliases = {
        "严重风险": "critical",
        "高风险": "high",
        "中风险": "medium",
        "低风险": "low",
    }
    return aliases.get(lowered, lowered if lowered in RISK_ORDER else "unavailable")


def normalize_chain_type(row: dict) -> str:
    chain_type = (row.get("chain_evidence_type") or "").strip().lower()
    if chain_type in {"observed_runtime", "instruction_derived", "hybrid", "no_closed_chain"}:
        return chain_type
    dynamic = bool(row.get("dynamic_chain_observed"))
    instruction = bool(row.get("instruction_chain_recovered"))
    if dynamic and instruction:
        return "hybrid"
    if instruction:
        return "instruction_derived"
    if dynamic:
        return "observed_runtime"
    return "no_closed_chain"


def to_posix_path(path_str: str) -> PurePosixPath:
    normalized = path_str.replace("\\", "/")
    return PurePosixPath(normalized)


def first_part_relative(path_str: str, root_dir: Path) -> str:
    rel = to_posix_path(path_str).relative_to(to_posix_path(str(root_dir)))
    return rel.parts[0]


def windows_to_posix(raw: str) -> str:
    return raw.replace("\\", "/").replace("E:", "/mnt/e")


def path_to_skill_id(path_str: str) -> str:
    normalized = path_str.replace("\\", "/").strip("/")
    return normalized.replace("/", "_")


def safe_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def primary_chain_length(row: dict) -> int:
    chain = row.get("primary_chain")
    if isinstance(chain, list):
        return len(chain)
    return 0


def choose_better_provloom_row(current: dict | None, candidate: dict) -> dict:
    if current is None:
        return candidate
    current_key = (
        RISK_ORDER[normalize_risk_level(current.get("final_risk_level") or current.get("risk_level"))],
        1 if current.get("status") == "completed" else 0,
        1 if current.get("evidence_strength") == "chain_backed" else 0,
        {"hybrid": 4, "instruction_derived": 3, "observed_runtime": 2, "no_closed_chain": 1}.get(
            normalize_chain_type(current), 0
        ),
        float(current.get("risk_score") or 0),
    )
    candidate_key = (
        RISK_ORDER[normalize_risk_level(candidate.get("final_risk_level") or candidate.get("risk_level"))],
        1 if candidate.get("status") == "completed" else 0,
        1 if candidate.get("evidence_strength") == "chain_backed" else 0,
        {"hybrid": 4, "instruction_derived": 3, "observed_runtime": 2, "no_closed_chain": 1}.get(
            normalize_chain_type(candidate), 0
        ),
        float(candidate.get("risk_score") or 0),
    )
    return candidate if candidate_key > current_key else current


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def build_high_risk_provloom() -> dict[str, dict]:
    selected: dict[str, dict] = {}
    for path in sorted(HIGH_RISK_PROVLOOM_DIR.glob("*.json")):
        row = load_json(path)
        sample_key = first_part_relative(row["skill_root"], HIGH_RISK_ROOT)
        selected[sample_key] = choose_better_provloom_row(selected.get(sample_key), row)
    return selected


def build_safe_like_provloom() -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for path in sorted(SAFE_SAMPLE_PROVLOOM_DIR.glob("*.json")):
        row = load_json(path)
        rows[row["skill_id"]] = row
    return rows


def build_high_risk_skillscan() -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for row in load_jsonl(HIGH_RISK_SKILLSCAN_RESULTS):
        sample_key = first_part_relative(row["skill_path"], HIGH_RISK_ROOT)
        rows[sample_key] = row
    return rows


def manifest_skill_ids() -> set[str]:
    manifest = load_json(SAFE_SAMPLE_SKILLSCAN_MANIFEST)
    ids = set()
    for row in manifest.get("skills", []):
        if isinstance(row, dict):
            skill_id = row.get("skill_id")
            if skill_id:
                ids.add(skill_id)
        elif isinstance(row, str):
            ids.add(path_to_skill_id(row))
    return ids


def build_safe_like_skillscan() -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for row in load_jsonl(SAFE_SAMPLE_SKILLSCAN_RESULTS):
        if row.get("skill_id"):
            rows[row["skill_id"]] = row
    return rows


def build_static_map(path: Path) -> dict[str, dict[str, dict]]:
    by_scanner: dict[str, dict[str, dict]] = defaultdict(dict)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            by_scanner[row["scanner_name"].strip().lower()][row["skill_id"]] = row
    return by_scanner


def build_review_seed() -> dict[str, dict]:
    seed: dict[str, dict] = {}
    with HUMAN_REVIEW_SHEET.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            skill_root = row.get("skill_root") or ""
            if not skill_root:
                continue
            sample_key = first_part_relative(skill_root, HIGH_RISK_ROOT)
            if sample_key not in seed:
                seed[sample_key] = row
    return seed


def base_columns() -> list[str]:
    return [
        "corpus",
        "sample_scope",
        "sample_key",
        "sample_name",
        "sample_root_or_path",
        "sample_root_or_path_windows",
        "provloom_selected_skill_id",
        "provloom_selected_skill_root",
        "provloom_selected_skill_name",
        "provloom_status",
        "provloom_execution_outcome",
        "provloom_final_risk_level",
        "provloom_risk_score",
        "provloom_evidence_type",
        "provloom_evidence_strength",
        "provloom_primary_chain_length",
        "provloom_root_cause",
        "provloom_detected_behaviors",
        "provloom_external_endpoints",
        "skillscan_risk_level",
        "skillscan_risk_score",
        "skillscan_total_issues",
        "skillscan_status",
        "skillscan_path",
        "skillscan_match_scope",
        "cisco_risk_level",
        "cisco_status",
        "cisco_source_path",
        "cisco_match_scope",
        "clawvet_risk_level",
        "clawvet_status",
        "clawvet_source_path",
        "clawvet_match_scope",
        "skillfortify_risk_level",
        "skillfortify_status",
        "skillfortify_source_path",
        "skillfortify_match_scope",
        "seeded_from_existing_review",
        "existing_human_decision",
        "existing_human_gt_behavior",
        "existing_human_gt_chain_valid",
        "existing_human_gt_root_cause",
        "existing_human_notes",
        "existing_reviewer",
        "existing_review_status",
        "human_decision",
        "human_gt_behavior",
        "human_gt_chain_valid",
        "human_gt_root_cause",
        "human_notes",
        "reviewer",
        "review_status",
    ]


def row_from_high_risk(
    sample_key: str,
    provloom: dict | None,
    skillscan: dict | None,
    static_rows: dict[str, dict[str, dict]],
    review_seed: dict[str, dict],
) -> dict[str, str]:
    review = review_seed.get(sample_key, {})
    sample_root = str(HIGH_RISK_ROOT / sample_key)
    cisco = static_rows.get("cisco", {}).get(sample_key, {})
    clawvet = static_rows.get("clawvet", {}).get(sample_key, {})
    skillfortify = static_rows.get("skillfortify", {}).get(sample_key, {})
    effective_name = (
        safe_str((provloom or {}).get("name"))
        or safe_str((skillscan or {}).get("skill_name"))
        or sample_key
    )
    return {
        "corpus": "high_risk_470",
        "sample_scope": "top_level_public_sample",
        "sample_key": sample_key,
        "sample_name": effective_name,
        "sample_root_or_path": sample_root,
        "sample_root_or_path_windows": sample_root.replace("/mnt/e", "E:").replace("/", "\\"),
        "provloom_selected_skill_id": safe_str((provloom or {}).get("skill_id")),
        "provloom_selected_skill_root": safe_str((provloom or {}).get("skill_root")),
        "provloom_selected_skill_name": safe_str((provloom or {}).get("name")),
        "provloom_status": safe_str((provloom or {}).get("status")),
        "provloom_execution_outcome": safe_str((provloom or {}).get("execution_outcome")),
        "provloom_final_risk_level": normalize_risk_level(
            (provloom or {}).get("final_risk_level") or (provloom or {}).get("risk_level")
        ),
        "provloom_risk_score": safe_str((provloom or {}).get("risk_score")),
        "provloom_evidence_type": normalize_chain_type(provloom or {}),
        "provloom_evidence_strength": safe_str((provloom or {}).get("evidence_strength")),
        "provloom_primary_chain_length": str(primary_chain_length(provloom or {})),
        "provloom_root_cause": safe_str((provloom or {}).get("root_cause")),
        "provloom_detected_behaviors": safe_str((provloom or {}).get("detected_behaviors")),
        "provloom_external_endpoints": safe_str((provloom or {}).get("external_endpoints")),
        "skillscan_risk_level": normalize_risk_level((skillscan or {}).get("risk_level")),
        "skillscan_risk_score": safe_str((skillscan or {}).get("risk_score")),
        "skillscan_total_issues": safe_str((skillscan or {}).get("total_issues")),
        "skillscan_status": safe_str((skillscan or {}).get("status")),
        "skillscan_path": safe_str((skillscan or {}).get("skill_path")),
        "skillscan_match_scope": "top_level_public_sample" if skillscan else "unavailable",
        "cisco_risk_level": normalize_risk_level(cisco.get("highest_risk_level")),
        "cisco_status": safe_str(cisco.get("statuses")),
        "cisco_source_path": safe_str(cisco.get("source_path")),
        "cisco_match_scope": "top_level_public_sample" if cisco else "unavailable",
        "clawvet_risk_level": normalize_risk_level(clawvet.get("highest_risk_level")),
        "clawvet_status": safe_str(clawvet.get("statuses")),
        "clawvet_source_path": safe_str(clawvet.get("source_path")),
        "clawvet_match_scope": "top_level_public_sample" if clawvet else "unavailable",
        "skillfortify_risk_level": normalize_risk_level(skillfortify.get("highest_risk_level")),
        "skillfortify_status": safe_str(skillfortify.get("statuses")),
        "skillfortify_source_path": safe_str(skillfortify.get("source_path")),
        "skillfortify_match_scope": "top_level_public_sample" if skillfortify else "unavailable",
        "seeded_from_existing_review": "true" if review else "false",
        "existing_human_decision": safe_str(review.get("human_decision")),
        "existing_human_gt_behavior": safe_str(review.get("human_gt_behavior")),
        "existing_human_gt_chain_valid": safe_str(review.get("human_gt_chain_valid")),
        "existing_human_gt_root_cause": safe_str(review.get("human_gt_root_cause")),
        "existing_human_notes": safe_str(review.get("human_notes")),
        "existing_reviewer": safe_str(review.get("reviewer")),
        "existing_review_status": safe_str(review.get("review_status")),
        "human_decision": "",
        "human_gt_behavior": "",
        "human_gt_chain_valid": "",
        "human_gt_root_cause": "",
        "human_notes": "",
        "reviewer": "",
        "review_status": "",
    }


def row_from_safe_like(
    skill_id: str,
    provloom: dict,
    skillscan: dict | None,
    skillscan_top_level: dict | None,
    static_rows: dict[str, dict[str, dict]],
) -> dict[str, str]:
    sample_key = first_part_relative(provloom["skill_root"], SAFE_SAMPLE_ROOT)
    sample_root = str(Path(provloom["skill_root"]).resolve())
    effective_skillscan = skillscan or skillscan_top_level or {}
    if skillscan:
        skillscan_match_scope = "exact_skill_path"
    elif skillscan_top_level:
        skillscan_match_scope = "top_level_package_max"
    else:
        skillscan_match_scope = "unavailable"
    cisco = static_rows.get("cisco", {}).get(sample_key, {})
    clawvet = static_rows.get("clawvet", {}).get(sample_key, {})
    skillfortify = static_rows.get("skillfortify", {}).get(sample_key, {})
    return {
        "corpus": "safe_like_200",
        "sample_scope": "sampled_skill_path",
        "sample_key": skill_id,
        "sample_name": safe_str(provloom.get("name")),
        "sample_root_or_path": sample_root,
        "sample_root_or_path_windows": sample_root.replace("/mnt/e", "E:").replace("/", "\\"),
        "provloom_selected_skill_id": safe_str(provloom.get("skill_id")),
        "provloom_selected_skill_root": safe_str(provloom.get("skill_root")),
        "provloom_selected_skill_name": safe_str(provloom.get("name")),
        "provloom_status": safe_str(provloom.get("status")),
        "provloom_execution_outcome": safe_str(provloom.get("execution_outcome")),
        "provloom_final_risk_level": normalize_risk_level(provloom.get("final_risk_level") or provloom.get("risk_level")),
        "provloom_risk_score": safe_str(provloom.get("risk_score")),
        "provloom_evidence_type": normalize_chain_type(provloom),
        "provloom_evidence_strength": safe_str(provloom.get("evidence_strength")),
        "provloom_primary_chain_length": str(primary_chain_length(provloom)),
        "provloom_root_cause": safe_str(provloom.get("root_cause")),
        "provloom_detected_behaviors": safe_str(provloom.get("detected_behaviors")),
        "provloom_external_endpoints": safe_str(provloom.get("external_endpoints")),
        "skillscan_risk_level": normalize_risk_level(effective_skillscan.get("risk_level")),
        "skillscan_risk_score": safe_str(effective_skillscan.get("risk_score")),
        "skillscan_total_issues": safe_str(effective_skillscan.get("total_issues")),
        "skillscan_status": safe_str(effective_skillscan.get("status")),
        "skillscan_path": safe_str(effective_skillscan.get("skill_path")),
        "skillscan_match_scope": skillscan_match_scope,
        "cisco_risk_level": normalize_risk_level(cisco.get("highest_risk_level")),
        "cisco_status": safe_str(cisco.get("statuses")),
        "cisco_source_path": safe_str(cisco.get("source_path")),
        "cisco_match_scope": "top_level_package_max" if cisco else "unavailable",
        "clawvet_risk_level": normalize_risk_level(clawvet.get("highest_risk_level")),
        "clawvet_status": safe_str(clawvet.get("statuses")),
        "clawvet_source_path": safe_str(clawvet.get("source_path")),
        "clawvet_match_scope": "top_level_package_max" if clawvet else "unavailable",
        "skillfortify_risk_level": normalize_risk_level(skillfortify.get("highest_risk_level")),
        "skillfortify_status": safe_str(skillfortify.get("statuses")),
        "skillfortify_source_path": safe_str(skillfortify.get("source_path")),
        "skillfortify_match_scope": "top_level_package_max" if skillfortify else "unavailable",
        "seeded_from_existing_review": "false",
        "existing_human_decision": "",
        "existing_human_gt_behavior": "",
        "existing_human_gt_chain_valid": "",
        "existing_human_gt_root_cause": "",
        "existing_human_notes": "",
        "existing_reviewer": "",
        "existing_review_status": "",
        "human_decision": "",
        "human_gt_behavior": "",
        "human_gt_chain_valid": "",
        "human_gt_root_cause": "",
        "human_notes": "",
        "reviewer": "",
        "review_status": "",
    }


def main() -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    high_provloom = build_high_risk_provloom()
    safe_provloom = build_safe_like_provloom()
    high_skillscan = build_high_risk_skillscan()
    safe_skillscan = build_safe_like_skillscan()
    high_static = build_static_map(HIGH_RISK_STATIC_CSV)
    safe_static = build_static_map(SAFE_SAMPLE_STATIC_CSV)
    review_seed = build_review_seed()

    safe_skillscan_top_level: dict[str, dict] = {}
    for row in safe_skillscan.values():
        sample_key = first_part_relative(row["skill_path"], SAFE_SAMPLE_ROOT)
        current = safe_skillscan_top_level.get(sample_key)
        if current is None or RISK_ORDER[normalize_risk_level(row.get("risk_level"))] > RISK_ORDER[
            normalize_risk_level(current.get("risk_level"))
        ]:
            safe_skillscan_top_level[sample_key] = row

    rows: list[dict[str, str]] = []

    high_sample_keys = set(high_provloom) | set(high_skillscan) | set(high_static.get("skillfortify", {}))
    for sample_key in sorted(high_sample_keys):
        rows.append(
            row_from_high_risk(
                sample_key=sample_key,
                provloom=high_provloom.get(sample_key),
                skillscan=high_skillscan.get(sample_key),
                static_rows=high_static,
                review_seed=review_seed,
            )
        )

    for skill_id in sorted(safe_provloom):
        sample_key = first_part_relative(safe_provloom[skill_id]["skill_root"], SAFE_SAMPLE_ROOT)
        rows.append(
            row_from_safe_like(
                skill_id=skill_id,
                provloom=safe_provloom[skill_id],
                skillscan=safe_skillscan.get(skill_id),
                skillscan_top_level=safe_skillscan_top_level.get(sample_key),
                static_rows=safe_static,
            )
        )

    if len(high_sample_keys) != 470:
        raise RuntimeError(f"Expected 470 high-risk canonical rows, got {len(high_sample_keys)}")
    if len(safe_provloom) != 200:
        raise RuntimeError(f"Expected 200 safe-like ProvLoom rows, got {len(safe_provloom)}")
    if len(rows) != 670:
        raise RuntimeError(f"Expected 670 total rows, got {len(rows)}")

    fieldnames = base_columns()
    with OUTPUT_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {OUTPUT_CSV}")
    print(f"high_risk_rows={len(high_provloom)}")
    print(f"safe_like_rows={len(safe_provloom)}")
    print(f"total_rows={len(rows)}")


if __name__ == "__main__":
    main()
