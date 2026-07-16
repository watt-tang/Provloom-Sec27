from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LATEX_DIR = PROJECT_ROOT / "Latex"
GENERATED_DIR = LATEX_DIR / "generated"

HIGH_RISK_ROOT = Path("/mnt/e/dangerous_skills")
HIGH_RISK_PROVLOOM_DIR = Path("/mnt/e/log8/skills")
HIGH_RISK_STATIC_DIR = Path("/mnt/e/log10_stasticduibi")

SAFE_SAMPLE_ROOT = Path("/mnt/e/sample")
SAFE_SAMPLE_PROVLOOM_DIR = Path("/mnt/e/log9sample/skills")
SAFE_SAMPLE_STATIC_DIR = Path("/mnt/e/log9sample_stastic")

SKILLSCAN_HIGH_RISK_SUMMARY = PROJECT_ROOT / "skillscan_results" / "summary_stats.json"
SKILLSCAN_SAFE_SUMMARY = PROJECT_ROOT / "skillscan_results" / "sample_results" / "summary_stats.json"
HUMAN_REVIEW_SHEET = PROJECT_ROOT / "real_world2" / "human_review_sheet.csv"

OUTPUT_JSON = GENERATED_DIR / "realworld_scanner_summary.json"
OUTPUT_TEX = GENERATED_DIR / "realworld_scanner_tables.tex"
OUTPUT_MAIN_TEX = GENERATED_DIR / "realworld_scanner_tables_main.tex"
OUTPUT_APPENDIX_TEX = GENERATED_DIR / "realworld_scanner_tables_appendix.tex"

RISK_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "safe": 1,
    "info": 0,
    "unavailable": -1,
}

RISK_LEVELS = ["safe", "info", "low", "medium", "high", "critical", "unavailable"]
PROVLOOM_LEVELS = ["safe", "info", "low", "medium", "high", "critical"]
EVIDENCE_ORDER = {
    "hybrid": 4,
    "instruction_derived": 3,
    "observed_runtime": 2,
    "no_closed_chain": 1,
    "unknown": 0,
}


@dataclass
class ScannerRow:
    name: str
    counts: dict[str, int]
    total: int
    available: int

    @property
    def medium_plus(self) -> int:
        return self.counts.get("medium", 0) + self.counts.get("high", 0) + self.counts.get("critical", 0)

    @property
    def high_plus_critical(self) -> int:
        return self.counts.get("high", 0) + self.counts.get("critical", 0)


def normalize_risk_level(value: str | None) -> str:
    if not value:
        return "unavailable"
    lowered = value.strip().lower()
    if lowered in RISK_ORDER:
        return lowered
    if lowered == "严重风险":
        return "critical"
    if lowered == "高风险":
        return "high"
    if lowered == "中风险":
        return "medium"
    if lowered == "低风险":
        return "low"
    return "unavailable"


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


def repo_key_for_skill_root(skill_root: str, root_dir: Path) -> str:
    rel = Path(skill_root).resolve().relative_to(root_dir.resolve())
    return rel.parts[0]


def choose_better_row(current: dict | None, candidate: dict) -> dict:
    if current is None:
        return candidate
    current_key = (
        RISK_ORDER[normalize_risk_level(current.get("final_risk_level") or current.get("risk_level"))],
        1 if current.get("status") == "completed" else 0,
        EVIDENCE_ORDER[normalize_chain_type(current)],
        1 if current.get("evidence_strength") == "chain_backed" else 0,
        float(current.get("risk_score") or 0),
    )
    candidate_key = (
        RISK_ORDER[normalize_risk_level(candidate.get("final_risk_level") or candidate.get("risk_level"))],
        1 if candidate.get("status") == "completed" else 0,
        EVIDENCE_ORDER[normalize_chain_type(candidate)],
        1 if candidate.get("evidence_strength") == "chain_backed" else 0,
        float(candidate.get("risk_score") or 0),
    )
    return candidate if candidate_key > current_key else current


def load_json_rows(directory: Path) -> list[dict]:
    rows = []
    for path in sorted(directory.glob("*.json")):
        with path.open(encoding="utf-8") as handle:
            rows.append(json.load(handle))
    return rows


def aggregate_provloom(directory: Path, root_dir: Path, expected_total: int) -> tuple[ScannerRow, Counter[str], dict[str, dict]]:
    selected: dict[str, dict] = {}
    for row in load_json_rows(directory):
        repo_key = repo_key_for_skill_root(row["skill_root"], root_dir)
        selected[repo_key] = choose_better_row(selected.get(repo_key), row)

    counts = Counter()
    evidence_counts = Counter()
    for row in selected.values():
        counts[normalize_risk_level(row.get("final_risk_level") or row.get("risk_level"))] += 1
        evidence_counts[normalize_chain_type(row)] += 1

    for level in RISK_LEVELS:
        counts.setdefault(level, 0)
    counts["unavailable"] += max(0, expected_total - len(selected))

    scanner_row = ScannerRow(
        name="ProvLoom",
        counts=dict(counts),
        total=expected_total,
        available=len(selected),
    )
    return scanner_row, evidence_counts, selected


def aggregate_provloom_instances(directory: Path, expected_total: int) -> tuple[ScannerRow, Counter[str]]:
    counts = Counter()
    evidence_counts = Counter()
    available = 0
    for row in load_json_rows(directory):
        available += 1
        counts[normalize_risk_level(row.get("final_risk_level") or row.get("risk_level"))] += 1
        evidence_counts[normalize_chain_type(row)] += 1

    for level in RISK_LEVELS:
        counts.setdefault(level, 0)
    counts["unavailable"] += max(0, expected_total - available)

    scanner_row = ScannerRow(
        name="ProvLoom",
        counts=dict(counts),
        total=expected_total,
        available=available,
    )
    return scanner_row, evidence_counts


def aggregate_skillscan(summary_path: Path) -> ScannerRow:
    with summary_path.open(encoding="utf-8") as handle:
        summary = json.load(handle)
    counts = Counter()
    for level, value in summary["risk_level_counts"].items():
        counts[normalize_risk_level(level)] = int(value)
    for level in RISK_LEVELS:
        counts.setdefault(level, 0)
    total = int(summary.get("total_skill_dirs") or summary.get("count") or sum(counts.values()))
    return ScannerRow(name="SkillScan", counts=dict(counts), total=total, available=total)


def aggregate_existing_scanner(highest_risk_csv: Path, total: int, scanner_name: str, label: str) -> ScannerRow:
    counts = Counter()
    available = 0
    with highest_risk_csv.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if row["scanner_name"].strip().lower() != scanner_name:
                continue
            available += 1
            counts[normalize_risk_level(row["highest_risk_level"])] += 1

    for level in RISK_LEVELS:
        counts.setdefault(level, 0)
    counts["unavailable"] += max(0, total - available)
    return ScannerRow(name=label, counts=dict(counts), total=total, available=available)


def format_count(value: int) -> str:
    return str(value)


def render_scanner_rows(rows: Iterable[ScannerRow]) -> str:
    lines = []
    for row in rows:
        c = row.counts
        lines.append(
            " & ".join(
                [
                    row.name,
                    format_count(c.get("safe", 0)),
                    format_count(c.get("info", 0)),
                    format_count(c.get("low", 0)),
                    format_count(c.get("medium", 0)),
                    format_count(c.get("high", 0)),
                    format_count(c.get("critical", 0)),
                    format_count(c.get("unavailable", 0)),
                    format_count(row.medium_plus),
                    format_count(row.high_plus_critical),
                    format_count(row.total),
                ]
            )
            + r" \\"
        )
    return "\n".join(lines)


def render_evidence_rows(title: str, evidence_counts: Counter[str], total: int) -> str:
    return (
        f"{title} & {evidence_counts.get('observed_runtime', 0)} & "
        f"{evidence_counts.get('instruction_derived', 0)} & "
        f"{evidence_counts.get('hybrid', 0)} & "
        f"{evidence_counts.get('no_closed_chain', 0)} & {total} \\\\"
    )


def summarize_manual_review(path: Path) -> dict[str, object]:
    dedup: dict[str, dict[str, str]] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            key = row["skill_root"] or row["skill_id"]
            dedup[key] = row

    decision_counter = Counter()
    runtime_counter = Counter()
    instruction_counter = Counter()
    for row in dedup.values():
        decision = (row.get("human_decision") or "unknown").strip().lower()
        decision_counter[decision] += 1
        ev = (row.get("evidence_summary") or "").lower()
        if "status=completed" in ev:
            runtime_counter[decision] += 1
        if row.get("human_gt_chain_valid", "").strip().lower() == "true" and "instruction" in (row.get("human_gt_behavior") or "").lower():
            instruction_counter[decision] += 1

    return {
        "deduplicated_total": len(dedup),
        "decision_counts": dict(decision_counter),
        "runtime_completed_by_decision": dict(runtime_counter),
        "instruction_valid_by_decision": dict(instruction_counter),
    }


def build_summary() -> dict[str, object]:
    prov_high, prov_high_evidence, prov_high_selected = aggregate_provloom(
        HIGH_RISK_PROVLOOM_DIR, HIGH_RISK_ROOT, expected_total=470
    )
    prov_safe, prov_safe_evidence = aggregate_provloom_instances(SAFE_SAMPLE_PROVLOOM_DIR, expected_total=200)

    summary = {
        "high_risk": {
            "provloom": {
                "counts": prov_high.counts,
                "available": prov_high.available,
                "total": prov_high.total,
                "evidence_type_counts": dict(prov_high_evidence),
            },
            "skillscan": aggregate_skillscan(SKILLSCAN_HIGH_RISK_SUMMARY).__dict__,
            "cisco": aggregate_existing_scanner(
                HIGH_RISK_STATIC_DIR / "stats" / "highest_risk_per_skill.csv", 470, "cisco", "Cisco Skill Scanner"
            ).__dict__,
            "clawvet": aggregate_existing_scanner(
                HIGH_RISK_STATIC_DIR / "stats" / "highest_risk_per_skill.csv", 470, "clawvet", "ClawVet"
            ).__dict__,
            "skillfortify": aggregate_existing_scanner(
                HIGH_RISK_STATIC_DIR / "stats" / "highest_risk_per_skill.csv", 470, "skillfortify", "SkillFortify"
            ).__dict__,
        },
        "safe_like": {
            "provloom": {
                "counts": prov_safe.counts,
                "available": prov_safe.available,
                "total": prov_safe.total,
                "evidence_type_counts": dict(prov_safe_evidence),
            },
            "skillscan": aggregate_skillscan(SKILLSCAN_SAFE_SUMMARY).__dict__,
            "cisco": aggregate_existing_scanner(
                SAFE_SAMPLE_STATIC_DIR / "stats" / "highest_risk_per_skill.csv", 200, "cisco", "Cisco Skill Scanner"
            ).__dict__,
            "clawvet": aggregate_existing_scanner(
                SAFE_SAMPLE_STATIC_DIR / "stats" / "highest_risk_per_skill.csv", 200, "clawvet", "ClawVet"
            ).__dict__,
            "skillfortify": aggregate_existing_scanner(
                SAFE_SAMPLE_STATIC_DIR / "stats" / "highest_risk_per_skill.csv", 200, "skillfortify", "SkillFortify"
            ).__dict__,
        },
        "manual_audit": summarize_manual_review(HUMAN_REVIEW_SHEET),
        "provenance_samples": {
            "high_risk_selected_roots": sorted(prov_high_selected.keys())[:10],
            "safe_like_example_paths": sorted(path.name for path in SAFE_SAMPLE_PROVLOOM_DIR.glob("*.json"))[:10],
        },
    }
    return summary


def render_tables(summary: dict[str, object]) -> str:
    high = summary["high_risk"]
    safe = summary["safe_like"]
    audit = summary["manual_audit"]

    def row_from_dict(label: str, data: dict[str, object]) -> ScannerRow:
        return ScannerRow(
            name=label,
            counts=data["counts"],
            total=int(data["total"]),
            available=int(data["available"]),
        )

    high_rows = [
        row_from_dict("ProvLoom", high["provloom"]),
        row_from_dict("SkillScan", high["skillscan"]),
        row_from_dict("Cisco Skill Scanner", high["cisco"]),
        row_from_dict("ClawVet", high["clawvet"]),
        row_from_dict("SkillFortify", high["skillfortify"]),
    ]
    safe_rows = [
        row_from_dict("ProvLoom", safe["provloom"]),
        row_from_dict("SkillScan", safe["skillscan"]),
        row_from_dict("Cisco Skill Scanner", safe["cisco"]),
        row_from_dict("ClawVet", safe["clawvet"]),
        row_from_dict("SkillFortify", safe["skillfortify"]),
    ]

    return rf"""
\begin{{table}}[htbp]
\caption{{Real-world corpus construction and comparison inputs. The lightweight prefilter is used only for candidate construction, not as ground truth.}}
\label{{tab:realworld-construction}}
\centering
\scriptsize
\setlength{{\tabcolsep}}{{4pt}}
\begin{{tabularx}}{{\columnwidth}}{{L{{0.28\columnwidth}}L{{0.23\columnwidth}}cY}}
\toprule
\textbf{{Stage}} & \textbf{{Source / artifact}} & \textbf{{Count}} & \textbf{{Role}} \\
\midrule
Discovery pool & Public GitHub Skill candidates & 80K+ & Broad public collection before filtering \\
Lightweight prefilter & syedabbast/skill-scanner~\cite{{syedabbast_skill_scanner}} & risk-enriched & Simple open-source prefilter used only to construct the candidate set \\
High-risk evaluation corpus & Top-level public Skills & 470 & Main real-world comparison set for scanner triage behavior \\
Safe-like calibration sample & Randomly sampled public Skills & 200 & False-positive and calibration comparison set \\
ProvLoom runtime logs & \path{{/mnt/e/log8}}, \path{{/mnt/e/log9sample}} & 470 / 200 roots & Evidence-typed runtime plus local-instruction analysis, aggregated by top-level sample \\
Static scanner comparison & SkillScan, Cisco, ClawVet, SkillFortify & 470 / 200 & Existing-tool triage comparison under tool-specific severity taxonomies \\
\bottomrule
\end{{tabularx}}
\end{{table}}

\begin{{table*}}[htbp]
\caption{{Risk-enriched 470-Skill public comparison. Counts are top-level sample strata after per-tool normalization to the highest reported risk per sample. Severity taxonomies are tool-specific, and \texttt{{unavail.}} marks scanner failures or missing outputs rather than safe judgments.}}
\label{{tab:scanner-compare-highrisk}}
\centering
\scriptsize
\setlength{{\tabcolsep}}{{3pt}}
\begin{{tabular*}}{{\textwidth}}{{@{{\extracolsep{{\fill}}}}lcccccccccc}}
\toprule
\textbf{{Tool}} & \textbf{{Safe}} & \textbf{{Info}} & \textbf{{Low}} & \textbf{{Med.}} & \textbf{{High}} & \textbf{{Crit.}} & \textbf{{Unavail.}} & \textbf{{Med.+}} & \textbf{{High+Crit.}} & \textbf{{Total}} \\
\midrule
{render_scanner_rows(high_rows)}
\bottomrule
\end{{tabular*}}
\end{{table*}}

\begin{{table*}}[htbp]
\caption{{Random 200-sample safe-like calibration comparison. ProvLoom reports the 200 executed sample paths from \texttt{{/mnt/e/log9sample}}, while the static scanners report the highest risk over the corresponding sampled packages; for multi-skill bundles this is a conservative static normalization. The main comparison is triage aggressiveness and false-positive behavior, not corpus-level accuracy.}}
\label{{tab:scanner-compare-safelike}}
\centering
\scriptsize
\setlength{{\tabcolsep}}{{3pt}}
\begin{{tabular*}}{{\textwidth}}{{@{{\extracolsep{{\fill}}}}lcccccccccc}}
\toprule
\textbf{{Tool}} & \textbf{{Safe}} & \textbf{{Info}} & \textbf{{Low}} & \textbf{{Med.}} & \textbf{{High}} & \textbf{{Crit.}} & \textbf{{Unavail.}} & \textbf{{Med.+}} & \textbf{{High+Crit.}} & \textbf{{Total}} \\
\midrule
{render_scanner_rows(safe_rows)}
\bottomrule
\end{{tabular*}}
\end{{table*}}

\begin{{table}}[htbp]
\caption{{ProvLoom evidence-type distribution after top-level aggregation. \texttt{{no\_closed\_chain}} means disconnected indicators or incomplete evidence remained weak signals rather than high-confidence malicious chains.}}
\label{{tab:provloom-evidence-types}}
\centering
\scriptsize
\setlength{{\tabcolsep}}{{4pt}}
\begin{{tabularx}}{{\columnwidth}}{{L{{0.26\columnwidth}}ccccc}}
\toprule
\textbf{{Corpus}} & \textbf{{Observed}} & \textbf{{Instr.}} & \textbf{{Hybrid}} & \textbf{{No chain}} & \textbf{{Total}} \\
\midrule
{render_evidence_rows("470 risk-enriched", Counter(high["provloom"]["evidence_type_counts"]), 470)}
{render_evidence_rows("200 safe-like", Counter(safe["provloom"]["evidence_type_counts"]), 200)}
\bottomrule
\end{{tabularx}}
\end{{table}}

\begin{{table}}[htbp]
\caption{{Deduplicated high/critical manual audit summary over top-level repositories. Confirmed malicious counts come only from reviewed audit targets, not from automatic strata.}}
\label{{tab:hc-review}}
\centering
\scriptsize
\setlength{{\tabcolsep}}{{3pt}}
\begin{{tabularx}}{{\columnwidth}}{{L{{0.24\columnwidth}}cY}}
\toprule
\textbf{{Outcome}} & \textbf{{Unique skills}} & \textbf{{Interpretation}} \\
\midrule
Confirmed malicious & {audit["decision_counts"].get("malicious", 0)} & Closed evidence path plus reviewer agreement; strongest cases are instruction-derived setup or maintenance chains. \\
Ambiguous / requires review & {audit["decision_counts"].get("ambiguous", 0)} & Security-relevant but insufficient to call malicious; often noisy runtime transfer or risky setup text without decisive intent evidence. \\
Benign / defensive false positive & {audit["decision_counts"].get("benign", 0)} & Public API use, local reporting, detector strings, or security-tool examples that do not close a malicious chain. \\
\bottomrule
\end{{tabularx}}
\end{{table}}
"""


def split_tables(rendered: str) -> tuple[str, str]:
    blocks = [block for block in rendered.strip().split("\n\n") if block.strip()]
    # Keep only the main 470 high-risk comparison in the paper body.
    main_blocks = [block for block in blocks if r"\label{tab:scanner-compare-highrisk}" in block]
    appendix_blocks = [block for block in blocks if block not in main_blocks]
    return "\n\n".join(main_blocks) + "\n", "\n\n".join(appendix_blocks) + "\n"


def main() -> None:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    summary = build_summary()
    OUTPUT_JSON.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    rendered = render_tables(summary)
    OUTPUT_TEX.write_text(rendered, encoding="utf-8")
    main_tex, appendix_tex = split_tables(rendered)
    OUTPUT_MAIN_TEX.write_text(main_tex, encoding="utf-8")
    OUTPUT_APPENDIX_TEX.write_text(appendix_tex, encoding="utf-8")
    print(f"Wrote {OUTPUT_JSON}")
    print(f"Wrote {OUTPUT_TEX}")
    print(f"Wrote {OUTPUT_MAIN_TEX}")
    print(f"Wrote {OUTPUT_APPENDIX_TEX}")


if __name__ == "__main__":
    main()
