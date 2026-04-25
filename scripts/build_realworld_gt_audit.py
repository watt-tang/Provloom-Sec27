from __future__ import annotations

import argparse
import csv
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_DIR = Path("/mnt/e/log7")
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "realworld_gt_audit"
DEFAULT_SEED = 20260424

STRATA_ORDER = [
    "suspected_benign_fp_note_report_inventory",
    "upload_or_mirror_outward",
    "chain_backed_critical",
    "llm_decision_heavy",
    "representative_low_risk",
    "partial_evidence_medium",
]

BASE_SAMPLE_QUOTAS = {
    "suspected_benign_fp_note_report_inventory": 20,
    "upload_or_mirror_outward": 20,
    "chain_backed_critical": 16,
    "llm_decision_heavy": 16,
    "representative_low_risk": 8,
    "partial_evidence_medium": 16,
}

REDISTRIBUTION_ORDER = [
    "upload_or_mirror_outward",
    "chain_backed_critical",
    "llm_decision_heavy",
    "partial_evidence_medium",
    "suspected_benign_fp_note_report_inventory",
    "representative_low_risk",
]

TARGET_SAMPLE_SIZE = sum(BASE_SAMPLE_QUOTAS.values())

NOTE_RE = re.compile(r"(^|[^a-z0-9])(note|memo|summary|brief|report|inventory)($|[^a-z0-9])", re.I)
UPLOAD_RE = re.compile(r"(^|[^a-z0-9])(upload|sync|relay|post|publish|share|send|push|webhook|mirror)($|[^a-z0-9])", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.I)
HOST_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?\b")
FILE_LIKE_SUFFIXES = {
    ".md",
    ".txt",
    ".json",
    ".jsonl",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".sh",
    ".bash",
    ".zsh",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".csv",
    ".html",
    ".htm",
    ".pdf",
    ".docx",
    ".pptx",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
}
SCRIPT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".zsh",
    ".rb",
    ".go",
    ".php",
    ".mjs",
    ".cjs",
}
IGNORED_DIR_NAMES = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "coverage",
    "__pycache__",
}
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4, None: 4}


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False))
            handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_ALL,
            escapechar="\\",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def join_behaviors(value: list[str] | None) -> str:
    return ", ".join(value or [])


def sanitize_text(text: str) -> str:
    return text.replace("\x00", "")


def json_cell(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    return sanitize_text(json.dumps(value, ensure_ascii=False, sort_keys=True))


def skill_blob(row: dict[str, Any]) -> str:
    return " ".join(
        [
            str(row.get("skill_id", "")),
            str(row.get("name", "")),
            str(row.get("skill_root", "")),
        ]
    )


def mechanism_class(row: dict[str, Any]) -> str:
    return str((row.get("root_cause_v2") or {}).get("mechanism_class") or "")


def primary_driver(row: dict[str, Any]) -> str:
    return str((row.get("root_cause_v2") or {}).get("primary_driver") or "")


def evidence_status(row: dict[str, Any]) -> str:
    return str((row.get("root_cause_v2") or {}).get("evidence_status") or "")


def llm_event_count(row: dict[str, Any]) -> int:
    return int((row.get("trace_summary") or {}).get("llm_event_count") or 0)


def has_primary_chain(row: dict[str, Any]) -> bool:
    return bool(row.get("primary_chain"))


def classify_stratum(row: dict[str, Any]) -> str:
    blob = skill_blob(row)
    if NOTE_RE.search(blob):
        return "suspected_benign_fp_note_report_inventory"
    if mechanism_class(row) == "overprivileged_external_transfer" or UPLOAD_RE.search(blob):
        return "upload_or_mirror_outward"
    if row.get("risk_level") == "critical" and has_primary_chain(row):
        return "chain_backed_critical"
    if row.get("risk_level") == "low":
        return "representative_low_risk"
    if row.get("root_cause_detail") == "llm_decision_induced_action" and llm_event_count(row) >= 8 and not has_primary_chain(row):
        return "llm_decision_heavy"
    return "partial_evidence_medium"


def risk_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        RISK_ORDER.get(row.get("risk_level"), 5),
        -int(row.get("risk_score") or -1),
        str(row.get("skill_id", "")),
    )


def compute_sample_quotas(stratum_rows: dict[str, list[dict[str, Any]]], target_total: int) -> dict[str, int]:
    quotas = {
        stratum: min(BASE_SAMPLE_QUOTAS[stratum], len(stratum_rows.get(stratum, [])))
        for stratum in STRATA_ORDER
    }
    running_total = sum(quotas.values())
    if running_total >= target_total:
        return quotas
    while running_total < target_total:
        made_progress = False
        for stratum in REDISTRIBUTION_ORDER:
            capacity = len(stratum_rows.get(stratum, []))
            if quotas[stratum] >= capacity:
                continue
            quotas[stratum] += 1
            running_total += 1
            made_progress = True
            if running_total >= target_total:
                break
        if not made_progress:
            break
    return quotas


def row_has_explicit_non_llm_sink(row: dict[str, Any]) -> bool:
    for node in row.get("primary_chain") or []:
        if node.get("node_type") != "network_endpoint":
            continue
        if node.get("is_llm_provider"):
            continue
        label = node.get("sink_url") or node.get("original_url") or node.get("sink_domain") or node.get("label") or ""
        if label and label != "unknown":
            return True
    return False


def balanced_sample(rows: list[dict[str, Any]], sample_size: int, rng: random.Random, stratum: str) -> list[dict[str, Any]]:
    if sample_size >= len(rows):
        return sorted(rows, key=risk_sort_key)

    selected: list[dict[str, Any]] = []
    if stratum in {"chain_backed_critical", "upload_or_mirror_outward"}:
        priority_rows = [row for row in rows if row_has_explicit_non_llm_sink(row)]
        if priority_rows:
            if len(priority_rows) >= sample_size:
                sampled_priority = rng.sample(sorted(priority_rows, key=risk_sort_key), sample_size)
                return sorted(sampled_priority, key=risk_sort_key)
            selected.extend(sorted(priority_rows, key=risk_sort_key))

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    remaining_rows = [row for row in rows if row not in selected]
    for row in sorted(remaining_rows, key=risk_sort_key):
        grouped[str(row.get("risk_level") or "")].append(row)

    risk_levels = sorted(grouped, key=lambda level: (len(grouped[level]), RISK_ORDER.get(level, 9), level))
    remaining = sample_size - len(selected)

    for level in risk_levels:
        candidates = grouped[level]
        levels_left = len(risk_levels) - risk_levels.index(level)
        min_reserved = max(levels_left - 1, 0)
        if remaining <= min_reserved:
            continue
        take_all_threshold = remaining - min_reserved
        if len(candidates) <= take_all_threshold:
            selected.extend(candidates)
            remaining -= len(candidates)

    if remaining > 0:
        remaining_pool = [row for row in remaining_rows if row not in selected]
        sampled = rng.sample(sorted(remaining_pool, key=risk_sort_key), remaining)
        selected.extend(sampled)

    return sorted(selected, key=risk_sort_key)


def summarize_trace(trace_summary: dict[str, Any] | None) -> str:
    trace_summary = trace_summary or {}
    return (
        f"file={int(trace_summary.get('file_event_count') or 0)}, "
        f"network={int(trace_summary.get('network_event_count') or 0)}, "
        f"process={int(trace_summary.get('process_event_count') or 0)}, "
        f"tool={int(trace_summary.get('tool_call_count') or 0)}, "
        f"llm={int(trace_summary.get('llm_event_count') or 0)}"
    )


def first_chain_source_label(primary_chain: list[dict[str, Any]] | None) -> str:
    if not primary_chain:
        return ""
    return str(primary_chain[0].get("label") or "")


def sink_display_labels(primary_chain: list[dict[str, Any]] | None) -> list[str]:
    labels: list[str] = []
    for node in primary_chain or []:
        if node.get("node_type") != "network_endpoint":
            continue
        label = (
            node.get("sink_url")
            or node.get("original_url")
            or node.get("sink_display_label")
            or node.get("label")
            or node.get("sink_domain")
            or ""
        )
        if label and label not in labels:
            labels.append(str(label))
    return labels


def recursive_find_endpoint_strings(value: Any, results: set[str]) -> None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if isinstance(nested_value, str):
                if key in {"url", "endpoint", "base_url", "endpoint_host", "host"}:
                    results.add(nested_value)
                    for match in HOST_RE.findall(nested_value):
                        results.add(match)
                for match in URL_RE.findall(nested_value):
                    results.add(match)
            else:
                recursive_find_endpoint_strings(nested_value, results)
    elif isinstance(value, list):
        for item in value:
            recursive_find_endpoint_strings(item, results)
    elif isinstance(value, str):
        for match in URL_RE.findall(value):
            results.add(match)


def looks_like_endpoint(raw: str) -> bool:
    value = raw.strip()
    if not value:
        return False
    if value.startswith(("http://", "https://")):
        return True
    if "/" in value or "\\" in value:
        return False
    suffix = Path(value).suffix.lower()
    if suffix and suffix in FILE_LIKE_SUFFIXES:
        return False
    if value.count(".") < 2:
        return False
    return bool(HOST_RE.fullmatch(value))


def normalize_endpoint(raw: str) -> str:
    raw = sanitize_text(raw).strip().rstrip(".,);")
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    if raw.startswith("www."):
        return f"https://{raw}"
    return raw


def collect_external_endpoints(row: dict[str, Any], attack_chain: list[dict[str, Any]], runtime_events_path: Path) -> list[dict[str, Any]]:
    endpoint_map: dict[str, dict[str, Any]] = {}

    def record_endpoint(value: str, source: str, is_llm_provider: bool = False) -> None:
        normalized = normalize_endpoint(value)
        if not normalized or normalized == "unknown" or not looks_like_endpoint(normalized):
            return
        entry = endpoint_map.setdefault(
            normalized,
            {
                "endpoint": normalized,
                "sources": [],
                "is_llm_provider": bool(is_llm_provider),
            },
        )
        if source not in entry["sources"]:
            entry["sources"].append(source)
        entry["is_llm_provider"] = entry["is_llm_provider"] and bool(is_llm_provider)

    for node in attack_chain:
        if node.get("node_type") != "network_endpoint":
            continue
        value = (
            node.get("sink_url")
            or node.get("original_url")
            or node.get("sink_display_label")
            or node.get("label")
            or node.get("sink_domain")
            or ""
        )
        record_endpoint(str(value), "attack_chain", bool(node.get("is_llm_provider")))

    if runtime_events_path.exists():
        with runtime_events_path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                payload = event.get("payload") or {}
                found: set[str] = set()
                recursive_find_endpoint_strings(payload, found)
                if not found:
                    continue
                source = f"runtime:{event.get('category') or event.get('event') or 'event'}"
                is_llm_provider = event.get("category") == "llm"
                for value in found:
                    record_endpoint(value, source, is_llm_provider)

    return sorted(endpoint_map.values(), key=lambda item: item["endpoint"])


def parse_attribution_map(root_cause_v2: dict[str, Any]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    rationale = (root_cause_v2 or {}).get("attribution_rationale") or {}
    for bucket in rationale.values():
        if not isinstance(bucket, list):
            continue
        for item in bucket:
            if not isinstance(item, str) or "=" not in item:
                continue
            key, value = item.split("=", 1)
            parsed[key.strip()] = value.strip()
    return parsed


def excerpt_text(lines: list[str], index: int, radius: int = 2) -> tuple[int, int, str]:
    start = max(0, index - radius)
    end = min(len(lines), index + radius + 1)
    snippet = sanitize_text("\n".join(line.rstrip() for line in lines[start:end]).strip())
    return start + 1, end, snippet[:800]


def snippet_score(text: str, hints: list[str]) -> int:
    lowered = text.lower()
    return sum(1 for hint in hints if hint and hint.lower() in lowered)


def extract_relevant_snippets(path: Path, hint_tokens: list[str], max_snippets: int) -> list[dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return []
    try:
        content = sanitize_text(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return []
    lines = content.splitlines()
    scored_lines: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        score = snippet_score(line, hint_tokens)
        if score > 0:
            scored_lines.append((score, index))
    if not scored_lines:
        for index, line in enumerate(lines):
            if line.strip():
                scored_lines.append((0, index))
                break

    snippets: list[dict[str, Any]] = []
    used_ranges: list[tuple[int, int]] = []
    for _, index in sorted(scored_lines, key=lambda item: (-item[0], item[1])):
        start_line, end_line, text = excerpt_text(lines, index)
        overlaps = any(not (end_line < other_start or start_line > other_end) for other_start, other_end in used_ranges)
        if overlaps or not text:
            continue
        used_ranges.append((start_line, end_line))
        snippets.append(
            {
                "path": str(path),
                "line_start": start_line,
                "line_end": end_line,
                "text": text,
            }
        )
        if len(snippets) >= max_snippets:
            break
    return snippets


def discover_script_files(skill_root: Path) -> list[Path]:
    scripts_dir = skill_root / "scripts"
    if not scripts_dir.exists() or not scripts_dir.is_dir():
        return []
    files: list[Path] = []
    for path in sorted(scripts_dir.rglob("*")):
        if any(part in IGNORED_DIR_NAMES for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in SCRIPT_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > 250_000:
                continue
        except OSError:
            continue
        files.append(path)
    return files


def collect_snippets(
    skill_root: Path,
    row: dict[str, Any],
    stratum: str,
    endpoints: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    endpoint_tokens: list[str] = []
    for endpoint in endpoints:
        value = endpoint["endpoint"]
        endpoint_tokens.append(value)
        for match in HOST_RE.findall(value):
            endpoint_tokens.append(match)

    hint_tokens = [
        str(row.get("name") or ""),
        str(row.get("skill_id") or ""),
        stratum,
        mechanism_class(row),
        primary_driver(row),
        join_behaviors(row.get("detected_behaviors")),
        "note",
        "report",
        "inventory",
        "upload",
        "mirror",
        "webhook",
        "relay",
        "share",
        "http",
        "api",
        "token",
        "agent",
        "session",
        "sandbox",
    ]
    hint_tokens.extend(endpoint_tokens)
    hint_tokens = [token for token in hint_tokens if token]

    snippets: dict[str, list[dict[str, Any]]] = {
        "skill_md": extract_relevant_snippets(skill_root / "SKILL.md", hint_tokens, max_snippets=2),
        "readme": [],
        "scripts": [],
    }

    for candidate in ["README.md", "README", "readme.md", "Readme.md"]:
        readme_path = skill_root / candidate
        if readme_path.exists():
            snippets["readme"] = extract_relevant_snippets(readme_path, hint_tokens, max_snippets=2)
            if snippets["readme"]:
                break

    script_files = discover_script_files(skill_root)
    script_scores: list[tuple[int, Path]] = []
    for path in script_files:
        try:
            content = sanitize_text(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        script_scores.append((snippet_score(content, hint_tokens), path))

    for _, path in sorted(script_scores, key=lambda item: (-item[0], str(item[1]))):
        extracted = extract_relevant_snippets(path, hint_tokens, max_snippets=1)
        if not extracted:
            continue
        snippets["scripts"].extend(extracted)
        if len(snippets["scripts"]) >= 2:
            break

    return snippets


def snippet_digest(snippets: dict[str, list[dict[str, Any]]]) -> str:
    parts: list[str] = []
    for bucket in ["skill_md", "readme", "scripts"]:
        for snippet in snippets.get(bucket, []):
            rel_path = snippet["path"]
            text = " ".join(snippet["text"].split())
            parts.append(f"{Path(rel_path).name}:{snippet['line_start']}-{snippet['line_end']} {text[:180]}")
    return " | ".join(parts)


def assess_chain_validity(row: dict[str, Any], attack_chain: list[dict[str, Any]]) -> str:
    if not attack_chain:
        return "unknown"

    source_label = first_chain_source_label(attack_chain)
    has_unknown_sink = any((node.get("label") or "") == "unknown" for node in attack_chain if node.get("node_type") == "network_endpoint")
    has_non_llm_sink = any(
        node.get("node_type") == "network_endpoint"
        and not bool(node.get("is_llm_provider"))
        and (node.get("sink_url") or node.get("original_url") or node.get("sink_domain") or node.get("label"))
        and (node.get("label") or "") != "unknown"
        for node in attack_chain
    )
    source_is_generated = source_label.startswith("runtime_output/") or source_label.startswith("public/") or "/runtime_output/" in source_label

    if source_is_generated and has_unknown_sink:
        return "false"
    if has_non_llm_sink and not source_is_generated:
        return "true"
    if has_unknown_sink:
        return "unknown"
    if has_non_llm_sink:
        return "unknown"
    return "false"


def infer_gt_root_cause(row: dict[str, Any], stratum: str) -> str:
    mechanism = mechanism_class(row)
    mapping = {
        "unsafe_dataflow_design": "unsafe dataflow design from local inputs toward an external sink",
        "unsafe_command_construction": "unsafe command construction or tool selection around externalized actions",
        "ambiguous_connected_workflow": "ambiguous connected workflow with incomplete source/sink attribution",
        "overprivileged_external_transfer": "outward transfer or mirroring workflow with broader-than-needed privileges",
    }
    if mechanism in mapping:
        return mapping[mechanism]
    if stratum == "suspected_benign_fp_note_report_inventory":
        return "note/report/inventory style workflow likely over-interpreted by machine labeling"
    if stratum == "representative_low_risk":
        return "low-risk workflow with weak evidence of harmful transfer"
    return str(row.get("root_cause_detail") or row.get("root_cause") or "underspecified root cause")


def infer_gt_behavior(row: dict[str, Any], stratum: str, endpoints: list[dict[str, Any]], chain_validity: str) -> str:
    endpoint_labels = [item["endpoint"] for item in endpoints if not item.get("is_llm_provider")]
    if stratum == "suspected_benign_fp_note_report_inventory":
        return "note/report/inventory generation with incidental networked tooling"
    if stratum == "upload_or_mirror_outward":
        if endpoint_labels:
            return f"upload or mirror style outward transfer toward {endpoint_labels[0]}"
        return "upload or mirror style outward transfer workflow"
    if stratum == "chain_backed_critical":
        if endpoint_labels:
            return f"source-to-sink transfer from local material toward {endpoint_labels[0]}"
        return "chain-backed source-to-sink transfer toward an external endpoint"
    if stratum == "llm_decision_heavy":
        return "LLM-driven tool-selection workflow without a resolved non-LLM sink"
    if stratum == "representative_low_risk":
        return "low-risk documentation or helper workflow"
    if "process_spawn" in (row.get("detected_behaviors") or []):
        return "partial-evidence process or shell workflow with unresolved external effect"
    if chain_validity == "unknown":
        return "partial-evidence networked workflow with unresolved source/sink"
    return "partial-evidence network access"


def infer_gt_label(
    row: dict[str, Any],
    stratum: str,
    attack_chain: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    snippets: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    chain_validity = assess_chain_validity(row, attack_chain)
    attribution = parse_attribution_map(row.get("root_cause_v2") or {})
    source_sensitivity = attribution.get("source_sensitivity", "")
    endpoint_labels = [item["endpoint"] for item in endpoints if not item.get("is_llm_provider")]
    gt_root_cause = infer_gt_root_cause(row, stratum)
    gt_behavior = infer_gt_behavior(row, stratum, endpoints, chain_validity)

    gt_risk = "ambiguous"
    confidence = "low"

    if stratum == "representative_low_risk":
        gt_risk = "benign"
        confidence = "high"
    elif stratum == "suspected_benign_fp_note_report_inventory":
        gt_risk = "benign" if chain_validity in {"false", "unknown"} else "ambiguous"
        confidence = "medium" if chain_validity != "true" else "low"
    elif stratum == "upload_or_mirror_outward":
        if chain_validity == "true" and endpoint_labels:
            gt_risk = "malicious"
            confidence = "high" if source_sensitivity == "HIGH_SENSITIVITY" else "medium"
        else:
            gt_risk = "ambiguous"
            confidence = "medium"
    elif stratum == "chain_backed_critical":
        if chain_validity == "true" and endpoint_labels:
            gt_risk = "malicious"
            confidence = "high" if source_sensitivity == "HIGH_SENSITIVITY" else "medium"
        else:
            gt_risk = "ambiguous"
            confidence = "medium"
    elif stratum == "llm_decision_heavy":
        gt_risk = "ambiguous"
        confidence = "low"
    elif stratum == "partial_evidence_medium":
        if row.get("risk_level") == "high" and "process_spawn" in (row.get("detected_behaviors") or []):
            gt_risk = "ambiguous"
            confidence = "medium"
        elif len(endpoints) <= 1 and join_behaviors(row.get("detected_behaviors")) == "network_access":
            gt_risk = "benign"
            confidence = "low"
        else:
            gt_risk = "ambiguous"
            confidence = "low"

    evidence_parts: list[str] = []
    evidence_parts.append(
        f"Trace counts: {summarize_trace(row.get('trace_summary'))}; detected behaviors: {join_behaviors(row.get('detected_behaviors')) or 'none'}."
    )
    if attack_chain:
        evidence_parts.append(
            f"Primary chain length {len(attack_chain)} from `{first_chain_source_label(attack_chain) or 'unknown source'}` to `{(sink_display_labels(attack_chain) or ['unknown sink'])[0]}`."
        )
    else:
        evidence_parts.append("No resolved primary chain is present in the run artifacts.")
    if endpoint_labels:
        evidence_parts.append(f"Non-LLM endpoint evidence: {', '.join(endpoint_labels[:3])}.")
    elif endpoints:
        evidence_parts.append("Only LLM-provider or unresolved endpoint evidence was recovered from the trace.")
    digest = snippet_digest(snippets)
    if digest:
        evidence_parts.append(f"Relevant local snippets: {digest[:420]}.")
    evidence_parts.append("This label is machine-assisted only and must remain pending until `human_decision` is filled.")

    return {
        "gt_risk": gt_risk,
        "gt_behavior": gt_behavior,
        "gt_chain_valid": chain_validity,
        "gt_root_cause": gt_root_cause,
        "confidence": confidence,
        "evidence_summary": " ".join(evidence_parts),
        "needs_human_review": True,
        "machine_assisted_status": "machine-assisted-pending-human-review",
    }


def enrich_sample_case(sample_id: str, row: dict[str, Any], stratum: str, seed: int) -> dict[str, Any]:
    skill_root = Path(str(row.get("skill_root") or ""))
    artifact_dir = Path(str(row.get("execution_artifact_dir") or ""))
    attack_chain = load_json(artifact_dir / "attack-chain.json", default=[]) or []
    runtime_events_path = artifact_dir / "runtime-events.jsonl"
    endpoints = collect_external_endpoints(row, attack_chain, runtime_events_path)
    snippets = collect_snippets(skill_root, row, stratum, endpoints)
    machine_label = infer_gt_label(row, stratum, attack_chain, endpoints, snippets)

    enriched = {
        "sample_id": sample_id,
        "sampling_seed": seed,
        "stratum": stratum,
        "skill_id": str(row.get("skill_id") or ""),
        "skill_root": str(row.get("skill_root") or ""),
        "name": str(row.get("name") or ""),
        "risk_level": str(row.get("risk_level") or ""),
        "risk_score": row.get("risk_score"),
        "detected_behaviors": row.get("detected_behaviors") or [],
        "primary_chain": attack_chain,
        "primary_chain_length": len(attack_chain),
        "root_cause": str(row.get("root_cause") or ""),
        "root_cause_detail": str(row.get("root_cause_detail") or ""),
        "mechanism_class": mechanism_class(row),
        "primary_driver": primary_driver(row),
        "evidence_status": evidence_status(row),
        "trace_summary": row.get("trace_summary") or {},
        "trace_overview": summarize_trace(row.get("trace_summary")),
        "external_endpoints": endpoints,
        "execution_artifact_dir": str(artifact_dir),
        "relevant_snippets": snippets,
        "snippet_digest": snippet_digest(snippets),
    }
    enriched.update(machine_label)
    return enriched


def build_rows_for_csv(enriched_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    manifest_rows: list[dict[str, Any]] = []
    review_rows: list[dict[str, Any]] = []
    for row in enriched_rows:
        base = {
            "sample_id": row["sample_id"],
            "stratum": row["stratum"],
            "skill_id": row["skill_id"],
            "name": row["name"],
            "skill_root": row["skill_root"],
            "risk_level": row["risk_level"],
            "risk_score": row["risk_score"],
            "detected_behaviors": join_behaviors(row["detected_behaviors"]),
            "primary_chain_length": row["primary_chain_length"],
            "primary_chain": json_cell(row["primary_chain"]),
            "root_cause": row["root_cause"],
            "root_cause_detail": row["root_cause_detail"],
            "mechanism_class": row["mechanism_class"],
            "primary_driver": row["primary_driver"],
            "evidence_status": row["evidence_status"],
            "trace_overview": row["trace_overview"],
            "trace_summary": json_cell(row["trace_summary"]),
            "external_endpoints": json_cell(row["external_endpoints"]),
            "execution_artifact_dir": row["execution_artifact_dir"],
            "snippet_digest": row["snippet_digest"],
            "snippet_refs": json_cell(
                [
                    {
                        "path": snippet["path"],
                        "line_start": snippet["line_start"],
                        "line_end": snippet["line_end"],
                    }
                    for bucket in row["relevant_snippets"].values()
                    for snippet in bucket
                ]
            ),
            "sampling_seed": row["sampling_seed"],
        }
        manifest_rows.append(dict(base))
        review_row = dict(base)
        review_row.update(
            {
                "machine_gt_risk": row["gt_risk"],
                "machine_gt_behavior": row["gt_behavior"],
                "machine_gt_chain_valid": row["gt_chain_valid"],
                "machine_gt_root_cause": row["gt_root_cause"],
                "machine_confidence": row["confidence"],
                "evidence_summary": row["evidence_summary"],
                "needs_human_review": row["needs_human_review"],
                "machine_assisted_status": row["machine_assisted_status"],
                "human_decision": "",
                "human_gt_behavior": "",
                "human_gt_chain_valid": "",
                "human_gt_root_cause": "",
                "human_notes": "",
                "reviewer": "",
                "review_status": "pending",
            }
        )
        review_rows.append(review_row)
    return manifest_rows, review_rows


def write_readme(
    output_dir: Path,
    summary: dict[str, Any],
    corpus_counts: dict[str, int],
    sample_counts: dict[str, int],
    gt_distribution: Counter,
    confidence_distribution: Counter,
    chain_distribution: Counter,
    seed: int,
) -> None:
    readme = "\n".join(
        [
            "# Real-World Sampled GT Audit",
            "",
            "This directory contains a deterministic, machine-assisted ground-truth audit pack for the completed real-world rerun in `/mnt/e/log7`.",
            "",
            "## Scope",
            "",
            f"- Source rerun: `/mnt/e/log7`",
            f"- Completed execution boundary: `{summary['completed']}` completed runs out of `{summary['scheduled']}` scheduled runs",
            f"- Fixed sampling seed: `{seed}`",
            f"- Target sample size: `{summary['target_sample_size']}`",
            f"- Actual sampled size: `{summary['sampled_cases']}`",
            "",
            "Only completed executions are in scope for this audit pack. Skipped cases remain out of scope because they were not exercised end-to-end under the rerun environment.",
            "",
            "## Strata",
            "",
            "Every completed case is assigned to exactly one stratum using a documented precedence order:",
            "",
            "1. `suspected_benign_fp_note_report_inventory`",
            "2. `upload_or_mirror_outward`",
            "3. `chain_backed_critical`",
            "4. `representative_low_risk`",
            "5. `llm_decision_heavy`",
            "6. `partial_evidence_medium`",
            "",
            "The note/report/inventory bucket is evaluated before the outward-transfer bucket because the audit is meant to explicitly stress-test likely benign false-positive clusters. The outward-transfer bucket is evaluated before chain-backed critical cases so explicit transfer semantics are preserved as their own review stratum.",
            "",
            "## Files",
            "",
            "- `sample_manifest.csv`: one row per sampled case with detector outputs, trace summaries, endpoint summaries, and snippet references.",
            "- `initial_gt_labels.jsonl`: machine-assisted provisional labels plus supporting evidence for each sampled case.",
            "- `human_review_sheet.csv`: review sheet with machine-assisted fields and blank human annotation columns.",
            "- `summary_tables.md`: corpus counts, stratum counts, and provisional label distributions.",
            "",
            "## Labeling Protocol",
            "",
            "- `gt_risk` is limited to `malicious`, `benign`, or `ambiguous`.",
            "- `gt_chain_valid` is limited to `true`, `false`, or `unknown`.",
            "- Every exported label is machine-assisted and provisional.",
            "- `needs_human_review` is always `true` until a reviewer fills `human_decision`.",
            "- No precision, recall, or accuracy claims should be computed from this directory until human review is complete.",
            "",
            "Suggested review order:",
            "",
            "1. Confirm the sampled skill root and execution artifact directory are readable.",
            "2. Check `primary_chain`, `external_endpoints`, and `trace_summary` before reading the local snippets.",
            "3. Compare the machine-assisted label against the run evidence and the local skill text.",
            "4. Fill `human_decision`, `human_gt_behavior`, `human_gt_chain_valid`, `human_gt_root_cause`, and `human_notes` in `human_review_sheet.csv`.",
            "",
            "## Paper-Ready Framing",
            "",
            f"The `/mnt/e/log7` rerun covers `{summary['scheduled']}` scheduled skills, of which `{summary['completed']}` completed and `{summary['skipped']}` were skipped. This audit pack should therefore be described as a sampled manual-audit set over the completed execution boundary, not as a full real-world correctness benchmark.",
            "",
            f"We deterministically sampled `{summary['sampled_cases']}` completed cases across six predefined strata to create a lightweight manual-audit layer that is reproducible, inspectable, and suitable for error analysis. The machine-assisted labels exported here are provisional only: they organize reviewer effort, but they are not gold labels and they do not justify end-to-end accuracy claims before human decisions are recorded.",
            "",
            "## Snapshot",
            "",
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Completed runs | {summary['completed']} |",
            f"| Sampled runs | {summary['sampled_cases']} |",
            f"| Machine-assisted `malicious` | {gt_distribution.get('malicious', 0)} |",
            f"| Machine-assisted `benign` | {gt_distribution.get('benign', 0)} |",
            f"| Machine-assisted `ambiguous` | {gt_distribution.get('ambiguous', 0)} |",
            f"| High confidence | {confidence_distribution.get('high', 0)} |",
            f"| Medium confidence | {confidence_distribution.get('medium', 0)} |",
            f"| Low confidence | {confidence_distribution.get('low', 0)} |",
            f"| `gt_chain_valid=true` | {chain_distribution.get('true', 0)} |",
            f"| `gt_chain_valid=false` | {chain_distribution.get('false', 0)} |",
            f"| `gt_chain_valid=unknown` | {chain_distribution.get('unknown', 0)} |",
        ]
    )
    (output_dir / "README.md").write_text(readme, encoding="utf-8")


def write_summary_tables(
    output_dir: Path,
    summary: dict[str, Any],
    corpus_counts: dict[str, int],
    sample_counts: dict[str, int],
    gt_distribution: Counter,
    confidence_distribution: Counter,
    chain_distribution: Counter,
    mechanism_distribution: Counter,
    sampled_endpoint_counts: Counter,
) -> None:
    lines = [
        "# Real-World GT Audit Summary Tables",
        "",
        "All figures below are code-generated from `/mnt/e/log7` plus the deterministic sampled audit set. These are descriptive counts only. They are not accuracy, precision, or recall claims.",
        "",
        "## Corpus Boundary",
        "",
        "| Field | Value |",
        "| --- | ---: |",
        f"| Scheduled executions | {summary['scheduled']} |",
        f"| Completed executions | {summary['completed']} |",
        f"| Skipped executions | {summary['skipped']} |",
        f"| Failed executions | {summary['failed']} |",
        f"| Target sample size | {summary['target_sample_size']} |",
        f"| Actual sampled cases | {summary['sampled_cases']} |",
        "",
        "## Completed Cases by Stratum",
        "",
        "| Stratum | Completed Cases | Sampled Cases |",
        "| --- | ---: | ---: |",
    ]
    for stratum in STRATA_ORDER:
        lines.append(f"| `{stratum}` | {corpus_counts.get(stratum, 0)} | {sample_counts.get(stratum, 0)} |")

    lines.extend(
        [
            "",
            "## Provisional Machine-Assisted Label Distribution",
            "",
            "| Label | Count |",
            "| --- | ---: |",
            f"| `malicious` | {gt_distribution.get('malicious', 0)} |",
            f"| `benign` | {gt_distribution.get('benign', 0)} |",
            f"| `ambiguous` | {gt_distribution.get('ambiguous', 0)} |",
            "",
            "## Provisional Chain-Validity Distribution",
            "",
            "| `gt_chain_valid` | Count |",
            "| --- | ---: |",
            f"| `true` | {chain_distribution.get('true', 0)} |",
            f"| `false` | {chain_distribution.get('false', 0)} |",
            f"| `unknown` | {chain_distribution.get('unknown', 0)} |",
            "",
            "## Confidence Distribution",
            "",
            "| Confidence | Count |",
            "| --- | ---: |",
            f"| `high` | {confidence_distribution.get('high', 0)} |",
            f"| `medium` | {confidence_distribution.get('medium', 0)} |",
            f"| `low` | {confidence_distribution.get('low', 0)} |",
            "",
            "## Sampled Mechanism-Class Distribution",
            "",
            "| Mechanism Class | Count |",
            "| --- | ---: |",
        ]
    )
    for mechanism, count in mechanism_distribution.most_common():
        lines.append(f"| `{mechanism}` | {count} |")

    lines.extend(
        [
            "",
            "## Endpoint Evidence in Sampled Cases",
            "",
            "| Endpoint Bucket | Count |",
            "| --- | ---: |",
            f"| Cases with any endpoint evidence | {sampled_endpoint_counts.get('any', 0)} |",
            f"| Cases with non-LLM endpoint evidence | {sampled_endpoint_counts.get('non_llm', 0)} |",
            f"| Cases with only LLM-provider or unresolved endpoint evidence | {sampled_endpoint_counts.get('llm_only_or_none', 0)} |",
            "",
            "## Paper-Ready Note",
            "",
            "This table set describes a sampled manual-audit layer over the completed `/mnt/e/log7` executions. It should be cited as a reproducible completed-subset audit pack, not as a full real-world correctness benchmark.",
        ]
    )
    (output_dir / "summary_tables.md").write_text("\n".join(lines), encoding="utf-8")


def build_audit(log_dir: Path, output_dir: Path, seed: int, target_total: int) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    progress = load_json(log_dir / "progress.json", default={}) or {}
    results = load_jsonl(log_dir / "results.jsonl")
    completed = [row for row in results if row.get("status") == "completed"]

    strata_rows: dict[str, list[dict[str, Any]]] = {stratum: [] for stratum in STRATA_ORDER}
    for row in completed:
        strata_rows[classify_stratum(row)].append(row)
    for stratum in STRATA_ORDER:
        strata_rows[stratum] = sorted(strata_rows[stratum], key=risk_sort_key)

    quotas = compute_sample_quotas(strata_rows, target_total=target_total)
    rng = random.Random(seed)

    sampled_rows: list[dict[str, Any]] = []
    sample_counts: dict[str, int] = {}
    for stratum in STRATA_ORDER:
        picked = balanced_sample(strata_rows[stratum], quotas[stratum], rng, stratum)
        sample_counts[stratum] = len(picked)
        sampled_rows.extend({"stratum": stratum, "row": row} for row in picked)

    enriched_rows: list[dict[str, Any]] = []
    for index, item in enumerate(sampled_rows, start=1):
        sample_id = f"RW-AUDIT-{index:03d}"
        enriched_rows.append(enrich_sample_case(sample_id, item["row"], item["stratum"], seed))

    manifest_rows, review_rows = build_rows_for_csv(enriched_rows)

    write_csv(
        output_dir / "sample_manifest.csv",
        manifest_rows,
        [
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
            "sampling_seed",
        ],
    )

    write_jsonl(output_dir / "initial_gt_labels.jsonl", enriched_rows)

    write_csv(
        output_dir / "human_review_sheet.csv",
        review_rows,
        [
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
        ],
    )

    corpus_counts = {stratum: len(rows) for stratum, rows in strata_rows.items()}
    gt_distribution = Counter(row["gt_risk"] for row in enriched_rows)
    confidence_distribution = Counter(row["confidence"] for row in enriched_rows)
    chain_distribution = Counter(row["gt_chain_valid"] for row in enriched_rows)
    mechanism_distribution = Counter(row["mechanism_class"] for row in enriched_rows)
    endpoint_distribution = Counter()
    for row in enriched_rows:
        if row["external_endpoints"]:
            endpoint_distribution["any"] += 1
            if any(not endpoint.get("is_llm_provider") for endpoint in row["external_endpoints"]):
                endpoint_distribution["non_llm"] += 1
            else:
                endpoint_distribution["llm_only_or_none"] += 1
        else:
            endpoint_distribution["llm_only_or_none"] += 1

    summary = {
        "seed": seed,
        "target_sample_size": target_total,
        "scheduled": int((progress.get("totals") or {}).get("discovered") or len(results)),
        "completed": len(completed),
        "skipped": int((progress.get("totals") or {}).get("skipped") or 0),
        "failed": int((progress.get("totals") or {}).get("failed") or 0),
        "sampled_cases": len(enriched_rows),
    }

    write_readme(
        output_dir=output_dir,
        summary=summary,
        corpus_counts=corpus_counts,
        sample_counts=sample_counts,
        gt_distribution=gt_distribution,
        confidence_distribution=confidence_distribution,
        chain_distribution=chain_distribution,
        seed=seed,
    )
    write_summary_tables(
        output_dir=output_dir,
        summary=summary,
        corpus_counts=corpus_counts,
        sample_counts=sample_counts,
        gt_distribution=gt_distribution,
        confidence_distribution=confidence_distribution,
        chain_distribution=chain_distribution,
        mechanism_distribution=mechanism_distribution,
        sampled_endpoint_counts=endpoint_distribution,
    )

    return {
        "summary": summary,
        "corpus_counts": corpus_counts,
        "sample_counts": sample_counts,
        "gt_distribution": dict(gt_distribution),
        "confidence_distribution": dict(confidence_distribution),
        "chain_distribution": dict(chain_distribution),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a deterministic real-world sampled GT audit pack from /mnt/e/log7.")
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR, help="Path to the rerun log directory.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Directory to write audit artifacts.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Fixed sampling seed.")
    parser.add_argument("--target-total", type=int, default=TARGET_SAMPLE_SIZE, help="Target number of sampled cases.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = build_audit(
        log_dir=args.log_dir,
        output_dir=args.output_dir,
        seed=args.seed,
        target_total=args.target_total,
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
