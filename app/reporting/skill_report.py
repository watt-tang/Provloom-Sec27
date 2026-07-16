from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


MISSING = "not available"
RISK_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "warning": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
    "safe": 5,
    "unknown": 6,
}
MISSING_FIELD_ORDER = [
    "evidence_type",
    "primary_chain",
    "observed_runtime_chain",
    "instruction_derived_chain",
    "runtime_events",
    "instruction_evidence",
    "findings",
    "behaviors",
    "files",
    "recommendations",
]


def generate_report_file(input_path: str | Path, output_path: str | Path | None = None) -> Path:
    src = Path(input_path)
    dst = Path(output_path) if output_path is not None else src.with_suffix(".md")
    data = json.loads(src.read_text(encoding="utf-8"))
    dst.write_text(generate_markdown(data), encoding="utf-8")
    return dst


def generate_markdown(data: Any) -> str:
    if not isinstance(data, dict):
        data = {}
    ctx = _build_context(data)
    lines: list[str] = ["# Single-Skill Evidence Explanation Report", ""]
    lines.extend(_executive_verdict(ctx))
    lines.extend(_why_flagged(ctx))
    lines.extend(_evidence_type_classification(ctx))
    lines.extend(_primary_chain_explanation(ctx))
    lines.extend(_runtime_observed_evidence(ctx))
    lines.extend(_instruction_derived_evidence(ctx))
    lines.extend(_weak_indicators(ctx))
    lines.extend(_root_cause(ctx))
    lines.extend(_risk_findings(ctx))
    lines.extend(_behavior_tags(ctx))
    lines.extend(_file_level_evidence(ctx))
    lines.extend(_errors_and_skipped(ctx))
    lines.extend(_recommendations(ctx))
    lines.extend(_missing_evidence_fields(ctx))
    lines.extend(_human_reviewer_checklist())
    lines.extend(_machine_readable_summary(ctx))
    lines.extend(_reproducibility_statement())
    return "\n".join(lines).rstrip() + "\n"


def _build_context(data: dict[str, Any]) -> dict[str, Any]:
    primary = _chain_info(data.get("primary_chain"), "source_relay_sink", "primary_chain")
    runtime = _chain_info(data.get("observed_runtime_chain"), "source_relay_sink", "observed_runtime_chain")
    instruction = _instruction_context(data)
    runtime_for_report = runtime
    selected = primary if primary["provided"] else runtime if runtime["provided"] else instruction if instruction["provided"] else None
    original_evidence = _first_raw(data, "evidence_type", "chain_evidence_type")
    derived_evidence, evidence_source = _derive_evidence_type(data, original_evidence)
    if derived_evidence in {"observed_runtime", "hybrid"} and primary["provided"]:
        runtime_for_report = primary
    final_risk_raw = _final_risk_raw(data)
    final_risk = _string_or_missing(final_risk_raw)
    closed_chain = _closed_chain(data, primary, runtime, instruction)
    return {
        "data": data,
        "primary": primary,
        "runtime": runtime,
        "runtime_for_report": runtime_for_report,
        "instruction": instruction,
        "selected_chain": selected,
        "closed_chain": closed_chain,
        "final_risk": final_risk,
        "final_risk_raw": final_risk_raw,
        "evidence_type": _string_or_missing(original_evidence),
        "derived_evidence_type": derived_evidence,
        "evidence_type_source": evidence_source,
        "root_cause": _root_cause_value(data),
        "reviewer_action": _reviewer_action(final_risk_raw, closed_chain),
        "missing_fields": _missing_fields(data),
    }


def _executive_verdict(ctx: dict[str, Any]) -> list[str]:
    data = ctx["data"]
    rows = [
        ("Skill ID", _first(data, "skill_id", "id")),
        ("Skill Name", _first(data, "skill_name", "name")),
        ("Skill Path", _first(data, "skill_path")),
        ("Repository", _first(data, "repository", "repo")),
        ("Scan Status", _first(data, "status")),
        ("Scan Time", _first(data, "scan_time", "timestamp")),
        ("Scanner Version", _first(data, "scanner_version")),
        ("Rule Version", _first(data, "rule_version")),
        ("Final Risk", ctx["final_risk"]),
        ("Evidence Type", ctx["evidence_type"]),
        ("Root Cause", ctx["root_cause"]),
        ("Closed Chain", _bool_text(ctx["closed_chain"])),
        ("Reviewer Action", ctx["reviewer_action"]),
    ]
    lines = ["## 1. Executive Verdict", "", "| Item | Value |", "|---|---|"]
    lines.extend(f"| {item} | {_escape_table(value)} |" for item, value in rows)
    lines.append("")
    return lines


def _why_flagged(ctx: dict[str, Any]) -> list[str]:
    lines = [
        "## 2. Why This Skill Was Flagged",
        "",
        f"The scan verdict for this Skill is **{ctx['final_risk']}**.",
        f"The primary evidence type is **{ctx['derived_evidence_type']}**.",
        f"The root-cause category is **{ctx['root_cause']}**.",
        f"The scan result **{'contains' if ctx['closed_chain'] else 'does not contain'}** a closed evidence chain.",
        "",
    ]
    if ctx["primary"]["provided"]:
        lines.extend(["The primary evidence chain is:", ""])
        lines.extend(_inline_chain_block(ctx["primary"]))
    elif ctx["runtime"]["provided"]:
        lines.extend(
            [
                "The JSON result does not provide primary_chain, but it provides observed_runtime_chain. This report displays it as a runtime-observed candidate chain.",
                "",
            ]
        )
    elif ctx["instruction"]["provided"]:
        instruction_field = ctx["instruction"]["field"]
        lines.extend(
            [
                f"The JSON result does not provide primary_chain, but it provides {instruction_field}. This report displays it as an instruction-derived candidate chain.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "The JSON result does not provide primary_chain, observed_runtime_chain, or instruction_derived_chain. Therefore, the current verdict lacks closed-chain support and should be treated as a weak-indicator-based result or a result requiring review.",
                "",
            ]
        )
    return lines


def _evidence_type_classification(ctx: dict[str, Any]) -> list[str]:
    lines = [
        "## 3. Evidence-Type Classification",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Original evidence_type | {_escape_table(ctx['evidence_type'])} |",
        f"| Derived evidence_type | {_escape_table(ctx['derived_evidence_type'])} |",
        f"| Evidence type source | {ctx['evidence_type_source']} |",
        "",
        "| Evidence Type | Explanation |",
        "| --- | --- |",
        "| observed_runtime | The risk path is supported by runtime-observed events, indicating that a source-relay-sink path was observed during bounded execution. |",
        "| instruction_derived | The risk path comes from local Skill documentation, configuration, or scripts. It represents latent setup or maintenance risk and is not equivalent to a runtime attack. |",
        "| hybrid | Both a runtime-observed chain and an instruction-derived chain are present. |",
        "| no_closed_chain | Only weak indicators or incomplete evidence are present; no closed chain was recovered. |",
        "| missing | The JSON result does not provide evidence_type; manual review is required. |",
        "",
        "Note: Derived values are marked as derived_from_json_structure and must not be presented as original scanner output.",
        "",
    ]
    return lines


def _primary_chain_explanation(ctx: dict[str, Any]) -> list[str]:
    chain = ctx["selected_chain"]
    lines = ["## 4. Primary Chain Explanation", ""]
    if chain is None:
        lines.extend(["No primary or candidate chain was provided in the JSON result.", ""])
        return lines
    if chain["field"] != "primary_chain":
        lines.extend([f"Chain Field: {chain['field']} (candidate chain)", ""])
    else:
        lines.extend(["Chain Field: primary_chain", ""])
    lines.extend(["### 4.1 Chain Diagram", ""])
    lines.extend(_diagram_block(chain))
    lines.extend(["### 4.2 Chain Components", ""])
    lines.extend(["| Role | Value | Derived Type | Evidence Field |", "| --- | --- | --- | --- |"])
    roles = _role_labels(chain)
    for role_label, key in roles:
        value = chain["values"].get(key)
        lines.append(
            f"| {role_label} | {_escape_table(_string_or_missing(value))} | {_derive_component_type(value)} | {chain['field']}.{key} |"
        )
    lines.extend(["", "### 4.3 Chain Validity Check", ""])
    lines.extend(_chain_validity_table(chain, ctx))
    return lines


def _runtime_observed_evidence(ctx: dict[str, Any]) -> list[str]:
    data = ctx["data"]
    runtime_chain = ctx["runtime_for_report"]
    has_runtime = runtime_chain["provided"] or _has_content(data.get("runtime_events"))
    lines = ["## 5. Runtime-Observed Evidence", ""]
    if not has_runtime:
        lines.extend(["No runtime-observed evidence was provided in the JSON result.", ""])
        return lines
    lines.extend(["### 5.1 Observed Runtime Chain", ""])
    if runtime_chain["provided"]:
        if runtime_chain["field"] == "primary_chain" and ctx["derived_evidence_type"] in {"observed_runtime", "hybrid"}:
            lines.extend(["Runtime chain source: primary_chain", ""])
        lines.extend(_inline_chain_block(runtime_chain))
    else:
        lines.extend(["No observed_runtime_chain was provided.", ""])
    lines.extend(["### 5.2 Runtime Event Table", ""])
    events = _as_list(data.get("runtime_events"))
    if events:
        lines.extend(["| Index | Event Type | Actor | Action | Object | Target | Timestamp | Raw Evidence |", "| ----: | --- | --- | --- | --- | --- | --- | --- |"])
        for index, event in enumerate(sorted(events, key=_runtime_event_sort_key), 1):
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(index),
                        _escape_table(_first_in(event, "event_type", "type")),
                        _escape_table(_first_in(event, "actor", "process", "tool", "caller")),
                        _escape_table(_first_in(event, "action", "op", "operation")),
                        _escape_table(_first_in(event, "object", "source", "file")),
                        _escape_table(_first_in(event, "target", "sink", "destination", "url")),
                        _escape_table(_first_in(event, "timestamp", "time")),
                        _escape_table(_first_in(event, "raw", "evidence", "detail")),
                    ]
                )
                + " |"
            )
        lines.append("")
    else:
        lines.extend(["No runtime_events were provided.", ""])
    lines.extend(
        [
            "### 5.3 Runtime Evidence Boundary",
            "",
            "This section only represents runtime-observed evidence recorded in the JSON result. The report generator does not infer events absent from the JSON and does not complete missing events as attack behavior. A chain should be treated as runtime-observed only when the JSON contains a closed runtime source-relay-sink path.",
            "",
        ]
    )
    return lines


def _instruction_derived_evidence(ctx: dict[str, Any]) -> list[str]:
    data = ctx["data"]
    has_instruction = ctx["instruction"]["provided"] or _has_content(data.get("instruction_evidence")) or _has_content(data.get("instruction_chain"))
    lines = ["## 6. Instruction-Derived Evidence", ""]
    if not has_instruction:
        lines.extend(["No instruction-derived evidence was provided in the JSON result.", ""])
        return lines
    lines.extend(["### 6.1 Latent Instruction Chain", ""])
    if ctx["instruction"]["provided"]:
        lines.extend(_inline_chain_block(ctx["instruction"]))
    else:
        lines.extend(["No instruction_derived_chain was provided.", ""])
    if _has_content(data.get("instruction_chain")):
        lines.extend(["Instruction Chain Steps:", ""])
        lines.extend(
            [
                "| Index | Source | Action | Target | Evidence Source | Evidence Type | Observed At Runtime | Confidence | Raw Snippet |",
                "| ----: | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for index, step in enumerate(_as_list(data.get("instruction_chain")), 1):
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(index),
                        _escape_table(_first_in(step, "source")),
                        _escape_table(_first_in(step, "action")),
                        _escape_table(_first_in(step, "target")),
                        _escape_table(_first_in(step, "evidence_source")),
                        _escape_table(_first_in(step, "evidence_type")),
                        _escape_table(_first_in(step, "observed_at_runtime")),
                        _escape_table(_first_in(step, "confidence")),
                        _escape_table(_first_in(step, "raw_snippet")),
                    ]
                )
                + " |"
            )
        lines.append("")
    lines.extend(["### 6.2 Local Instruction Evidence", ""])
    evidence = _as_list(data.get("instruction_evidence"))
    if evidence:
        lines.extend(["| Index | File | Line | Evidence Type | Matched Text | Chain Role |", "| ----: | --- | ---: | --- | --- | --- |"])
        for index, item in enumerate(sorted(evidence, key=_instruction_sort_key), 1):
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(index),
                        _escape_table(_first_in(item, "file", "path")),
                        _escape_table(_first_in(item, "line", "line_number")),
                        _escape_table(_first_in(item, "evidence_type", "type")),
                        _escape_table(_first_in(item, "matched_text", "text", "snippet")),
                        _escape_table(_first_in(item, "chain_role", "role")),
                    ]
                )
                + " |"
            )
        lines.append("")
    else:
        lines.extend(["No instruction_evidence was provided.", ""])
    lines.extend(
        [
            "### 6.3 Latent Evidence Boundary",
            "",
            "Instruction-derived evidence means that local Skill documentation, configuration, or scripts record a latent risk path. Unless corresponding execution events exist in runtime_events, this chain must not be described as a runtime attack.",
            "",
        ]
    )
    if data.get("dynamic_chain_observed") is False and data.get("instruction_chain_recovered") is True:
        lines.extend(
            [
                "Boundary Classification: instruction-derived latent chain; not a runtime-observed attack.",
                "",
            ]
        )
    return lines


def _weak_indicators(ctx: dict[str, Any]) -> list[str]:
    rows: list[tuple[str, str, Any]] = []
    data = ctx["data"]
    for field in ("indicators", "rule_hits", "behaviors", "warnings", "findings", "issues"):
        for item in _as_list(data.get(field)):
            rows.append((field, _indicator_label(item), item))
    lines = ["## 7. Weak Indicators and Non-Closed Evidence", ""]
    if not rows:
        lines.extend(["No weak indicators or rule-hit records were provided.", ""])
        return lines
    lines.extend(["| Index | Indicator | Source Field | Severity | Evidence | Closed-Chain Status | Why Not Closed |", "| ----: | --- | --- | --- | --- | --- | --- |"])
    for index, (field, label, item) in enumerate(sorted(rows, key=_indicator_sort_key), 1):
        status, reason = _indicator_chain_status(item, ctx)
        lines.append(
            f"| {index} | {_escape_table(label)} | {field} | {_escape_table(_indicator_severity(item))} | {_escape_table(_indicator_evidence(item))} | {status} | {reason} |"
        )
    lines.append("")
    return lines


def _root_cause(ctx: dict[str, Any]) -> list[str]:
    value = ctx["root_cause"]
    explanation = {
        "unsafe_dataflow_design": "Design risk where local or sensitive data flows to an external sink.",
        "unsafe_command_construction": "Risk in command construction or execution paths.",
        "llm_decision": "The risk path is related to LLM-driven action selection.",
        "overprivileged_tool_use": "Tool permissions or external transfer capability exceed what is necessary.",
        "skill_design": "The Skill design itself forms the risk path.",
        "supply_chain_setup": "Setup or maintenance instructions introduce external code, persistence, or environment-control risk.",
        "environment_control_setup": "An instruction_chain action points to global environment modification or environment-control setup.",
        "maintenance_update_risk": "An instruction_chain action points to bulk Skill update or maintenance-update risk.",
        "unsafe_distribution_setup": "An instruction_chain action points to fixed-password archives or unsafe distribution setup.",
        "unknown": "The JSON result does not provide an explainable root cause.",
        "missing": "The JSON result does not provide the root_cause field.",
    }.get(str(value).lower(), MISSING)
    return [
        "## 8. Root-Cause Attribution",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Root Cause | {_escape_table(value)} |",
        f"| Explanation | {_escape_table(explanation)} |",
        "",
    ]


def _risk_findings(ctx: dict[str, Any]) -> list[str]:
    data = ctx["data"]
    findings = _as_list(data.get("findings")) + _as_list(data.get("issues"))
    lines = ["## 9. Risk Findings", ""]
    if not findings:
        lines.extend(
            [
                "The JSON result does not include finding-level records. This limits the report to summary-level chain explanation and top-level risk fields. Reviewer should not assume that detailed rule-level evidence exists unless it is present in the original JSON.",
                "",
            ]
        )
        return lines
    for index, finding in enumerate(sorted(findings, key=_finding_sort_key), 1):
        title = _finding_title(finding)
        lines.extend(
            [
                f"### Finding {index}: {title}",
                "",
                "| Field | Value |",
                "| --- | --- |",
                f"| Finding ID | {_escape_table(_first_in(finding, 'finding_id', 'id'))} |",
                f"| Rule ID | {_escape_table(_first_in(finding, 'rule_id'))} |",
                f"| Rule Name | {_escape_table(_first_in(finding, 'rule_name', 'name'))} |",
                f"| Severity | {_escape_table(_first_in(finding, 'severity', 'risk_level'))} |",
                f"| File | {_escape_table(_first_in(finding, 'file', 'file_path', 'path'))} |",
                f"| Line | {_escape_table(_first_in(finding, 'line', 'line_number'))} |",
                f"| Evidence Type | {_escape_table(_first_in(finding, 'evidence_type', 'type'))} |",
                f"| Description | {_escape_table(_first_in(finding, 'description', 'detail'))} |",
                f"| Matched Text | {_escape_table(_first_in(finding, 'matched_text', 'match', 'pattern', 'text', 'snippet'))} |",
                f"| Recommendation | {_escape_table(_first_in(finding, 'recommendation', 'remediation', 'fix'))} |",
                "",
            ]
        )
        chain = _chain_info(_get_from(finding, "chain"), "source_relay_sink", "chain")
        if chain["provided"]:
            lines.extend(["#### Finding-Level Chain", ""])
            lines.extend(_inline_chain_block(chain))
    return lines


def _behavior_tags(ctx: dict[str, Any]) -> list[str]:
    behaviors = _as_list(ctx["data"].get("behaviors"))
    lines = ["## 10. Behavior Tags", ""]
    if not behaviors:
        lines.extend(["No behavior tags were provided. This limits aggregate behavior analysis and error analysis.", ""])
        return lines
    lines.extend(["| Index | Behavior | Description | Source Field |", "| ----: | --- | --- | --- |"])
    for index, item in enumerate(sorted(behaviors, key=_behavior_sort_key), 1):
        if isinstance(item, dict):
            behavior = _first_in(item, "name", "behavior", "tag")
            description = _first_in(item, "description", "detail")
        else:
            behavior = _string_or_missing(item)
            description = MISSING
        lines.append(f"| {index} | {_escape_table(behavior)} | {_escape_table(description)} | behaviors |")
    lines.append("")
    return lines


def _file_level_evidence(ctx: dict[str, Any]) -> list[str]:
    files = _as_list(ctx["data"].get("files"))
    lines = ["## 11. File-Level Evidence", ""]
    if not files:
        lines.extend(["No file-level evidence was provided. This limits file-level provenance review.", ""])
        return lines
    lines.extend(["| Index | File Path | File Type | Hit Status | Highest Risk | Evidence Count |", "| ----: | --- | --- | --- | --- | ---: |"])
    for index, item in enumerate(sorted(files, key=_file_sort_key), 1):
        lines.append(
            "| "
            + " | ".join(
                [
                    str(index),
                    _escape_table(_first_in(item, "path", "file_path", "name", "file")),
                    _escape_table(_first_in(item, "file_type", "type", "extension")),
                    _escape_table(_first_in(item, "hit_status", "matched", "hit", "is_hit")),
                    _escape_table(_first_in(item, "highest_risk", "highest_risk_level", "risk_level", "severity")),
                    _escape_table(_first_in(item, "evidence_count", "count", "matches")),
                ]
            )
            + " |"
        )
    lines.append("")
    return lines


def _errors_and_skipped(ctx: dict[str, Any]) -> list[str]:
    data = ctx["data"]
    errors = _as_list(data.get("errors")) + _as_list(data.get("error"))
    skipped = _first_raw(data, "skipped_reason")
    status = _first_raw(data, "status")
    status_skipped = str(status).lower() == "skipped"
    lines = ["## 12. Errors and Skipped State", ""]
    if not errors and not _has_content(skipped) and not status_skipped:
        lines.extend(["No errors or skipped-state records were provided in the JSON result.", ""])
        return lines
    if errors:
        lines.extend(["### 12.1 Errors", "", "| Index | Error Type | Message | Location | Stack / Code |", "| ----: | --- | --- | --- | --- |"])
        for index, error in enumerate(sorted(errors, key=_stable_json), 1):
            lines.append(
                f"| {index} | {_escape_table(_first_in(error, 'error_type', 'type'))} | {_escape_table(_error_message(error))} | {_escape_table(_first_in(error, 'location', 'file', 'path'))} | {_escape_table(_first_in(error, 'stack', 'stacktrace', 'traceback', 'code'))} |"
            )
        lines.append("")
    if _has_content(skipped) or status_skipped:
        lines.extend(
            [
                "### 12.2 Skipped State",
                "",
                f"* Scan Status: {_string_or_missing(status)}",
                f"* Skipped Reason: {_string_or_missing(skipped)}",
                "* Boundary Note: runtime execution skipped does not invalidate instruction-derived evidence.",
                "",
            ]
        )
    return lines


def _recommendations(ctx: dict[str, Any]) -> list[str]:
    records: list[dict[str, str]] = []
    data = ctx["data"]
    for key in ("recommendation", "remediation", "fix"):
        if _has_content(data.get(key)):
            records.append({"source": key, "severity": ctx["final_risk"], "text": _string_or_missing(data.get(key))})
    for field in ("findings", "issues"):
        for item in _as_list(data.get(field)):
            if isinstance(item, dict):
                for key in ("recommendation", "remediation", "fix"):
                    if _has_content(item.get(key)):
                        records.append(
                            {
                                "source": f"{field}[*].{key}",
                                "severity": _first_in(item, "severity", "risk_level"),
                                "text": _string_or_missing(item.get(key)),
                            }
                        )
    lines = ["## 13. Recommendations", ""]
    if not records:
        lines.extend(["No remediation or recommendation text was provided in the JSON result.", ""])
        return lines
    lines.extend(["| Index | Source | Severity | Recommendation |", "| ----: | --- | --- | --- |"])
    for index, record in enumerate(sorted(records, key=lambda r: (_risk_rank(r["severity"]), r["source"], r["text"])), 1):
        lines.append(f"| {index} | {record['source']} | {_escape_table(record['severity'])} | {_escape_table(record['text'])} |")
    lines.append("")
    return lines


def _missing_evidence_fields(ctx: dict[str, Any]) -> list[str]:
    why = {
        "evidence_type": "Distinguishes observed_runtime, instruction_derived, hybrid, or no_closed_chain.",
        "primary_chain": "Supports primary evidence-chain explanation.",
        "observed_runtime_chain": "Supports runtime source-relay-sink explanation.",
        "instruction_derived_chain": "Supports setup or maintenance latent-chain explanation.",
        "runtime_events": "Supports runtime event-level review.",
        "instruction_evidence": "Supports local instruction evidence review.",
        "findings": "Supports finding-level review.",
        "behaviors": "Supports behavior category analysis.",
        "files": "Supports file-level provenance review.",
        "recommendations": "Supports remediation recommendation review.",
    }
    lines = ["## 14. Missing Evidence Fields", "", "| Field | Status | Why It Matters |", "| --- | --- | --- |"]
    missing = set(ctx["missing_fields"])
    for field in MISSING_FIELD_ORDER:
        lines.append(f"| {field} | {'missing' if field in missing else 'present'} | {why[field]} |")
    lines.append("")
    return lines


def _human_reviewer_checklist() -> list[str]:
    return [
        "## 15. Human Reviewer Checklist",
        "",
        "* [ ] Check whether the source is a sensitive file, credential file, user data, or generated artifact.",
        "* [ ] Check whether the relay truly represents data flow, control flow, or action transfer rather than a generic intermediate operation.",
        "* [ ] Check whether the sink crosses a trust boundary, such as an external URL, remote API, webhook, remote script, persistence location, or global environment modification.",
        "* [ ] Check whether evidence_type clearly distinguishes runtime-observed evidence from instruction-derived evidence.",
        "* [ ] If evidence_type is a derived candidate, review the original JSON or scanner output to determine whether the scanner should explicitly emit evidence_type.",
        "* [ ] If findings are empty, add finding-level evidence to avoid a report that only contains summary-level chains.",
        "* [ ] If behaviors are empty, add behavior tags to support aggregate statistics and error analysis.",
        "* [ ] If runtime_events are empty, do not claim that the chain fully occurred at runtime.",
        "* [ ] If instruction_evidence is empty, do not claim that the chain comes from local instruction evidence.",
        "* [ ] If the chain validity check reports an unknown sink trust boundary, manually confirm whether the sink has security impact.",
        "",
    ]


def _machine_readable_summary(ctx: dict[str, Any]) -> list[str]:
    chain = ctx["selected_chain"]
    runtime_chain = ctx["runtime_for_report"]
    instruction_chain = ctx["instruction"]
    summary = {
        "skill_id": _nullable(_first_raw(ctx["data"], "skill_id", "id")),
        "skill_name": _nullable(_first_raw(ctx["data"], "skill_name", "name")),
        "scan_status": _nullable(_first_raw(ctx["data"], "status")),
        "final_risk": _nullable(ctx["final_risk_raw"]),
        "evidence_type": _nullable(ctx["derived_evidence_type"]),
        "evidence_type_source": ctx["evidence_type_source"],
        "root_cause": None if ctx["root_cause"] == "missing" else ctx["root_cause"],
        "closed_chain": bool(ctx["closed_chain"]),
        "chain_source": _machine_chain_value(chain, "source", "trust_boundary"),
        "chain_relay": _machine_chain_value(chain, "relay", "control_transfer"),
        "chain_sink": _machine_chain_value(chain, "sink", "impact_sink"),
        "sink_crosses_trust_boundary": _sink_crosses_trust_boundary(_machine_chain_value(chain, "sink", "impact_sink")),
        "runtime_chain": _machine_chain_object(runtime_chain, "source", "relay", "sink") if ctx["derived_evidence_type"] in {"observed_runtime", "hybrid"} else None,
        "instruction_chain_summary": _machine_chain_object(instruction_chain, "trust_boundary", "control_transfer", "impact_sink") if ctx["derived_evidence_type"] in {"instruction_derived", "hybrid"} else None,
        "missing_fields": ctx["missing_fields"],
        "reviewer_action": ctx["reviewer_action"],
    }
    return [
        "## 16. Machine-Readable Summary",
        "",
        "```json",
        json.dumps(summary, ensure_ascii=False, indent=2),
        "```",
        "",
    ]


def _reproducibility_statement() -> list[str]:
    return [
        "## 17. Reproducibility Statement",
        "",
        "This report was generated deterministically from a single-skill JSON result.",
        "No LLM, external API, network access, semantic summarization, or probabilistic reasoning was used.",
        "Repeated generation from the same JSON input should produce byte-identical Markdown output, assuming stable key ordering and renderer version.",
        "",
    ]


def _chain_validity_table(chain: dict[str, Any], ctx: dict[str, Any]) -> list[str]:
    if chain["kind"] in {"instruction", "instruction_steps"}:
        path_result = _instruction_path_crosses_trust_boundary(chain)
        rows = [
            ("Has trust boundary", _pass_fail(chain["values"].get("trust_boundary")), "Whether the field is present"),
            ("Has control transfer", _pass_fail(chain["values"].get("control_transfer")), "Whether the field is present"),
            ("Has impact sink", _pass_fail(chain["values"].get("impact_sink")), "Whether the field is present"),
            ("Path crosses trust boundary", path_result, "Whether the instruction path crosses external acquisition, environment-control, maintenance-update, persistence, or distribution boundaries"),
            ("Latent chain closed", "pass" if chain["closed"] else "fail", "Whether trust boundary, control transfer, and impact sink are all present"),
            ("Evidence type available", "pass" if ctx["evidence_type_source"] != "missing" else "fail", "Whether evidence_type is present or derivable"),
        ]
        lines = ["| Check | Result | Reason |", "| --- | --- | --- |"]
        lines.extend(f"| {check} | {result} | {reason} |" for check, result, reason in rows)
        lines.append("")
        return lines

    roles = _role_keys(chain)
    first, second, third = roles
    sink = chain["values"].get(third)
    sink_result = _sink_crosses_trust_boundary(sink)
    rows = [
        ("Has source / trust boundary", _pass_fail(chain["values"].get(first)), "Whether the field is present"),
        ("Has relay / control transfer", _pass_fail(chain["values"].get(second)), "Whether the field is present"),
        ("Has sink / impact sink", _pass_fail(sink), "Whether the field is present"),
        ("Sink crosses trust boundary", sink_result, "Whether the sink is an external URL, remote endpoint, global-state modification, or persistence target"),
        ("Chain is closed", "pass" if chain["closed"] else "fail", "Whether all three core roles are present"),
        ("Evidence type available", "pass" if ctx["evidence_type_source"] != "missing" else "fail", "Whether evidence_type is present or derivable"),
    ]
    lines = ["| Check | Result | Reason |", "| --- | --- | --- |"]
    lines.extend(f"| {check} | {result} | {reason} |" for check, result, reason in rows)
    lines.append("")
    return lines


def _inline_chain_block(chain: dict[str, Any]) -> list[str]:
    if chain["kind"] == "instruction_steps":
        return ["```text", _instruction_steps_path(chain["steps"]), "```", ""]
    values = [_string_or_missing(chain["values"].get(key)) for key in _role_keys(chain)]
    return ["```text", " -> ".join(values), "```", ""]


def _diagram_block(chain: dict[str, Any]) -> list[str]:
    if chain["kind"] == "instruction_steps":
        return ["```text", _instruction_steps_path(chain["steps"]), "```", ""]
    values = [_string_or_missing(chain["values"].get(key)) for key in _role_keys(chain)]
    return ["```text", values[0], "  |", "  v", values[1], "  |", "  v", values[2], "```", ""]


def _role_keys(chain: dict[str, Any]) -> tuple[str, str, str]:
    if chain["kind"] in {"instruction", "instruction_steps"}:
        return ("trust_boundary", "control_transfer", "impact_sink")
    return ("source", "relay", "sink")


def _role_labels(chain: dict[str, Any]) -> list[tuple[str, str]]:
    if chain["kind"] in {"instruction", "instruction_steps"}:
        return [
            ("Source / Trust Boundary", "trust_boundary"),
            ("Relay / Control Transfer", "control_transfer"),
            ("Sink / Impact Sink", "impact_sink"),
        ]
    return [
        ("Source / Trust Boundary", "source"),
        ("Relay / Control Transfer", "relay"),
        ("Sink / Impact Sink", "sink"),
    ]


def _chain_info(value: Any, kind: str, field: str) -> dict[str, Any]:
    keys = ("trust_boundary", "control_transfer", "impact_sink") if kind == "instruction" else ("source", "relay", "sink")
    values = {key: _extract_chain_value(value, key) for key in keys}
    provided = _has_content(value)
    closed = provided and all(_has_content(values[key]) for key in keys)
    return {"field": field, "kind": kind, "provided": provided, "closed": closed, "values": values}


def _instruction_context(data: dict[str, Any]) -> dict[str, Any]:
    if _has_content(data.get("instruction_derived_chain")):
        return _chain_info(data.get("instruction_derived_chain"), "instruction", "instruction_derived_chain")
    steps = _as_list(data.get("instruction_chain"))
    if not steps:
        return _chain_info(None, "instruction", "instruction_derived_chain")
    values = {
        "trust_boundary": _first_raw(steps[0], "source") if isinstance(steps[0], dict) else steps[0],
        "control_transfer": " -> ".join(_string_or_missing(_first_raw(step, "action")) for step in steps if isinstance(step, dict)),
        "impact_sink": _first_raw(steps[-1], "target") if isinstance(steps[-1], dict) else steps[-1],
    }
    closed = bool(data.get("instruction_chain_recovered")) and all(_has_content(v) for v in values.values())
    return {
        "field": "instruction_chain",
        "kind": "instruction_steps",
        "provided": True,
        "closed": closed,
        "values": values,
        "steps": steps,
    }


def _instruction_steps_path(steps: list[Any]) -> str:
    parts: list[str] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            if not parts:
                parts.append(_string_or_missing(step))
            continue
        source = _string_or_missing(_first_raw(step, "source"))
        action = _string_or_missing(_first_raw(step, "action"))
        target = _string_or_missing(_first_raw(step, "target"))
        if index == 0:
            parts.append(source)
        parts.append(f"--{action}-->")
        parts.append(target)
    return " ".join(parts) if parts else MISSING


def _extract_chain_value(chain: Any, key: str) -> Any:
    if isinstance(chain, dict):
        return _first_raw(chain, key)
    if isinstance(chain, list):
        aliases = {
            "source": {"source", "src"},
            "relay": {"relay", "intermediate", "middle"},
            "sink": {"sink", "destination", "dst"},
            "trust_boundary": {"trust_boundary"},
            "control_transfer": {"control_transfer"},
            "impact_sink": {"impact_sink"},
        }
        for item in chain:
            if isinstance(item, dict):
                role = str(_first_raw(item, "role", "type", "node_role") or "").lower()
                if role in aliases[key]:
                    return _node_label(item)
        index = {"source": 0, "relay": 1, "sink": 2, "trust_boundary": 0, "control_transfer": 1, "impact_sink": 2}[key]
        if len(chain) > index:
            return _node_label(chain[index])
    return None


def _node_label(node: Any) -> Any:
    if isinstance(node, dict):
        return _first_raw(node, "label", "value", "path", "url", "endpoint", "name", "id", "node_id")
    return node


def _derive_evidence_type(data: dict[str, Any], original: Any) -> tuple[str, str]:
    if _has_content(original):
        return _string_or_missing(original), "original"
    has_runtime = bool(data.get("dynamic_chain_observed")) or _has_content(data.get("observed_runtime_chain"))
    has_instruction = bool(data.get("instruction_chain_recovered")) or _has_content(data.get("instruction_derived_chain")) or _has_content(data.get("instruction_chain"))
    if has_runtime and has_instruction:
        return "hybrid", "derived_from_json_structure"
    if has_runtime:
        return "observed_runtime", "derived_from_json_structure"
    if has_instruction:
        return "instruction_derived", "derived_from_json_structure"
    if any(_has_content(data.get(field)) for field in ("indicators", "rule_hits", "behaviors", "warnings", "findings", "issues")):
        return "no_closed_chain", "derived_from_json_structure"
    return "missing", "missing"


def _final_risk_raw(data: dict[str, Any]) -> Any:
    final_risk_level = _first_raw(data, "final_risk_level")
    if _has_content(final_risk_level):
        return final_risk_level
    final_risk = _first_raw(data, "final_risk")
    if _has_content(final_risk):
        return final_risk
    static_risk = data.get("static_supply_chain_risk")
    if isinstance(static_risk, dict) and static_risk.get("closed_risk_path") is True and _has_content(static_risk.get("level")):
        return static_risk.get("level")
    return _first_raw(data, "risk_level")


def _closed_chain(
    data: dict[str, Any],
    primary: dict[str, Any],
    runtime: dict[str, Any],
    instruction: dict[str, Any],
) -> bool:
    static_risk = data.get("static_supply_chain_risk")
    if isinstance(static_risk, dict) and static_risk.get("closed_risk_path") is True:
        return True
    if data.get("instruction_chain_recovered") is True and _has_content(data.get("instruction_chain")):
        return True
    return bool(primary["closed"] or runtime["closed"] or instruction["closed"])


def _reviewer_action(final_risk: Any, closed_chain: bool) -> str:
    if not _has_content(final_risk):
        return "Risk level missing; manual triage required"
    risk = str(final_risk).lower()
    if risk in {"low", "info", "safe"}:
        return "Review optional"
    if not closed_chain:
        return "Inspect weak indicators before escalation"
    if risk in {"critical", "high"}:
        return "Immediate manual review required"
    if risk == "medium":
        return "Manual review recommended"
    return "Inspect weak indicators before escalation"


def _root_cause_value(data: dict[str, Any]) -> str:
    derived = _root_cause_from_instruction_actions(data)
    if _has_content(derived):
        return derived
    if "root_cause" not in data or not _has_content(data.get("root_cause")):
        return "missing"
    return _string_or_missing(data.get("root_cause"))


def _root_cause_from_instruction_actions(data: dict[str, Any]) -> str | None:
    actions = {
        str(_first_raw(step, "action") or "").lower()
        for step in _as_list(data.get("instruction_chain"))
        if isinstance(step, dict)
    }
    if "remote_script_or_binary_acquisition" in actions and "persistence_setup" in actions:
        return "supply_chain_setup"
    if "global_environment_modification" in actions:
        return "environment_control_setup"
    if "bulk_skill_update" in actions:
        return "maintenance_update_risk"
    if "fixed_password_archive" in actions:
        return "unsafe_distribution_setup"
    return None


def _derive_component_type(value: Any) -> str:
    text = _string_or_missing(value)
    lower = text.lower()
    if lower.startswith("http://") or lower.startswith("https://"):
        return "external_url"
    if any(token in lower for token in ("api", "endpoint", "relay", "webhook")):
        return "network_endpoint_candidate"
    if lower.startswith("runtime_output/"):
        return "generated_artifact"
    if any(token in lower for token in (".env", "credential", "secret", "token", "key")):
        return "credential_or_sensitive_file"
    if any(token in lower for token in (".txt", ".md", ".json", ".csv", ".yaml", ".yml")):
        return "local_file_or_artifact"
    if "write file" in lower:
        return "file_write_action"
    if "read file" in lower:
        return "file_read_action"
    if "trigger event" in lower:
        return "event_trigger"
    if any(token in lower for token in ("send", "upload", "export", "forward", "post")):
        return "external_transfer_action"
    if any(token in lower for token in ("command", "exec", "shell", "process")):
        return "process_or_command_action"
    return "unknown"


def _sink_crosses_trust_boundary(sink: Any) -> str:
    if not _has_content(sink):
        return "fail"
    lower = _string_or_missing(sink).lower()
    if lower.startswith("http://") or lower.startswith("https://"):
        return "pass"
    if any(token in lower for token in ("remote", "external", "webhook", "api", "relay")):
        return "pass"
    if any(token in lower for token in ("persistence", "global", "shellrc", "bashrc", "zshrc", "profile", "cron")):
        return "pass"
    return "unknown"


def _indicator_chain_status(item: Any, ctx: dict[str, Any]) -> tuple[str, str]:
    chain = _chain_info(_get_from(item, "chain"), "source_relay_sink", "chain")
    if chain["closed"]:
        return "closed", "closed_chain_available"
    if ctx["primary"]["provided"]:
        return "not_closed", "not_applicable"
    if not chain["provided"]:
        return "not_closed", "insufficient_fields"
    if not _has_content(chain["values"].get("source")):
        return "not_closed", "missing_source"
    if not _has_content(chain["values"].get("relay")):
        return "not_closed", "missing_relay"
    if not _has_content(chain["values"].get("sink")):
        return "not_closed", "missing_sink"
    return "not_closed", "insufficient_fields"


def _indicator_label(item: Any) -> str:
    if isinstance(item, dict):
        return _first_in(item, "indicator", "title", "rule_name", "rule_id", "name", "label", "behavior", "tag", "id")
    return _string_or_missing(item)


def _indicator_severity(item: Any) -> str:
    if isinstance(item, dict):
        return _first_in(item, "severity", "risk_level", "highest_risk")
    return MISSING


def _indicator_evidence(item: Any) -> str:
    if isinstance(item, dict):
        return _first_in(item, "evidence", "matched_text", "match", "pattern", "text", "snippet", "description")
    return MISSING


def _finding_title(finding: Any) -> str:
    if isinstance(finding, dict):
        return _first_in(finding, "title", "rule_name", "rule_id", "finding_id", "id")
    return _string_or_missing(finding)


def _error_message(error: Any) -> str:
    if isinstance(error, dict):
        return _first_in(error, "message", "error", "detail")
    return _string_or_missing(error)


def _missing_fields(data: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for field in MISSING_FIELD_ORDER:
        if field == "recommendations":
            present = any(_has_content(data.get(key)) for key in ("recommendation", "remediation", "fix"))
            for item in _as_list(data.get("findings")) + _as_list(data.get("issues")):
                if isinstance(item, dict):
                    present = present or any(_has_content(item.get(key)) for key in ("recommendation", "remediation", "fix"))
        elif field == "evidence_type":
            present = _has_content(data.get("evidence_type")) or _has_content(data.get("chain_evidence_type"))
        elif field == "findings":
            present = _has_content(data.get("findings")) or _has_content(data.get("issues"))
        elif field == "instruction_derived_chain":
            present = _has_content(data.get("instruction_derived_chain")) or _has_content(data.get("instruction_chain"))
        else:
            present = _has_content(data.get(field))
        if not present:
            missing.append(field)
    return missing


def _pass_fail(value: Any) -> str:
    return "pass" if _has_content(value) else "fail"


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _nullable(value: Any) -> Any:
    if not _has_content(value):
        return None
    return value


def _machine_chain_value(chain: dict[str, Any] | None, first: str, second: str) -> Any:
    if chain is None:
        return None
    return _nullable(chain["values"].get(first) if first in chain["values"] else chain["values"].get(second))


def _machine_chain_object(chain: dict[str, Any], first: str, second: str, third: str) -> dict[str, Any] | None:
    if not chain["provided"]:
        return None
    if first in chain["values"]:
        keys = (first, second, third)
    else:
        keys = ("trust_boundary", "control_transfer", "impact_sink")
    result = {
        keys[0]: _nullable(chain["values"].get(keys[0])),
        keys[1]: _nullable(chain["values"].get(keys[1])),
        keys[2]: _nullable(chain["values"].get(keys[2])),
        "field": chain["field"],
        "closed": bool(chain["closed"]),
    }
    if chain["kind"] == "instruction_steps":
        result["path"] = _instruction_steps_path(chain["steps"])
    return result


def _instruction_path_crosses_trust_boundary(chain: dict[str, Any]) -> str:
    text_parts = [_string_or_missing(value) for value in chain["values"].values()]
    if chain["kind"] == "instruction_steps":
        for step in chain["steps"]:
            if isinstance(step, dict):
                text_parts.extend(
                    [
                        _string_or_missing(_first_raw(step, "source")),
                        _string_or_missing(_first_raw(step, "action")),
                        _string_or_missing(_first_raw(step, "target")),
                    ]
                )
    lower = " ".join(text_parts).lower()
    tokens = (
        "http://",
        "https://",
        "remote_script_or_binary_acquisition",
        "external_agent_install",
        "persistence_setup",
        "global_environment_modification",
        "bulk_skill_update",
        "fixed_password_archive",
        "external",
        "remote",
        "webhook",
        "api",
        "cron",
        "launchctl",
        "global_execution_environment",
    )
    if any(token in lower for token in tokens):
        return "pass"
    if not chain["closed"]:
        return "fail"
    return "unknown"


def _risk_rank(value: Any) -> int:
    key = str(value if value is not None else "unknown").strip().lower()
    return RISK_ORDER.get(key, RISK_ORDER["unknown"])


def _first(data: dict[str, Any], *keys: str) -> str:
    return _string_or_missing(_first_raw(data, *keys))


def _first_in(value: Any, *keys: str) -> str:
    if isinstance(value, dict):
        return _first(value, *keys)
    return MISSING


def _first_raw(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and _has_content(data[key]):
            return data[key]
    return None


def _get_from(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else None


def _has_content(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if _has_content(value):
        return [value]
    return []


def _string_or_missing(value: Any) -> str:
    if not _has_content(value):
        return MISSING
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _escape_table(value: Any) -> str:
    return _string_or_missing(value).replace("|", "\\|").replace("\n", "<br>")


def _line_number(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _runtime_event_sort_key(item: Any) -> tuple[str, str, str, str, str]:
    if not isinstance(item, dict):
        text = _string_or_missing(item)
        return ("", "", "", "", text)
    return (
        _string_or_missing(_first_raw(item, "timestamp", "time")),
        _string_or_missing(_first_raw(item, "event_type", "type")),
        _string_or_missing(_first_raw(item, "actor", "process", "tool", "caller")),
        _string_or_missing(_first_raw(item, "target", "sink", "destination", "url")),
        _stable_json(item),
    )


def _instruction_sort_key(item: Any) -> tuple[str, int, str, str]:
    if not isinstance(item, dict):
        text = _string_or_missing(item)
        return ("", 0, "", text)
    return (
        _string_or_missing(_first_raw(item, "file", "path")),
        _line_number(_first_raw(item, "line", "line_number")),
        _string_or_missing(_first_raw(item, "evidence_type", "type")),
        _stable_json(item),
    )


def _finding_sort_key(item: Any) -> tuple[int, str, int, str, str, str]:
    if not isinstance(item, dict):
        text = _string_or_missing(item)
        return (_risk_rank(None), "", 0, "", "", text)
    return (
        _risk_rank(_first_raw(item, "severity", "risk_level")),
        _string_or_missing(_first_raw(item, "file", "file_path", "path")),
        _line_number(_first_raw(item, "line", "line_number")),
        _string_or_missing(_first_raw(item, "rule_id")),
        _string_or_missing(_first_raw(item, "finding_id", "id")),
        _stable_json(item),
    )


def _indicator_sort_key(row: tuple[str, str, Any]) -> tuple[str, int, str]:
    field, label, item = row
    return (field, _risk_rank(_indicator_severity(item)), label)


def _behavior_sort_key(item: Any) -> str:
    if isinstance(item, dict):
        return _first_in(item, "name", "behavior", "tag")
    return _string_or_missing(item)


def _file_sort_key(item: Any) -> tuple[str, str]:
    if isinstance(item, dict):
        return (_string_or_missing(_first_raw(item, "path", "file_path", "name", "file")), _stable_json(item))
    return (_string_or_missing(item), _string_or_missing(item))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a deterministic Markdown report for one Skill scan JSON.")
    parser.add_argument("--input", required=True, help="Path to a single Skill scan result JSON file.")
    parser.add_argument("--output", help="Path to write the Markdown report. Defaults to input path with .md suffix.")
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    args = build_arg_parser().parse_args(argv)
    output = generate_report_file(args.input, args.output)
    print(str(output))


if __name__ == "__main__":
    main()
