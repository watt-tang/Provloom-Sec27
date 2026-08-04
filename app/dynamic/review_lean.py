from __future__ import annotations

from typing import Any


REVIEW_LEAN_NONE = "none"
REVIEW_LEAN_MALICIOUS = "malicious_leaning"
REVIEW_LEAN_BENIGN = "benign_leaning"
CLASSIFICATION_THRESHOLD = 0.55
REVIEW_LOWER_BOUND = 0.47
REVIEW_UPPER_BOUND = 0.66

_RETRY_GAP_STATES = {
    "timeout",
    "llm_request_timeout",
    "max_steps_exhausted",
    "provider_failure",
    "execution_failed",
    "path_not_triggered",
    "insufficient_coverage",
}
_DANGEROUS_TOKENS = {
    "send",
    "upload",
    "exfil",
    "egress",
    "network",
    "http",
    "socket",
    "exec",
    "run_command",
    "shell",
    "download",
    "persist",
    "persistence",
    "destructive",
    "delete",
    "write_sensitive",
    "privilege",
    "remote_control",
    "authorization_bypass",
}
_HIGH_RISK_STATIC_TYPES = {
    "credential_exfiltration",
    "private_data_exfiltration",
    "destructive_write",
    "download_execute",
    "privilege_expansion",
    "persistence",
    "remote_control",
}
_BENIGN_STATIC_STATUSES = {"expected", "trusted", "allowed", "capability_only"}


def apply_review_lean(
    assessment: dict[str, Any],
    *,
    runtime_chains: Any = None,
    runtime_events: Any = None,
    policy_findings: Any = None,
    coverage_certificate: Any = None,
    dynamic_payload: dict[str, Any] | None = None,
    static_payload: dict[str, Any] | None = None,
    analysis_mode: str = "full_system",
) -> dict[str, Any]:
    """Resolve binary security prediction and keep review as auxiliary metadata."""

    payload = dict(assessment or {})
    chains = _records(runtime_chains)
    events = _records(runtime_events)
    findings = _records(policy_findings)
    coverage = _record(coverage_certificate)
    dynamic_payload = dynamic_payload or {}
    static_payload = static_payload or {}
    if dynamic_payload:
        chains = chains or _records(dynamic_payload.get("runtime_chains") or dynamic_payload.get("chains"))
        events = events or _records(dynamic_payload.get("runtime_events") or dynamic_payload.get("events"))
        findings = findings or _records(dynamic_payload.get("policy_findings") or dynamic_payload.get("policy_violations"))
        coverage = coverage or _record(dynamic_payload.get("coverage") or dynamic_payload.get("coverage_certificate"))

    old_decision = str(payload.get("canonical_final_decision") or payload.get("final_decision") or "unknown")
    payload["legacy_review_decision"] = old_decision
    mode = "static_only" if str(analysis_mode) == "static_only" else "full_system"
    if mode == "static_only":
        score, reasons, review_reasons = _static_score(static_payload, findings)
    else:
        score, reasons, review_reasons = _full_system_score(payload, chains, events, findings, coverage, static_payload)

    score = round(max(0.0, min(1.0, score)), 4)
    binary = "malicious" if score >= CLASSIFICATION_THRESHOLD else "benign"
    review_required = _review_required(
        score=score,
        payload=payload,
        chains=chains,
        findings=findings,
        coverage=coverage,
        mode=mode,
        review_reasons=review_reasons,
    )
    if review_required and not review_reasons and REVIEW_LOWER_BOUND <= score <= REVIEW_UPPER_BOUND:
        review_reasons.append("decision score is near the classification threshold")
    if review_required and not review_reasons:
        if str(payload.get("security_resolution_status")) == "unresolved_before_guard":
            review_reasons.append("security guard remained unresolved before execution ended")
        elif any(item.get("contradiction_type") for item in _records(payload.get("contradictions"))):
            review_reasons.append("static and runtime evidence contain a security-relevant contradiction")
        elif any(str(item.get("evidence_status")) == "contradicted" for item in findings):
            review_reasons.append("policy evidence is contradicted")
        elif mode != "static_only" and _has_decisive_sink_gap(payload, coverage):
            review_reasons.append("decisive instrumentation gap affects security judgment")
        else:
            review_reasons.append("security-relevant uncertainty remains")
    if _has_confirmed_violation(payload, chains, findings):
        binary = "malicious"
        score = max(score, 0.95)
        review_required = False
        review_reasons = []
        reasons.insert(0, "confirmed violation")
    if _security_resolved_after_timeout(payload, coverage):
        review_required = False
        review_reasons = [reason for reason in review_reasons if "timeout" not in reason and "provider" not in reason]

    review_lean = REVIEW_LEAN_NONE
    if review_required:
        review_lean = REVIEW_LEAN_MALICIOUS if binary == "malicious" else REVIEW_LEAN_BENIGN
    reason = "; ".join(_dedupe(reasons)) or "decision score resolved from available canonical evidence"
    review_reason = "; ".join(_dedupe(review_reasons)) if review_required else "not_required"
    payload.update(
        {
            "final_decision": binary,
            "canonical_final_decision": binary,
            "binary_prediction": binary,
            "decision_score": score,
            "review_required": bool(review_required),
            "review_lean": review_lean,
            "review_reason": review_reason,
            "needs_review": bool(review_required),
            "lean_score": score,
            "lean_reason": review_reason,
            "classification_threshold": CLASSIFICATION_THRESHOLD,
            "review_lower_bound": REVIEW_LOWER_BOUND,
            "review_upper_bound": REVIEW_UPPER_BOUND,
            "operating_thresholds": {
                "classification_threshold": CLASSIFICATION_THRESHOLD,
                "review_lower_bound": REVIEW_LOWER_BOUND,
                "review_upper_bound": REVIEW_UPPER_BOUND,
            },
            "decision_reason": reason,
        }
    )
    return payload


def _static_score(static_payload: dict[str, Any], findings: list[dict[str, Any]]) -> tuple[float, list[str], list[str]]:
    chains = _records(static_payload.get("static_chains"))
    actions = _records(static_payload.get("extracted_actions"))
    entities = _records(static_payload.get("resolved_entities"))
    review_reasons: list[str] = []
    scores: list[float] = []
    reasons: list[str] = []
    for chain in chains:
        alert = str(chain.get("alert_status") or chain.get("policy_status") or "").lower()
        status = str(chain.get("status") or "").lower()
        priority = str(chain.get("review_priority") or "").lower()
        ctype = str(chain.get("chain_type") or chain.get("capability_type") or "").lower()
        strength = str(chain.get("resolution_strength_summary") or "").lower()
        if alert == "violation" or str(chain.get("policy_status") or "") == "untrusted_external_flow":
            base = 0.9 if status == "closed" and strength in {"strong", "confirmed"} else 0.72
            if priority in {"critical", "high"}:
                base += 0.04
            if ctype in _HIGH_RISK_STATIC_TYPES:
                base += 0.03
            scores.append(base)
            reasons.append(f"static {ctype or 'risk'} path classified as violation")
            if base < 0.7:
                review_reasons.append("static path confidence is low")
        elif alert == "review" or priority in {"review", "medium"}:
            scores.append(0.52)
            review_reasons.append("static path is semantically ambiguous")
            reasons.append("static path requires semantic review")
        elif alert in _BENIGN_STATIC_STATUSES or str(chain.get("policy_status") or "").lower() in _BENIGN_STATIC_STATUSES:
            scores.append(0.15)
            reasons.append("static path is allowed or capability-only")
    action_score, action_reasons, action_reviews = _static_action_score(actions, entities)
    if action_score and (not scores or action_score > max(scores)):
        scores.append(action_score)
        reasons.extend(action_reasons)
        review_reasons.extend(action_reviews)
        if action_score >= 0.7:
            review_reasons = [reason for reason in review_reasons if reason != "static path is semantically ambiguous"]
    if not scores:
        scores.append(0.12)
        reasons.append("static-only analysis found no risky path")
    if any(str(item.get("evidence_status")) == "contradicted" for item in findings):
        review_reasons.append("static policy finding is contradicted")
    return max(scores), reasons, review_reasons


def _full_system_score(
    payload: dict[str, Any],
    chains: list[dict[str, Any]],
    events: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    coverage: dict[str, Any],
    static_payload: dict[str, Any] | None = None,
) -> tuple[float, list[str], list[str]]:
    reasons: list[str] = []
    review_reasons: list[str] = []
    if _has_confirmed_violation(payload, chains, findings):
        return 1.0, ["confirmed runtime violation"], []
    if _has_candidate_violation(payload, chains, findings):
        review_reasons.append("candidate violation needs human confirmation")
        return 0.74, ["candidate violation or candidate untrusted sink"], review_reasons
    if _resolved_allowed_or_no_flow(payload, coverage) and not _has_decisive_sink_gap(payload, coverage):
        return 0.1, ["confirmed allowed flow or resolved no-flow"], []
    if _has_decisive_sink_gap(payload, coverage):
        review_reasons.append("decisive instrumentation gap affects security judgment")
        return 0.66, ["source/carrier evidence with unresolved decisive sink"], review_reasons
    if _has_dangerous_prefix(events, coverage, chains=chains, findings=findings, static_payload=static_payload or {}):
        review_reasons.append("execution incomplete after dangerous operation prefix")
        return 0.69, ["dangerous runtime operation prefix"], review_reasons
    if _has_confirmed_allowed(payload, chains, events, coverage):
        return 0.1, ["confirmed allowed flow or resolved no-flow"], []
    if str(payload.get("status")) == "no_violation_observed":
        return 0.16, ["canonical runtime assessment observed no violation"], []
    execution_status = str(payload.get("execution_completion_status") or coverage.get("execution_status") or coverage.get("coverage_state") or payload.get("coverage_state") or "")
    if execution_status in _RETRY_GAP_STATES:
        review_reasons.append(f"runtime/provider failure before security resolution: {execution_status}")
        return 0.52, ["execution incomplete before safety could be resolved"], review_reasons
    return 0.35, ["insufficient runtime evidence but no risky flow observed"], []


def _review_required(
    *,
    score: float,
    payload: dict[str, Any],
    chains: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    coverage: dict[str, Any],
    mode: str,
    review_reasons: list[str],
) -> bool:
    if review_reasons:
        return True
    if REVIEW_LOWER_BOUND <= score <= REVIEW_UPPER_BOUND:
        return True
    if _resolved_allowed_or_no_flow(payload, coverage) and not _has_candidate_violation(payload, chains, findings) and not _has_confirmed_violation(payload, chains, findings) and not _has_decisive_sink_gap(payload, coverage):
        return False
    if any(item.get("contradiction_type") for item in _records(payload.get("contradictions"))):
        return True
    if any(str(item.get("evidence_status")) == "contradicted" for item in findings):
        return True
    if str(payload.get("security_resolution_status")) == "unresolved_before_guard":
        return True
    if _has_candidate_violation(payload, chains, findings) and _has_confirmed_allowed(payload, chains, [], coverage):
        return True
    if mode != "static_only" and _has_decisive_sink_gap(payload, coverage):
        return True
    return False


def _has_confirmed_violation(payload: dict[str, Any], chains: list[dict[str, Any]], findings: list[dict[str, Any]]) -> bool:
    if str(payload.get("status")) == "violation_confirmed" or int(payload.get("policy_violation_count") or 0) > 0:
        return True
    if str(payload.get("risk_chain_status")) == "confirmed_violation":
        return True
    if any(str(item.get("status")) == "violation" and str(item.get("evidence_status")) == "runtime_confirmed" for item in findings):
        return True
    return any(str(chain.get("chain_type") or "").endswith("_confirmed") and str(chain.get("policy_status") or "") == "violation" for chain in chains)


def _has_candidate_violation(payload: dict[str, Any], chains: list[dict[str, Any]], findings: list[dict[str, Any]]) -> bool:
    if int(payload.get("candidate_chain_count") or 0) > 0:
        return True
    if str(payload.get("risk_chain_status")) in {"candidate_violation", "candidate_flow"}:
        return True
    if any(str(item.get("status")) in {"review", "violation"} and "candidate" in str(item.get("evidence_status") or "") for item in findings):
        return True
    return any("candidate" in str(chain.get("chain_type") or "") for chain in chains)


def _has_decisive_sink_gap(payload: dict[str, Any], coverage: dict[str, Any]) -> bool:
    if str(payload.get("security_resolution_status")) in {"unresolved_before_sink", "unresolved_instrumentation"}:
        return True
    unresolved = {str(item) for item in coverage.get("unresolved_decisive_obligations", []) or []}
    if unresolved:
        for obligation in _records(coverage.get("obligations")):
            oid = str(obligation.get("obligation_id") or "")
            if oid in unresolved and _operation_is_dangerous(obligation.get("expected_runtime_operation")):
                return True
    return False


def _has_dangerous_prefix(
    events: list[dict[str, Any]],
    coverage: dict[str, Any],
    *,
    chains: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    static_payload: dict[str, Any] | None = None,
) -> bool:
    context = {
        "chains": chains or [],
        "findings": findings or [],
        "static_payload": static_payload or {},
    }
    for event in events:
        if _is_evidence_backed_dangerous_prefix(event, context):
            return True
    for obligation in _records(coverage.get("obligations")):
        if (
            str(obligation.get("status")) == "satisfied"
            and _operation_is_dangerous(obligation.get("expected_runtime_operation"), structured=True)
            and _obligation_is_security_relevant(obligation, context)
        ):
            return True
    return False


def _has_confirmed_allowed(payload: dict[str, Any], chains: list[dict[str, Any]], events: list[dict[str, Any]], coverage: dict[str, Any]) -> bool:
    risk_status = str(payload.get("risk_chain_status") or "")
    security_status = str(payload.get("security_resolution_status") or "")
    if risk_status in {"confirmed_allowed", "no_sensitive_flow_observed"} and security_status in {"resolved_allowed", "resolved_no_flow"}:
        return True
    if bool(payload.get("termination_after_security_resolution")) and risk_status in {"confirmed_allowed", "no_sensitive_flow_observed"}:
        return True
    if str(coverage.get("coverage_state")) == "target_reached_no_flow":
        return True
    return _only_trusted_llm_or_no_untrusted_sink(events, chains) and risk_status == "confirmed_allowed"


def _resolved_allowed_or_no_flow(payload: dict[str, Any], coverage: dict[str, Any]) -> bool:
    security_status = str(payload.get("security_resolution_status") or coverage.get("security_resolution_status") or "")
    risk_status = str(payload.get("risk_chain_status") or coverage.get("risk_chain_status") or "")
    if security_status in {"resolved_allowed", "resolved_no_flow"}:
        return True
    return risk_status in {"confirmed_allowed", "no_sensitive_flow_observed"} and str(coverage.get("coverage_state")) == "target_reached_no_flow"


def _security_resolved_after_timeout(payload: dict[str, Any], coverage: dict[str, Any]) -> bool:
    execution_status = str(payload.get("execution_completion_status") or coverage.get("execution_status") or "")
    if execution_status not in _RETRY_GAP_STATES:
        return False
    return bool(payload.get("termination_after_security_resolution")) or str(payload.get("security_resolution_status")) in {"resolved_allowed", "resolved_no_flow"}


def _actions_include_danger(actions: list[dict[str, Any]]) -> bool:
    return any(_operation_is_dangerous(action.get("action_type")) or _operation_is_dangerous(action.get("raw_verb")) for action in actions)


def _static_action_score(actions: list[dict[str, Any]], entities: list[dict[str, Any]]) -> tuple[float, list[str], list[str]]:
    required = [action for action in actions if str(action.get("modality") or "required").lower() == "required"]
    action_types = {str(action.get("action_type") or "").upper() for action in required}
    has_sensitive = _entities_include_sensitive_source(entities) or any(str(action.get("action_type") or "").upper() == "ACCESS_CREDENTIAL" for action in required)
    has_endpoint = any(str(entity.get("entity_type") or "") == "NetworkEndpoint" for entity in entities)
    reasons: list[str] = []
    reviews: list[str] = []
    if has_sensitive and action_types & {"SEND", "UPLOAD", "INVOKE_API"}:
        reasons.append("static required sensitive-source external transfer")
        return 0.72, reasons, []
    if has_sensitive and "READ" in action_types and has_endpoint and any(str(action.get("action_type") or "").upper() in {"SEND", "UPLOAD", "INVOKE_API"} for action in actions):
        reasons.append("static sensitive read and endpoint-bearing transfer path")
        return 0.64, reasons, []
    if action_types & {"DOWNLOAD", "EXECUTE"} and {"DOWNLOAD", "EXECUTE"}.issubset(action_types):
        reasons.append("static download-execute path")
        return 0.74, reasons, []
    if action_types & {"EXECUTE", "DELETE", "PERSIST", "PRIVILEGE_EXPANSION"} and has_sensitive:
        reasons.append("static dangerous operation over sensitive context")
        return 0.66, reasons, []
    return 0.0, [], []


def _entities_include_sensitive_source(entities: list[dict[str, Any]]) -> bool:
    return any(str(entity.get("entity_type") or "").lower() in {"credential", "sensitiveresource", "secret"} for entity in entities)


def _only_trusted_llm_or_no_untrusted_sink(events: list[dict[str, Any]], chains: list[dict[str, Any]]) -> bool:
    if any("candidate" in str(chain.get("chain_type") or "") for chain in chains):
        return False
    network_events = [event for event in events if _event_is_network(event)]
    if not network_events:
        return True
    for event in network_events:
        text = " ".join(
            str(value or "")
            for value in (
                event.get("event_type"),
                event.get("object_id"),
                event.get("object_path"),
                event.get("carrier_type"),
                (event.get("metadata") or {}).get("provider") if isinstance(event.get("metadata"), dict) else "",
                (event.get("metadata") or {}).get("destination") if isinstance(event.get("metadata"), dict) else "",
            )
        ).lower()
        if "llm" not in text and not any(domain in text for domain in ("openai", "deepseek", "siliconflow", "sec.llm.autos")):
            return False
    return True


def _event_is_network(event: dict[str, Any]) -> bool:
    return str(event.get("object_type") or "") == "network" or "network" in str(event.get("event_type") or "")


def _is_evidence_backed_dangerous_prefix(event: dict[str, Any], context: dict[str, Any]) -> bool:
    if _is_runtime_internal(event):
        return False
    if _is_cache_or_interpreter_noise(event):
        return False
    if _is_process_spawn_only(event):
        return False
    if _is_trusted_provider_request(event):
        return False
    if _is_plain_network_observation(event):
        return False
    if not _operation_is_dangerous(_event_operation_text(event), structured=True):
        return False
    return any(
        (
            _event_has_taint(event),
            _event_matches_candidate_chain(event, context.get("chains", [])),
            _event_matches_runtime_policy_finding(event, context.get("findings", [])),
            _event_matches_static_risk_path(event, context.get("static_payload", {})),
            _event_reaches_untrusted_sink(event),
            _event_has_explicit_dangerous_target(event),
        )
    )


def _event_operation_text(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    metadata_values: list[Any] = []
    if isinstance(metadata, dict):
        metadata_values = [
            metadata.get("action"),
            metadata.get("operation"),
            metadata.get("command"),
            metadata.get("executable"),
            metadata.get("destination"),
            metadata.get("endpoint_kind"),
        ]
    return " ".join(
        str(value or "")
        for value in (
            event.get("event_type"),
            event.get("operation"),
            event.get("object_type"),
            event.get("carrier_type"),
            event.get("object_path"),
            event.get("object_id"),
            *metadata_values,
        )
    )


def _operation_is_dangerous(value: Any, *, structured: bool = False) -> bool:
    text = str(value or "").lower()
    if structured:
        if _text_is_process_spawn_only(text):
            return False
        structured_tokens = {
            "exfil",
            "egress",
            "upload",
            "http_body",
            "multipart_field",
            "upload_file",
            "socket_payload",
            "destructive",
            "delete_or_rename",
            "write_sensitive",
            "privilege",
            "authorization_bypass",
            "remote_control",
            "download_execute",
            "persistence",
            "persist",
        }
        if any(token in text for token in structured_tokens):
            return True
        if "execve" in text or "run_command" in text or "shell" in text:
            return _text_has_concrete_dangerous_exec(text)
        if any(token in text for token in ("network_send", "llm_request", "http_request")):
            return any(carrier in text for carrier in ("http_body", "http_header", "http_query", "multipart", "upload_file", "socket_payload", "llm_context"))
        return False
    return any(token in text for token in _DANGEROUS_TOKENS)


def _event_has_taint(event: dict[str, Any]) -> bool:
    metadata = event.get("metadata") or {}
    return bool(
        event.get("taint_ids")
        or event.get("input_taint_ids")
        or event.get("output_taint_ids")
        or (isinstance(metadata, dict) and (metadata.get("taint_ids") or metadata.get("source_id") or metadata.get("source_ids")))
    )


def _event_matches_candidate_chain(event: dict[str, Any], chains: list[dict[str, Any]]) -> bool:
    event_id = str(event.get("event_id") or "")
    if not event_id:
        return False
    for chain in chains:
        if "candidate" not in str(chain.get("chain_type") or chain.get("status") or chain.get("policy_status") or "").lower():
            continue
        supporting_ids = _chain_event_ids(chain)
        if event_id in supporting_ids:
            return True
    return False


def _event_matches_runtime_policy_finding(event: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
    event_id = str(event.get("event_id") or "")
    if not event_id:
        return False
    for finding in findings:
        if str(finding.get("origin") or "") not in {"runtime", "reconciliation"}:
            continue
        if str(finding.get("status") or "") not in {"review", "violation"}:
            continue
        if event_id in {str(item) for item in finding.get("supporting_ids", []) or []}:
            return True
    return False


def _event_matches_static_risk_path(event: dict[str, Any], static_payload: dict[str, Any]) -> bool:
    if not _static_payload_has_high_risk_path(static_payload):
        return False
    metadata = event.get("metadata") or {}
    static_ids = []
    if isinstance(metadata, dict):
        static_ids.extend(metadata.get("static_ids") or [])
        static_ids.extend(metadata.get("aligned_static_ids") or [])
    if static_ids:
        return True
    if _event_has_explicit_dangerous_target(event):
        return True
    text = _event_operation_text(event).lower()
    return any(token in text for token in ("download", "curl", "wget", "chmod", "sudo", "crontab", "systemd", "/etc/shadow", ".ssh/id_"))


def _event_reaches_untrusted_sink(event: dict[str, Any]) -> bool:
    if not _event_is_network(event):
        return False
    if _is_trusted_provider_request(event):
        return False
    if _is_plain_network_observation(event):
        return False
    text = _event_operation_text(event).lower()
    has_payload_carrier = any(carrier in text for carrier in ("http_body", "http_header", "http_query", "multipart", "upload_file", "socket_payload"))
    return has_payload_carrier and (_event_has_taint(event) or any(token in text for token in ("exfil", "upload", "credential", "secret")))


def _event_has_explicit_dangerous_target(event: dict[str, Any]) -> bool:
    text = _event_operation_text(event).replace("\\", "/").lower()
    if _is_plain_network_observation(event):
        return False
    target_markers = (
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh/",
        ".ssh/id_",
        "/.ssh/id_",
        "/etc/cron",
        "/var/spool/cron",
        ".bashrc",
        ".profile",
        "authorized_keys",
        "/systemd/",
        "/usr/bin/",
        "/usr/local/bin/",
    )
    command_markers = (
        "curl ",
        "wget ",
        "| sh",
        "| bash",
        "chmod +x",
        "sudo ",
        "crontab ",
        "systemctl ",
        "launchctl ",
        "powershell",
    )
    return any(marker in text for marker in target_markers) or any(marker in text for marker in command_markers)


def _obligation_is_security_relevant(obligation: dict[str, Any], context: dict[str, Any]) -> bool:
    if obligation.get("static_ids"):
        return True
    if str(obligation.get("origin") or "") in {"static_path", "declared_action"}:
        return _static_payload_has_high_risk_path(context.get("static_payload", {}))
    return str(obligation.get("blocking_condition") or "") in {
        "untrusted_sink_pending",
        "payload_observable_pending",
        "artifact_identity_pending",
        "privilege_target_pending",
    }


def _chain_event_ids(chain: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for key in ("event_ids", "supporting_event_ids", "runtime_event_ids"):
        values.update(str(item) for item in chain.get(key, []) or [] if str(item))
    for edge in _records(chain.get("edges")):
        values.update(str(item) for item in edge.get("event_ids", []) or [] if str(item))
    return values


def _static_payload_has_high_risk_path(static_payload: dict[str, Any]) -> bool:
    for chain in _records(static_payload.get("static_chains")):
        text = " ".join(str(chain.get(key) or "") for key in ("chain_type", "capability_type", "alert_status", "policy_status", "review_priority")).lower()
        if "violation" in text or "untrusted_external_flow" in text or any(kind in text for kind in _HIGH_RISK_STATIC_TYPES):
            return True
    for action in _records(static_payload.get("extracted_actions")):
        text = " ".join(str(action.get(key) or "") for key in ("action_type", "raw_verb", "tool_name", "command")).lower()
        if any(token in text for token in ("delete", "execute", "exec", "persist", "privilege", "download", "upload", "send")):
            return True
    return False


def _is_runtime_internal(event: dict[str, Any]) -> bool:
    metadata = event.get("metadata") or {}
    if isinstance(metadata, dict):
        scope = str(metadata.get("scope") or metadata.get("runtime_scope") or metadata.get("path_scope") or "").lower()
        category = str(metadata.get("category") or metadata.get("source_category") or "").lower()
        if scope == "runtime_internal" or category in {"runtime_internal", "package_cache"}:
            return True
        if metadata.get("runtime_internal") is True:
            return True
    return False


def _is_cache_or_interpreter_noise(event: dict[str, Any]) -> bool:
    text = _event_operation_text(event).replace("\\", "/").lower()
    if not text:
        return False
    internal_markers = (
        "/opt/skill_sandbox/",
        "python -m app.runtime.container_runtime",
        "/usr/local/lib/python",
        "/usr/lib/python",
        "/lib/python",
        "/site-packages/",
        "__pycache__",
        ".pyc",
        "/etc/ssl/",
        "/usr/lib/ssl/",
        "/etc/ca-certificates/",
        "/usr/share/ca-certificates/",
        "certifi/cacert.pem",
        "/root/.cache/",
        "/.cache/",
        "/pip/",
        "/.npm/",
        "node_modules/",
        "huggingface/",
        "transformers/",
        "modelscope/",
        "/var/cache/",
        "/var/lib/apt/",
        "/tmp/pip-",
        "/tmp/tmp",
        "ld-linux",
        "libc.so",
        "libpython",
    )
    if any(marker in text for marker in internal_markers):
        return True
    return "rename(" in text and (".pyc" in text or "__pycache__" in text)


def _is_process_spawn_only(event: dict[str, Any]) -> bool:
    if str(event.get("object_type") or "") != "process" and "process" not in str(event.get("event_type") or ""):
        return False
    text = _event_operation_text(event).lower()
    return _text_is_process_spawn_only(text)


def _text_is_process_spawn_only(text: str) -> bool:
    if any(token in text for token in ("execve", "posix_spawn", "run_command", "shell")):
        return False
    return any(token in text for token in ("vfork", "fork", "clone", "process_spawn"))


def _text_has_concrete_dangerous_exec(text: str) -> bool:
    if _text_is_process_spawn_only(text):
        return False
    return any(
        token in text
        for token in (
            "curl ",
            "wget ",
            "| sh",
            "| bash",
            "chmod +x",
            "sudo ",
            "crontab ",
            "systemctl ",
            "nc ",
            "netcat",
            "bash -c",
            "sh -c",
            "powershell",
            "/etc/shadow",
            ".ssh/id_",
        )
    )


def _is_trusted_provider_request(event: dict[str, Any]) -> bool:
    return _event_is_network(event) and _only_trusted_llm_or_no_untrusted_sink([event], [])


def _is_plain_network_observation(event: dict[str, Any]) -> bool:
    if not _event_is_network(event):
        return False
    text = _event_operation_text(event).lower()
    if any(carrier in text for carrier in ("http_body", "http_header", "http_query", "multipart", "upload_file", "socket_payload", "llm_context")):
        return False
    return any(token in text for token in ("connect", "socket", "dns", "endpoint_observed", "network_connect"))


def _records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [_record(value)]
    result: list[dict[str, Any]] = []
    if isinstance(value, (list, tuple, set)):
        for item in value:
            record = _record(item)
            if record:
                result.append(record)
    else:
        record = _record(value)
        if record:
            result.append(record)
    return result


def _record(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "to_dict"):
        return dict(value.to_dict())
    return dict(getattr(value, "__dict__", {}) or {})


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
