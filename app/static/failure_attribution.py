from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


FAILURE_REASONS = {
    "artifact_not_loaded", "unsupported_artifact", "parse_failure", "action_not_extracted", "malicious_code_not_reached",
    "source_not_identified", "sink_not_identified", "data_object_not_created", "variable_propagation_missing",
    "argument_binding_missing", "payload_binding_missing", "endpoint_resolution_failed", "entity_linking_failed",
    "cross_artifact_link_missing", "artifact_identity_missing", "critical_edge_uncertain", "modality_filtered",
    "trusted_endpoint_misclassified", "expected_behavior_misclassified", "policy_insufficient_context",
    "path_template_missing", "attack_not_chain_compatible", "unsupported_attack_behavior", "analysis_error", "timeout",
}

BEHAVIOR_NAMES = {
    "B1": "Data Exfiltration",
    "B2": "Credential Theft",
    "B3": "Remote Code Execution",
    "B4": "Malware Delivery",
    "B5": "Persistence",
    "B6": "Reverse Shell",
    "B7": "Ransomware",
    "B8": "Resource Abuse",
    "B9": "Privilege Escalation",
    "B10": "Role Hijack",
    "B11": "Safety Bypass",
    "B12": "Instruction Override",
    "B13": "System Prompt Leak",
    "B14": "Goal Hijacking",
    "B15": "Content Manipulation",
}

CHAIN_COMPATIBLE_BEHAVIORS = {f"B{i}" for i in range(1, 10)}
PI_BEHAVIORS = {f"B{i}" for i in range(10, 16)}


@dataclass
class FailureAttribution:
    skill_id: str
    attack_vector: str
    behavior_id: str
    primary_failure_reason: str
    secondary_failure_reasons: list[str] = field(default_factory=list)
    highest_recovered_stage: str = "none"
    recovered_actions: list[str] = field(default_factory=list)
    recovered_entities: list[str] = field(default_factory=list)
    candidate_paths: list[dict[str, Any]] = field(default_factory=list)
    missing_requirements: list[str] = field(default_factory=list)
    evidence_unit_ids: list[str] = field(default_factory=list)
    recommended_component: str = "coverage"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FailureAttributor:
    def attribute(self, row: dict[str, Any], payload: dict[str, Any] | None = None) -> FailureAttribution:
        path = row.get("skill_path", "")
        vector, behavior = infer_attack_labels(path)
        payload = payload or {}
        coverage_states = set(row.get("coverage_states") or payload.get("static_coverage", {}).get("states", []))
        chains = payload.get("static_chains") or ([row["primary_chain"]] if row.get("primary_chain") else [])
        actions = payload.get("extracted_actions", [])
        entities = payload.get("resolved_entities", [])
        limitations = _all_limitations(chains)
        review_reasons = [chain.get("review_reason") for chain in chains if chain.get("review_reason") and chain.get("review_reason") != "not_applicable"]
        action_types = {action.get("action_type") for action in actions}
        entity_types = {entity.get("entity_type") for entity in entities}

        primary = "path_template_missing"
        secondary: list[str] = []
        component = "path_template"
        highest = "none"
        missing: list[str] = []

        if "analysis_error" in coverage_states:
            primary, component, highest = "analysis_error", "coverage", "coverage"
        elif "unsupported_artifact" in coverage_states:
            primary, component, highest = "unsupported_artifact", "coverage", "artifact_loading"
        elif "parse_failure" in coverage_states:
            primary, component, highest = "parse_failure", "coverage", "semantic_parse"
        elif not actions:
            primary, component, highest = "action_not_extracted", "deterministic_extractor", "artifact_loading"
        elif behavior in PI_BEHAVIORS:
            if any(_pi_action_text(action) for action in actions):
                primary, component, highest = "policy_insufficient_context", "path_template", "instruction_policy_action"
            else:
                primary, component, highest = "path_template_missing", "path_template", "actions"
        elif not any(entity_type in entity_types for entity_type in {"Credential", "SensitiveResource", "EnvironmentVariable", "NetworkEndpoint", "APIEndpoint", "PersistenceTarget"}):
            primary, component, highest = "source_not_identified", "entity_resolver", "actions"
        elif row.get("predicted_review"):
            primary = _reason_to_failure(review_reasons[0] if review_reasons else "", limitations)
            component = _component_for_failure(primary)
            highest = "candidate_path"
        elif row.get("predicted_closed_capability"):
            primary, component, highest = "policy_insufficient_context", "policy", "closed_capability"
        else:
            primary, component, highest = _behavior_default_failure(behavior, action_types, entity_types)

        if "conditional_or_optional_gate" in limitations:
            secondary.append("modality_filtered")
        if "missing_shared_sensitive_data_object" in limitations:
            secondary.append("data_object_not_created")
        if "downloaded_artifact_not_resolved_to_executed_artifact" in limitations:
            secondary.append("artifact_identity_missing")
        if "missing_external_sink" in limitations:
            secondary.append("sink_not_identified")
        if any(entity.get("resolution_status") in {"ambiguous", "unresolved"} for entity in entities):
            secondary.append("entity_linking_failed")

        missing.extend(_missing_requirements(primary, behavior))
        evidence_units = sorted({unit for chain in chains for unit in chain.get("evidence_unit_ids", [])})
        candidates = [
            {
                "chain_id": chain.get("chain_id"),
                "status": chain.get("status"),
                "capability_type": chain.get("capability_type"),
                "policy_status": chain.get("policy_status"),
                "alert_status": chain.get("alert_status"),
                "review_reason": chain.get("review_reason"),
                "limitations": chain.get("limitations", []),
            }
            for chain in chains[:5]
            if chain
        ]
        return FailureAttribution(
            skill_id=Path(path).name or path,
            attack_vector=vector,
            behavior_id=behavior,
            primary_failure_reason=primary if primary in FAILURE_REASONS else "unsupported_attack_behavior",
            secondary_failure_reasons=sorted(set(reason for reason in secondary if reason != primary)),
            highest_recovered_stage=highest,
            recovered_actions=sorted(str(item) for item in action_types if item),
            recovered_entities=sorted(str(item) for item in entity_types if item),
            candidate_paths=candidates,
            missing_requirements=missing,
            evidence_unit_ids=evidence_units,
            recommended_component=component,
        )


def infer_attack_labels(path: str) -> tuple[str, str]:
    name = Path(path).name
    vector = "unknown"
    behavior = "unknown"
    match = re.search(r"__(CI|PI|MIXED)_B(\d{1,2})", name, re.I)
    if match:
        vector = match.group(1).upper()
        behavior = f"B{int(match.group(2))}"
    return vector, behavior


def _all_limitations(chains: list[dict[str, Any]]) -> str:
    return " ".join(str(item) for chain in chains if chain for item in chain.get("limitations", []))


def _reason_to_failure(review_reason: str, limitations: str) -> str:
    mapping = {
        "missing_data_continuity": "data_object_not_created",
        "missing_artifact_identity": "artifact_identity_missing",
        "ambiguous_entity": "entity_linking_failed",
        "unknown_endpoint_trust": "trusted_endpoint_misclassified",
        "unsupported_language_construct": "variable_propagation_missing",
        "unsupported_attack_template": "path_template_missing",
        "ambiguous_modality": "modality_filtered",
        "cross_artifact_gap": "cross_artifact_link_missing",
        "partial_source": "source_not_identified",
        "partial_sink": "sink_not_identified",
        "policy_boundary_missing": "policy_insufficient_context",
        "analysis_coverage_gap": "artifact_not_loaded",
        "instruction_semantics_ambiguous": "policy_insufficient_context",
    }
    if review_reason in mapping:
        return mapping[review_reason]
    if "payload" in limitations:
        return "payload_binding_missing"
    if "artifact" in limitations:
        return "artifact_identity_missing"
    if "endpoint" in limitations or "sink" in limitations:
        return "endpoint_resolution_failed"
    return "policy_insufficient_context"


def _component_for_failure(reason: str) -> str:
    if reason in {"variable_propagation_missing", "argument_binding_missing", "payload_binding_missing", "data_object_not_created"}:
        return "python_flow|shell_flow|js_flow"
    if reason in {"entity_linking_failed", "cross_artifact_link_missing", "artifact_identity_missing", "endpoint_resolution_failed"}:
        return "entity_resolver"
    if reason in {"trusted_endpoint_misclassified", "expected_behavior_misclassified", "policy_insufficient_context"}:
        return "policy"
    if reason in {"path_template_missing", "unsupported_attack_behavior", "attack_not_chain_compatible"}:
        return "path_template"
    return "coverage"


def _behavior_default_failure(behavior: str, action_types: set[str], entity_types: set[str]) -> tuple[str, str, str]:
    if behavior in PI_BEHAVIORS:
        return "path_template_missing", "path_template", "actions"
    if behavior in {"B3", "B4", "B6"} and not {"DOWNLOAD", "EXECUTE"} & action_types:
        return "action_not_extracted", "python_flow|shell_flow|js_flow", "entities"
    if behavior in {"B1", "B2"} and "NetworkEndpoint" not in entity_types:
        return "sink_not_identified", "entity_resolver", "source"
    if behavior == "B5" and "PersistenceTarget" not in entity_types:
        return "sink_not_identified", "path_template", "actions"
    if behavior not in CHAIN_COMPATIBLE_BEHAVIORS and behavior != "unknown":
        return "attack_not_chain_compatible", "path_template", "actions"
    return "path_template_missing", "path_template", "actions"


def _missing_requirements(primary: str, behavior: str) -> list[str]:
    base = {
        "data_object_not_created": ["source value binding", "DataObject propagation edge"],
        "payload_binding_missing": ["payload role evidence", "sink consumes same data object"],
        "artifact_identity_missing": ["download destination", "execute target equality"],
        "entity_linking_failed": ["strong or unique medium entity resolution"],
        "cross_artifact_link_missing": ["explicit cross-artifact invocation or config reference"],
        "path_template_missing": [f"template support for {behavior}"],
        "policy_insufficient_context": ["policy boundary evidence"],
    }
    return base.get(primary, [primary.replace("_", " ")])


def _pi_action_text(action: dict[str, Any]) -> bool:
    text = ((action.get("evidence") or {}).get("exact_text") or "").lower()
    return any(token in text for token in {"ignore previous", "system prompt", "developer message", "from now on", "bypass safety", "override"})
