from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PolicyDecision:
    policy_status: str
    alert_status: str
    review_priority: str
    review_reason: str = "not_applicable"
    policy_reasons: list[str] = field(default_factory=list)
    policy_evidence_unit_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PolicyClassifier:
    def classify(
        self,
        *,
        path_status: str,
        capability_type: str,
        trust_assessment: dict[str, Any],
        limitations: list[str],
        has_unresolved: bool,
        has_conditions: bool,
    ) -> PolicyDecision:
        trusted = bool(trust_assessment.get("trusted")) and trust_assessment.get("resolution_strength", "strong") == "strong"
        reasons: list[str] = []
        policy_status = "not_applicable"
        alert_status = "none"
        priority = "informational"
        review_reason = "not_applicable"

        if path_status in {"partial", "uncertain"}:
            policy_status = "insufficient_context"
            alert_status = "review"
            priority = "medium" if capability_type in _HIGH_IMPACT_CAPABILITIES else "low"
            review_reason = _review_reason(limitations, capability_type)
            reasons.append("The path is not fully closed by deterministic evidence.")
        elif path_status == "isolated":
            policy_status = "insufficient_context"
            alert_status = "review" if capability_type in _HIGH_IMPACT_CAPABILITIES else "capability_only"
            priority = "low"
            review_reason = "unsupported_attack_template" if alert_status == "review" else "not_applicable"
            reasons.append("Only isolated capability evidence is present.")
        elif path_status == "closed":
            if capability_type == "credential_authentication":
                policy_status = "trusted_service_flow" if trusted else "insufficient_context"
                alert_status = "capability_only" if trusted else "review"
                priority = "low" if trusted else "medium"
                reasons.append("Credential appears to be used for authentication rather than business payload transfer.")
            elif capability_type == "credential_exposure":
                policy_status = "insufficient_context"
                alert_status = "review"
                priority = "medium"
                review_reason = "unknown_endpoint_trust"
                reasons.append("Credential is exposed locally, but no untrusted external sink is proven.")
            elif capability_type == "credential_exfiltration":
                policy_status = "trusted_service_flow" if trusted else "untrusted_external_flow"
                alert_status = "capability_only" if trusted else "violation"
                priority = "low" if trusted else "critical"
                reasons.append("Credential-like data is carried as request payload or upload content.")
            elif capability_type == "declared_dependency_install":
                policy_status = "expected_declared_behavior"
                alert_status = "capability_only"
                priority = "low"
                reasons.append("Package installation matches a standard package-manager dependency flow.")
            elif capability_type == "remote_artifact_execution":
                policy_status = "declared_high_impact_behavior" if trusted else "insufficient_context"
                alert_status = "review"
                priority = "medium"
                review_reason = "policy_boundary_missing"
                reasons.append("A remote artifact is executed, but policy context is insufficient for violation.")
            elif capability_type == "untrusted_download_execute":
                policy_status = "untrusted_external_flow"
                alert_status = "violation"
                priority = "critical"
                reasons.append("A concrete untrusted downloaded artifact is automatically executed.")
            elif capability_type == "privilege_escalation":
                policy_status = "undeclared_behavior"
                alert_status = "violation"
                priority = "critical"
                reasons.append("The action crosses a high-risk permission boundary.")
            elif capability_type in {"permission_request", "declared_capability", "permission_expansion"}:
                policy_status = "insufficient_context" if capability_type == "permission_expansion" else "expected_declared_behavior"
                alert_status = "review" if capability_type == "permission_expansion" else "capability_only"
                priority = "medium" if capability_type == "permission_expansion" else "low"
                review_reason = "policy_boundary_missing" if capability_type == "permission_expansion" else "not_applicable"
                reasons.append("Permission-related behavior is declared, but expansion beyond task needs is not fully proven.")
            elif capability_type in {"persistence_write", "destructive_modification"}:
                policy_status = "undeclared_behavior"
                alert_status = "violation"
                priority = "critical"
                reasons.append(f"Closed {capability_type} path targets a high-impact sink.")
            elif capability_type in {"reverse_shell", "ransomware", "resource_abuse", "malware_delivery", "agent_lifecycle_persistence"}:
                policy_status = "undeclared_behavior" if capability_type != "malware_delivery" else "untrusted_external_flow"
                alert_status = "violation"
                priority = "critical"
                reasons.append(f"Closed {capability_type} path has explicit execution evidence.")
            elif capability_type in {"role_hijack", "safety_bypass", "instruction_override", "system_prompt_leak", "goal_hijacking", "content_manipulation"}:
                policy_status = "documentation_behavior_mismatch"
                alert_status = "violation"
                priority = "high"
                reasons.append(f"Explicit instruction-policy behavior detected: {capability_type}.")

        if has_conditions and alert_status == "violation":
            alert_status = "review"
            priority = "medium"
            policy_status = "insufficient_context"
            review_reason = "ambiguous_modality"
            reasons.append("A conditional or user-confirmation gate prevents direct violation classification.")
        if has_unresolved and path_status == "closed":
            alert_status = "review" if alert_status == "violation" else alert_status
            priority = "medium" if priority in {"critical", "high"} else priority
            policy_status = "insufficient_context" if policy_status in {"untrusted_external_flow", "undeclared_behavior"} else policy_status
            review_reason = "ambiguous_entity"
            reasons.append("Unresolved or ambiguous critical entities prevent violation escalation.")
        if limitations:
            reasons.extend(f"Limitation: {item}" for item in limitations[:4])

        evidence = list(trust_assessment.get("evidence_unit_ids", []))
        return PolicyDecision(policy_status, alert_status, priority, review_reason, reasons or ["No policy-significant static path was formed."], evidence)


_HIGH_IMPACT_CAPABILITIES = {
    "credential_exposure",
    "credential_exfiltration",
    "untrusted_download_execute",
    "remote_artifact_execution",
    "permission_expansion",
    "privilege_escalation",
    "reverse_shell",
    "ransomware",
    "resource_abuse",
    "malware_delivery",
    "agent_lifecycle_persistence",
    "role_hijack",
    "safety_bypass",
    "instruction_override",
    "system_prompt_leak",
    "goal_hijacking",
    "content_manipulation",
    "persistence_write",
    "destructive_modification",
}


def _review_reason(limitations: list[str], capability_type: str) -> str:
    text = " ".join(limitations)
    if "data" in text or "shared_sensitive" in text or "payload" in text:
        return "missing_data_continuity"
    if "artifact" in text or "download" in text:
        return "missing_artifact_identity"
    if "external_sink" in text or "endpoint" in text:
        return "partial_sink"
    if "cross" in text:
        return "cross_artifact_gap"
    if "conditional" in text or "optional" in text:
        return "ambiguous_modality"
    if capability_type in {"credential_exfiltration", "credential_exposure"}:
        return "missing_data_continuity"
    if capability_type in {"remote_artifact_execution", "untrusted_download_execute"}:
        return "missing_artifact_identity"
    if capability_type in {"permission_expansion", "privilege_escalation"}:
        return "policy_boundary_missing"
    return "instruction_semantics_ambiguous"
