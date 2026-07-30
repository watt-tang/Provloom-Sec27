from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SCHEMA_VERSION = "provloom-unified-v1"
ALIGNMENT_VERSION = "static-runtime-reconciliation-v1"
ASSESSMENT_VERSION = "canonical-assessment-v1"
STATIC_VERSION = "provloom-static-v2"
DYNAMIC_VERSION = "runtime-analysis-v3"


@dataclass
class UnifiedAlignment:
    alignment_id: str
    status: str
    alignment_type: str
    static_ids: list[str] = field(default_factory=list)
    runtime_ids: list[str] = field(default_factory=list)
    score: float = 0.0
    reason: str = ""
    matched_keys: list[str] = field(default_factory=list)
    conflicting_keys: list[str] = field(default_factory=list)
    supporting_evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UnifiedContradiction:
    contradiction_type: str
    severity: str
    static_claim: dict[str, Any]
    runtime_observation: dict[str, Any]
    alignment_id: str = ""
    reason: str = ""
    confidence: float = 0.0
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeObligation:
    obligation_id: str
    origin: str
    static_ids: list[str]
    expected_runtime_operation: str
    static_path_id: str = ""
    origin_static_ids: list[str] = field(default_factory=list)
    expected_entity_keys: list[str] = field(default_factory=list)
    status: str = "unsatisfied"
    supporting_runtime_ids: list[str] = field(default_factory=list)
    reason: str = ""
    obligation_type: str = ""
    path_role: str = "auxiliary"
    relevance: str = "auxiliary"
    risk_relevance: str = "low"
    required_for_path_completion: bool = True
    required_for_risk_closure: bool = False
    required_for_execution_completion: bool = False
    conditional: bool = False
    condition_status: str = "not_applicable"
    blocking_condition: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PathCompletionResult:
    static_path_id: str
    status: str
    satisfied_obligations: list[str] = field(default_factory=list)
    unsatisfied_obligations: list[str] = field(default_factory=list)
    unresolved_obligations: list[str] = field(default_factory=list)
    observed_runtime_chains: list[str] = field(default_factory=list)
    completion_ratio: float = 0.0
    termination_effect: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskChainStatus:
    status: str = "none"
    confirmed_violation_chain_ids: list[str] = field(default_factory=list)
    confirmed_allowed_chain_ids: list[str] = field(default_factory=list)
    candidate_chain_ids: list[str] = field(default_factory=list)
    decisive_chain_ids: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionCompletion:
    status: str = "unknown"
    termination_reason: str = ""
    agent_step_count: int = 0
    max_agent_steps: int = 0
    total_timeout_seconds: int | None = None
    llm_request_timeout_seconds: int | None = 120
    provider_retry_count: int = 0
    final_response_emitted: bool = False
    pending_tool_call: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StaticPathCompletion:
    static_path_id: str
    risk_relevance: str = "medium"
    status: str = "unresolved"
    matched_runtime_chain_ids: list[str] = field(default_factory=list)
    decisive_obligations: list[str] = field(default_factory=list)
    supporting_obligations: list[str] = field(default_factory=list)
    auxiliary_obligations: list[str] = field(default_factory=list)
    satisfied_obligation_ids: list[str] = field(default_factory=list)
    unresolved_obligation_ids: list[str] = field(default_factory=list)
    completion_ratio: float = 0.0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CoverageCertificate:
    schema_version: str = "coverage-certificate-v1"
    coverage_state: str = "insufficient_coverage"
    obligations: list[RuntimeObligation] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    instrumentation_gaps: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    execution_status: str = "unknown"
    chain_evidence_status: str = "none"
    path_completion_status: str = "unresolved"
    termination_reason: str = ""
    obligation_summary: dict[str, Any] = field(default_factory=dict)
    environment_gaps: list[str] = field(default_factory=list)
    sensitive_artifacts: list[dict[str, Any]] = field(default_factory=list)
    path_completion: list[PathCompletionResult] = field(default_factory=list)
    risk_chain_status: RiskChainStatus = field(default_factory=RiskChainStatus)
    execution_completion: ExecutionCompletion = field(default_factory=ExecutionCompletion)
    static_path_results: list[StaticPathCompletion] = field(default_factory=list)
    primary_static_path_id: str = ""
    primary_static_path_status: str = "not_applicable"
    primary_risk_path_selection: dict[str, Any] = field(default_factory=dict)
    other_static_path_summary: dict[str, Any] = field(default_factory=dict)
    obligation_relevance_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["obligations"] = [item.to_dict() if hasattr(item, "to_dict") else item for item in self.obligations]
        payload["path_completion"] = [item.to_dict() if hasattr(item, "to_dict") else item for item in self.path_completion]
        payload["risk_chain_status"] = self.risk_chain_status.to_dict() if hasattr(self.risk_chain_status, "to_dict") else self.risk_chain_status
        payload["execution_completion"] = self.execution_completion.to_dict() if hasattr(self.execution_completion, "to_dict") else self.execution_completion
        payload["static_path_results"] = [item.to_dict() if hasattr(item, "to_dict") else item for item in self.static_path_results]
        return payload


@dataclass
class PolicyFinding:
    finding_id: str
    origin: str
    policy_domain: str
    status: str
    evidence_status: str
    supporting_ids: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UnifiedExplanationResult:
    skill_id: str
    static_result: dict[str, Any]
    dynamic_result: dict[str, Any]
    alignments: list[UnifiedAlignment] = field(default_factory=list)
    contradictions: list[UnifiedContradiction] = field(default_factory=list)
    aligned_paths: list[dict[str, Any]] = field(default_factory=list)
    instruction_only_paths: list[dict[str, Any]] = field(default_factory=list)
    runtime_only_paths: list[dict[str, Any]] = field(default_factory=list)
    relevant_unresolved: list[dict[str, Any]] = field(default_factory=list)
    internal_unresolved: list[dict[str, Any]] = field(default_factory=list)
    coverage_certificate: CoverageCertificate = field(default_factory=CoverageCertificate)
    policy_violations: list[dict[str, Any]] = field(default_factory=list)
    canonical_assessment: dict[str, Any] = field(default_factory=dict)
    minimal_witnesses: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    legacy_compatibility: dict[str, Any] = field(default_factory=dict)
    policy_findings: list[PolicyFinding] = field(default_factory=list)
    risk_chain_status: dict[str, Any] = field(default_factory=dict)
    execution_completion: dict[str, Any] = field(default_factory=dict)
    static_path_results: list[dict[str, Any]] = field(default_factory=list)
    primary_static_path_id: str = ""
    primary_static_path_status: str = "not_applicable"
    other_static_path_summary: dict[str, Any] = field(default_factory=dict)
    obligation_relevance_summary: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    versions: dict[str, str] = field(
        default_factory=lambda: {
            "static_analysis_version": STATIC_VERSION,
            "dynamic_analysis_version": DYNAMIC_VERSION,
            "alignment_version": ALIGNMENT_VERSION,
            "assessment_version": ASSESSMENT_VERSION,
        }
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "skill_id": self.skill_id,
            "versions": dict(self.versions),
            "static_result": self.static_result,
            "dynamic_result": self.dynamic_result,
            "alignments": [item.to_dict() for item in self.alignments],
            "contradictions": [item.to_dict() for item in self.contradictions],
            "aligned_paths": list(self.aligned_paths),
            "instruction_only_paths": list(self.instruction_only_paths),
            "runtime_only_paths": list(self.runtime_only_paths),
            "relevant_unresolved": list(self.relevant_unresolved),
            "internal_unresolved": list(self.internal_unresolved),
            "coverage_certificate": self.coverage_certificate.to_dict(),
            "risk_chain_status": dict(self.risk_chain_status),
            "execution_completion": dict(self.execution_completion),
            "static_path_results": list(self.static_path_results),
            "primary_static_path_id": self.primary_static_path_id,
            "primary_static_path_status": self.primary_static_path_status,
            "other_static_path_summary": dict(self.other_static_path_summary),
            "obligation_relevance_summary": dict(self.obligation_relevance_summary),
            "policy_violations": list(self.policy_violations),
            "policy_findings": [item.to_dict() for item in self.policy_findings],
            "canonical_assessment": dict(self.canonical_assessment),
            "minimal_witnesses": list(self.minimal_witnesses),
            "limitations": list(self.limitations),
            "legacy_compatibility": dict(self.legacy_compatibility),
        }
