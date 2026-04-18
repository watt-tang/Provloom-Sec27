from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class _StrEnum(str, Enum):
    pass


class SensitivityTier(_StrEnum):
    """Ordered source-sensitivity tiers used by the decision engine."""

    HIGH = "HIGH_SENSITIVITY"
    MEDIUM = "MEDIUM_SENSITIVITY"
    LOW = "LOW_SENSITIVITY"
    UNKNOWN = "UNKNOWN"


class SinkSemantics(_StrEnum):
    """Analyst-facing network sink semantics."""

    PUBLIC_UPLOAD_OR_POST = "PUBLIC_UPLOAD_OR_POST"
    PUBLIC_FETCH_ONLY = "PUBLIC_FETCH_ONLY"
    CALLBACK_OR_WEBHOOK = "CALLBACK_OR_WEBHOOK"
    TOOL_INTERNAL_ENDPOINT = "TOOL_INTERNAL_ENDPOINT"
    UNKNOWN_NETWORK_SINK = "UNKNOWN_NETWORK_SINK"


class FinalDecision(_StrEnum):
    """High-level decision states exposed to benchmark and artifacts."""

    MALICIOUS = "malicious"
    NEEDS_REVIEW = "needs_review"
    BENIGN = "benign"


@dataclass
class SourceAssessment:
    """Classification result for the best available source candidate."""

    label: str = ""
    node_type: str = "unknown"
    sensitivity: SensitivityTier = SensitivityTier.UNKNOWN
    evidence_paths: list[str] = field(default_factory=list)
    inferred_from: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    from_public_lineage: bool = False
    is_generated_artifact: bool = False
    is_sensitive_path: bool = False
    is_public_input: bool = False
    unknown: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "node_type": self.node_type,
            "sensitivity": self.sensitivity.value,
            "evidence_paths": self.evidence_paths,
            "inferred_from": self.inferred_from,
            "reasons": self.reasons,
            "from_public_lineage": self.from_public_lineage,
            "is_generated_artifact": self.is_generated_artifact,
            "is_sensitive_path": self.is_sensitive_path,
            "is_public_input": self.is_public_input,
            "unknown": self.unknown,
        }


@dataclass
class SinkAssessment:
    """Classification result for the best available network sink candidate."""

    label: str = ""
    semantics: SinkSemantics = SinkSemantics.UNKNOWN_NETWORK_SINK
    method: str = ""
    reasons: list[str] = field(default_factory=list)
    declared_endpoint: bool = False
    tool_linked_http_action: bool = False
    is_external: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "semantics": self.semantics.value,
            "method": self.method,
            "reasons": self.reasons,
            "declared_endpoint": self.declared_endpoint,
            "tool_linked_http_action": self.tool_linked_http_action,
            "is_external": self.is_external,
        }


@dataclass
class RiskFactor:
    """An auditable factor that raises the risk score."""

    code: str
    score_delta: int
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "score_delta": self.score_delta,
            "rationale": self.rationale,
            "evidence": self.evidence,
        }


@dataclass
class SuppressionFactor:
    """An auditable factor that suppresses or downgrades the risk score."""

    code: str
    score_delta: int
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "score_delta": self.score_delta,
            "rationale": self.rationale,
            "evidence": self.evidence,
        }


@dataclass
class DecisionInputs:
    """Stage-B inputs collected from telemetry, EPG, and execution context."""

    detected_behaviors: list[str]
    normalized_events: list[dict[str, Any]]
    primary_chain: list[dict[str, Any]]
    graph_summary: dict[str, Any]
    source: SourceAssessment
    sink: SinkAssessment
    risky_command: bool
    risky_command_reasons: list[str]
    overprivileged_outward_action: bool
    llm_involved: bool
    outward_network: bool
    tool_evidence: list[dict[str, Any]]
    command_evidence: list[dict[str, Any]]
    llm_evidence: list[dict[str, Any]]


@dataclass
class DecisionResult:
    """Final risk scoring output used by runtime analysis and benchmarking."""

    risk_score: int
    final_decision: FinalDecision
    triggered_factors: list[RiskFactor] = field(default_factory=list)
    suppression_factors: list[SuppressionFactor] = field(default_factory=list)
    evidence_bundle: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "final_decision": self.final_decision.value,
            "triggered_factors": [factor.to_dict() for factor in self.triggered_factors],
            "suppression_factors": [factor.to_dict() for factor in self.suppression_factors],
            "evidence_bundle": self.evidence_bundle,
        }
