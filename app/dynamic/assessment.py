from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.dynamic.models import PolicyViolation, RuntimeChain
from app.dynamic.review_lean import apply_review_lean


VIOLATION_SCORE = 80
REVIEW_SCORE = 30


@dataclass
class CanonicalAssessment:
    status: str
    source: str = "dynamic_v3"
    reason: str = ""
    policy_violation_count: int = 0
    confirmed_chain_count: int = 0
    candidate_chain_count: int = 0
    coverage_state: str = "unknown"
    supporting_chain_ids: list[str] = field(default_factory=list)
    supporting_violation_ids: list[str] = field(default_factory=list)
    instrumentation_gaps: list[str] = field(default_factory=list)
    consistency_errors: list[str] = field(default_factory=list)
    needs_review: bool = False
    canonical_risk_score: int = 0
    canonical_final_decision: str = "benign"
    review_required: bool = False
    review_lean: str = "none"
    binary_prediction: str = "benign"
    decision_score: float = 0.0
    review_reason: str = ""
    lean_reason: str = ""
    lean_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def assess_dynamic_result(dynamic_result: Any | None) -> CanonicalAssessment:
    """Map canonical Dynamic v3 evidence into the top-level decision contract."""

    if dynamic_result is None:
        return _finalize_assessment(
            CanonicalAssessment(
                status="execution_incomplete",
                reason="dynamic_v3_result_missing",
                needs_review=True,
                canonical_risk_score=REVIEW_SCORE,
                canonical_final_decision="needs_review",
            )
        )

    chains: list[RuntimeChain] = list(getattr(dynamic_result, "chains", []) or [])
    violations: list[PolicyViolation] = list(getattr(dynamic_result, "policy_violations", []) or [])
    coverage = getattr(dynamic_result, "coverage", None)
    coverage_state = str(getattr(coverage, "coverage_state", "unknown") or "unknown")
    coverage_missing = [str(item) for item in getattr(coverage, "missing_observations", []) or [] if item]
    confirmed = [chain for chain in chains if chain.chain_type.endswith("_confirmed")]
    candidates = _effective_candidates(chains, confirmed)
    gaps = _dedupe(coverage_missing + [gap for chain in chains for gap in list(chain.instrumentation_gaps or [])])

    if violations:
        assessment = CanonicalAssessment(
            status="violation_confirmed",
            reason="canonical dynamic v3 policy violation confirmed",
            policy_violation_count=len(violations),
            confirmed_chain_count=len(confirmed),
            candidate_chain_count=len(candidates),
            coverage_state=coverage_state,
            supporting_chain_ids=_dedupe([violation.chain_id or "" for violation in violations] + [chain.chain_id for chain in confirmed]),
            supporting_violation_ids=[violation.violation_id for violation in violations],
            instrumentation_gaps=gaps,
            needs_review=False,
            canonical_risk_score=VIOLATION_SCORE,
            canonical_final_decision="malicious",
        )
        return _finalize_assessment(assessment, chains=chains, coverage=coverage)

    incomplete_states = {
        "timeout",
        "max_steps_exhausted",
        "path_incomplete",
        "partially_complete",
        "execution_failed",
        "path_not_triggered",
        "source_unavailable",
        "environment_missing",
        "missing_required_command",
        "mock_service_unavailable",
        "unsupported_operation",
        "sink_unavailable",
    }
    review_states = {"instrumentation_gap", "insufficient_coverage"}
    has_review_chain = bool(candidates or [chain for chain in chains if chain.chain_type == "instruction_simulated"])
    has_hash_only = bool(chains) and all("hash_derived" in set(chain.evidence_strengths or []) for chain in chains)

    if coverage_state in incomplete_states:
        return _finalize_assessment(
            CanonicalAssessment(
                status="execution_incomplete",
                reason=f"dynamic execution incomplete: {coverage_state}",
                policy_violation_count=0,
                confirmed_chain_count=len(confirmed),
                candidate_chain_count=len(candidates),
                coverage_state=coverage_state,
                supporting_chain_ids=[chain.chain_id for chain in chains],
                instrumentation_gaps=gaps,
                needs_review=True,
                canonical_risk_score=REVIEW_SCORE,
                canonical_final_decision="needs_review",
            ),
            chains=chains,
            coverage=coverage,
        )

    if coverage_state in review_states or gaps or has_review_chain or has_hash_only:
        return _finalize_assessment(
            CanonicalAssessment(
                status="review_required",
                reason=_review_reason(coverage_state, gaps, has_review_chain, has_hash_only),
                policy_violation_count=0,
                confirmed_chain_count=len(confirmed),
                candidate_chain_count=len(candidates),
                coverage_state=coverage_state,
                supporting_chain_ids=[chain.chain_id for chain in chains],
                instrumentation_gaps=gaps,
                needs_review=True,
                canonical_risk_score=REVIEW_SCORE,
                canonical_final_decision="needs_review",
            ),
            chains=chains,
            coverage=coverage,
        )

    return _finalize_assessment(
        CanonicalAssessment(
            status="no_violation_observed",
            reason="canonical dynamic v3 observed no policy violation",
            policy_violation_count=0,
            confirmed_chain_count=len(confirmed),
            candidate_chain_count=0,
            coverage_state=coverage_state,
            supporting_chain_ids=[chain.chain_id for chain in confirmed],
            instrumentation_gaps=gaps,
            needs_review=False,
            canonical_risk_score=0,
            canonical_final_decision="benign",
        ),
        chains=chains,
        coverage=coverage,
    )


def apply_canonical_assessment(report: dict[str, Any], assessment: CanonicalAssessment) -> None:
    """Preserve legacy scores while making canonical v3 the top-level decision."""

    legacy_score = int(report.get("risk_score", 0) or 0)
    legacy_decision = str(report.get("final_decision", "unknown") or "unknown")
    report.setdefault("legacy_risk_score", legacy_score)
    report.setdefault("legacy_final_decision", legacy_decision)
    report["canonical_assessment"] = assessment.to_dict()
    report["canonical_risk_score"] = assessment.canonical_risk_score
    report["canonical_final_decision"] = assessment.canonical_final_decision
    report["needs_review"] = assessment.needs_review
    report["policy_violation_count"] = assessment.policy_violation_count
    report["confirmed_chain_count"] = assessment.confirmed_chain_count
    report["candidate_chain_count"] = assessment.candidate_chain_count
    report["coverage_state"] = assessment.coverage_state
    report["instrumentation_gaps"] = list(assessment.instrumentation_gaps)
    report["risk_score"] = assessment.canonical_risk_score
    report["final_decision"] = assessment.canonical_final_decision
    if assessment.status == "violation_confirmed":
        _append_triggered_factor(report, assessment)
    errors = validate_consistency(report)
    report["canonical_assessment"]["consistency_errors"] = errors
    report["consistency_errors"] = errors
    report["consistency_status"] = "error" if errors else "ok"
    if errors and assessment.status != "violation_confirmed":
        report["needs_review"] = True
        report["canonical_assessment"]["needs_review"] = True
        report["risk_score"] = max(int(report.get("risk_score", 0) or 0), REVIEW_SCORE)
        report["canonical_risk_score"] = report["risk_score"]
        report["review_required"] = True
        report["canonical_assessment"]["review_required"] = True
    _sync_review_lean_fields(report)


def validate_consistency(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    assessment = report.get("canonical_assessment") or {}
    status = str(assessment.get("status", ""))
    decision = str(report.get("final_decision", ""))
    score = int(report.get("risk_score", 0) or 0)
    policy_count = int(report.get("policy_violation_count", 0) or 0)
    coverage_state = str(report.get("coverage_state") or assessment.get("coverage_state") or "")

    if status == "violation_confirmed" and decision == "benign":
        errors.append("violation_confirmed_with_benign_decision")
    if policy_count > 0 and decision == "benign":
        errors.append("policy_violation_with_benign_decision")
    if policy_count > 0 and score < VIOLATION_SCORE:
        errors.append("policy_violation_below_violation_threshold")
    if coverage_state == "instrumentation_gap" and decision == "benign":
        errors.append("instrumentation_gap_with_benign_decision")
    return errors


def canonical_from_dict(payload: dict[str, Any] | None) -> CanonicalAssessment:
    """Compatibility helper for old reports that do not yet contain the field."""

    if not payload:
        return _finalize_assessment(
            CanonicalAssessment(
                status="review_required",
                reason="canonical assessment missing from legacy artifact",
                needs_review=True,
                canonical_risk_score=REVIEW_SCORE,
                canonical_final_decision="needs_review",
            )
        )
    return _finalize_assessment(CanonicalAssessment(**{key: value for key, value in payload.items() if key in CanonicalAssessment.__dataclass_fields__}))


def _finalize_assessment(
    assessment: CanonicalAssessment,
    *,
    chains: list[RuntimeChain] | None = None,
    coverage: Any | None = None,
) -> CanonicalAssessment:
    lean_payload = apply_review_lean(
        assessment.to_dict(),
        runtime_chains=chains or [],
        coverage_certificate=coverage.to_dict() if hasattr(coverage, "to_dict") else coverage,
    )
    for key in ("review_required", "review_lean", "binary_prediction", "decision_score", "review_reason", "lean_reason", "lean_score"):
        setattr(assessment, key, lean_payload.get(key, getattr(assessment, key)))
    assessment.needs_review = bool(lean_payload.get("review_required", assessment.needs_review))
    assessment.canonical_final_decision = str(lean_payload.get("canonical_final_decision", assessment.canonical_final_decision))
    return assessment


def _sync_review_lean_fields(report: dict[str, Any]) -> None:
    assessment = dict(report.get("canonical_assessment") or {})
    assessment["canonical_final_decision"] = report.get("canonical_final_decision", report.get("final_decision", assessment.get("canonical_final_decision", "unknown")))
    assessment["canonical_risk_score"] = int(report.get("canonical_risk_score", report.get("risk_score", assessment.get("canonical_risk_score", 0))) or 0)
    assessment["needs_review"] = bool(report.get("needs_review", assessment.get("needs_review", False)))
    assessment = apply_review_lean(
        assessment,
        runtime_chains=report.get("runtime_chains", []),
        runtime_events=report.get("runtime_events_v2", report.get("normalized_events", [])),
        coverage_certificate=report.get("coverage_certificate", report.get("runtime_coverage", {})),
        dynamic_payload=report,
    )
    report["canonical_assessment"] = assessment
    for key in ("review_required", "review_lean", "binary_prediction", "decision_score", "review_reason", "lean_reason", "lean_score", "classification_threshold", "review_lower_bound", "review_upper_bound", "operating_thresholds"):
        report[key] = assessment.get(key)
    report["needs_review"] = bool(assessment.get("review_required", False))
    report["final_decision"] = assessment.get("final_decision", report.get("final_decision"))
    report["canonical_final_decision"] = assessment.get("canonical_final_decision", report.get("canonical_final_decision"))


def _append_triggered_factor(report: dict[str, Any], assessment: CanonicalAssessment) -> None:
    factors = list(report.get("triggered_factors", []) or [])
    factors.append(
        {
            "code": "dynamic_v3_policy_violation",
            "score_delta": VIOLATION_SCORE,
            "rationale": assessment.reason,
            "evidence": {
                "policy_violation_count": assessment.policy_violation_count,
                "supporting_chain_ids": list(assessment.supporting_chain_ids),
                "supporting_violation_ids": list(assessment.supporting_violation_ids),
            },
        }
    )
    report["triggered_factors"] = factors


def _review_reason(coverage_state: str, gaps: list[str], has_review_chain: bool, has_hash_only: bool) -> str:
    if has_review_chain:
        return "candidate runtime chain requires review"
    if gaps:
        return "runtime instrumentation gap requires review"
    if has_hash_only:
        return "hash-derived flow is not original secret exfiltration"
    return f"coverage requires review: {coverage_state}"


def _effective_candidates(chains: list[RuntimeChain], confirmed: list[RuntimeChain]) -> list[RuntimeChain]:
    confirmed_sinks = {chain.sink for chain in confirmed if chain.sink}
    return [
        chain
        for chain in chains
        if chain.chain_type == "confidentiality_candidate" and (not chain.sink or chain.sink not in confirmed_sinks)
    ]


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result
