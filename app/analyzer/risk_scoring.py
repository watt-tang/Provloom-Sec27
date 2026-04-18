from __future__ import annotations

from app.analyzer.risk_model import (
    DecisionInputs,
    FinalDecision,
    RiskFactor,
    SensitivityTier,
    SinkSemantics,
)


def score_risk_factors(inputs: DecisionInputs) -> tuple[int, list[RiskFactor], FinalDecision]:
    """Convert structured evidence into auditable risk factors and a final decision."""

    factors: list[RiskFactor] = []
    if inputs.source.sensitivity == SensitivityTier.HIGH and inputs.sink.is_external:
        factors.append(
            RiskFactor(
                code="high_sensitivity_source_to_external_sink",
                score_delta=80,
                rationale="High-sensitivity source is connected to an external network sink.",
                evidence={"source": inputs.source.to_dict(), "sink": inputs.sink.to_dict()},
            )
        )
    if (
        inputs.source.sensitivity == SensitivityTier.MEDIUM
        and inputs.sink.semantics in {
            SinkSemantics.PUBLIC_UPLOAD_OR_POST,
            SinkSemantics.CALLBACK_OR_WEBHOOK,
            SinkSemantics.UNKNOWN_NETWORK_SINK,
        }
        and not inputs.source.from_public_lineage
    ):
        factors.append(
            RiskFactor(
                code="generated_artifact_external_transfer",
                score_delta=55,
                rationale="Locally generated artifact is transferred outward without public-only lineage.",
                evidence={"source": inputs.source.to_dict(), "sink": inputs.sink.to_dict()},
            )
        )
    if inputs.overprivileged_outward_action:
        factors.append(
            RiskFactor(
                code="overprivileged_outward_tool_action",
                score_delta=45,
                rationale="Outward-facing http_request tool transfers locally produced data.",
                evidence={"tool_evidence": inputs.tool_evidence, "source": inputs.source.to_dict()},
            )
        )
    if inputs.risky_command:
        factors.append(
            RiskFactor(
                code="unsafe_command_construction",
                score_delta=70,
                rationale="Command evidence indicates templated or shell-abusive command construction.",
                evidence={"reasons": inputs.risky_command_reasons, "commands": inputs.command_evidence},
            )
        )
    if inputs.llm_involved and (inputs.outward_network or inputs.risky_command):
        factors.append(
            RiskFactor(
                code="llm_induced_risky_action",
                score_delta=25,
                rationale="LLM steps appear on the path to an outward action or risky command.",
                evidence={"llm_evidence": inputs.llm_evidence},
            )
        )
    if (
        inputs.source.sensitivity == SensitivityTier.UNKNOWN
        and inputs.outward_network
        and inputs.sink.semantics in {SinkSemantics.CALLBACK_OR_WEBHOOK, SinkSemantics.UNKNOWN_NETWORK_SINK}
    ):
        factors.append(
            RiskFactor(
                code="unknown_source_external_sink",
                score_delta=25,
                rationale="Outbound transfer reached an external sink while the source remained unresolved.",
                evidence={"sink": inputs.sink.to_dict()},
            )
        )
    raw_score = sum(item.score_delta for item in factors)
    if raw_score >= 60:
        decision = FinalDecision.MALICIOUS
    elif raw_score >= 30:
        decision = FinalDecision.NEEDS_REVIEW
    else:
        decision = FinalDecision.BENIGN
    return raw_score, factors, decision
